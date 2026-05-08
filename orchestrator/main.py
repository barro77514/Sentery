from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel
from typing import List, Optional
import uuid
import datetime
import os
import json
import requests
from bs4 import BeautifulSoup
import re
import sqlite3
import sqlite_vss
from fastapi.middleware.cors import CORSMiddleware

from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import JsonOutputParser

from sentence_transformers import SentenceTransformer
import numpy as np
from va_scanner import scan_security_headers

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load Embedding Model
embed_model = SentenceTransformer('all-MiniLM-L6-v2')

# Configure Gemini with LangChain
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
if GEMINI_API_KEY:
    llm = ChatGoogleGenerativeAI(model="gemini-pro", google_api_key=GEMINI_API_KEY)
else:
    llm = None

class TrafficEntry(BaseModel):
    id: str
    method: str
    url: str
    headers: Optional[dict] = None
    request_body: str
    response_status: int
    response_body_size: int
    timestamp: datetime.datetime

class AttackSuggestion(BaseModel):
    id: str
    traffic_id: str
    flaw_type: str
    description: str
    suggested_payload: str
    status: str  # pending, approved, rejected

class VAAlertModel(BaseModel):
    id: str
    traffic_id: str
    title: str
    severity: str
    description: str
    recommendation: str

traffic_log: List[TrafficEntry] = []
attack_suggestions: List[AttackSuggestion] = []
va_alerts: List[VAAlertModel] = []

parser = JsonOutputParser(pydantic_object=AttackSuggestion)

def extract_price_from_url(url: str) -> Optional[float]:
    try:
        if url.startswith("file://"):
            with open(url.replace("file://", ""), 'r') as f:
                content = f.read()
            soup = BeautifulSoup(content, 'html.parser')
        else:
            response = requests.get(url, timeout=5)
            if response.status_code != 200:
                return None
            soup = BeautifulSoup(response.text, 'html.parser')

        # More robust price extraction: check all text nodes (handles $ and €)
        for text in soup.stripped_strings:
            match = re.search(r'[\$€]\s?(\d+[\.,]?\d*)', text)
            if match:
                price_str = match.group(1).replace(',', '.')
                try:
                    return float(price_str)
                except ValueError:
                    continue
    except Exception as e:
        print(f"Error crawling {url}: {e}")
    return None

def get_db_connection():
    # Use environment variable for DB path or fallback to orchestrated path
    db_path = os.getenv("DATABASE_PATH", "/app/traffic.db")
    if not os.path.exists(db_path):
        # Local development fallback
        db_path = "../core/traffic.db"

    conn = sqlite3.connect(db_path)
    try:
        conn.enable_load_extension(True)
        sqlite_vss.load(conn)
    except Exception as e:
        print(f"Warning: Could not load sqlite-vss: {e}")

    conn.row_factory = sqlite3.Row
    return conn

def init_vss():
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Create a virtual table for VSS
        cursor.execute("CREATE VIRTUAL TABLE IF NOT EXISTS vss_kb USING vss0(embedding(384))")
        # Mapping table to link VSS rowid to KB entry
        cursor.execute("CREATE TABLE IF NOT EXISTS kb_vss_map (rowid INTEGER PRIMARY KEY, kb_id INTEGER)")
        conn.commit()
    except Exception as e:
        print(f"Warning: Could not initialize VSS tables: {e}")
    finally:
        conn.close()

init_vss()

def semantic_lookup(query: str, top_k: int = 3):
    """
    Search for similar successful attacks in the knowledge base using VSS.
    """
    try:
        query_embedding = embed_model.encode([query])[0].tolist()
        conn = get_db_connection()
        cursor = conn.cursor()

        # VSS Query
        cursor.execute("""
            SELECT rowid, distance
            FROM vss_kb
            WHERE vss_search(embedding, ?)
            LIMIT ?
        """, (json.dumps(query_embedding), top_k))

        vss_results = cursor.fetchall()

        kb_entries = []
        for res in vss_results:
            cursor.execute("SELECT vulnerability_type, payload, fingerprint FROM knowledge_base WHERE id = ?", (res['rowid'],))
            entry = cursor.fetchone()
            if entry:
                kb_entries.append(dict(entry))

        conn.close()
        return kb_entries
    except Exception as e:
        print(f"VSS lookup error: {e}")
        return []

prompt_template = ChatPromptTemplate.from_template(
    """
    You are an expert in Business Logic Flaws for E-commerce and Ticketing systems.
    Analyze the following HTTP request.

    Method: {method}
    URL: {url}
    Request Body: {body}

    Relevant Knowledge Base (Past Successes):
    {knowledge_base}

    Determine if this request is related to a shopping cart (cart), checkout process, or ticketing system (e.g., Trenord, Airline, etc.).
    If it is, identify sensitive parameters such as 'price', 'quantity', 'user_id', 'amount', etc.

    Context: {context}

    If you find a potential business logic flaw (like price manipulation, quantity tampering, IDOR), propose a specific attack.
    Example attack: "Negative Price Injection" if 'price' is found.
    Special Case: If a discrepancy is found between a displayed price ({displayed_price}) and a submitted price, suggest "Parameter Pollution" (e.g., price=0.01&price={displayed_price}).

    Your response must be a JSON object with the following fields:
    - flaw_type: A short name for the flaw (e.g., "Price Manipulation")
    - description: A clear explanation of what to test.
    - suggested_payload: A specific payload or modification to try.

    If the request is not sensitive or no flaw is found, return the string "NONE".

    {format_instructions}
    """
)

async def analyze_traffic(entry: TrafficEntry):
    kb_relevant = semantic_lookup(entry.url + entry.request_body)

    # E-commerce specific logic: check for price discrepancies via crawling
    displayed_price = None
    context = ""

    if "checkout" in entry.url or "purchase" in entry.url or "cart" in entry.url or "ecommerce.com" in entry.url:
        referer = None
        if entry.headers:
            # Handle headers as potentially a dict of lists (Go style) or a plain dict
            referer_raw = entry.headers.get("Referer") or entry.headers.get("referer")
            if isinstance(referer_raw, list) and len(referer_raw) > 0:
                referer = referer_raw[0]
            elif isinstance(referer_raw, str):
                referer = referer_raw
            if isinstance(referer, list) and len(referer) > 0:
                referer = referer[0]

        if referer:
            print(f"Crawling referer for price: {referer}")
            displayed_price = extract_price_from_url(referer)
            print(f"Extracted price: {displayed_price}")
            if displayed_price:
                context = f"Price discrepancy analysis active. Page shows ${displayed_price}."
            else:
                context = "Sensitive context detected (E-commerce). Referer crawled but no price found."
        else:
            context = "Sensitive context detected (E-commerce). No Referer available for crawling."

    if not llm:
        # Fallback to mock reasoning if no LLM
        if any(keyword in entry.url.lower() for keyword in ["cart", "checkout", "ticket", "trenord"]):
            flaw_type = "Price Manipulation"
            description = "[MOCK] Detected sensitive context. Attempting to modify numeric parameters."
            payload = "Change 'price' or 'amount' to -1 or 0.01"

            if displayed_price:
                # User specifically asked for Parameter Pollution on price discrepancy
                flaw_type = "Parameter Pollution (Price)"
                description = f"[MOCK] Discrepancy detected! Page shows ${displayed_price}, but request sends a different value. Testing for Parameter Pollution."
                payload = f"price=0.01&price={displayed_price}"

            suggestion = AttackSuggestion(
                id=str(uuid.uuid4()),
                traffic_id=entry.id,
                flaw_type=flaw_type,
                description=description,
                suggested_payload=payload,
                status="pending"
            )
            attack_suggestions.append(suggestion)
        return

    chain = prompt_template | llm | parser

    try:
        response = chain.invoke({
            "method": entry.method,
            "url": entry.url,
            "body": entry.request_body,
            "context": context,
            "displayed_price": displayed_price,
            "knowledge_base": json.dumps(kb_relevant),
            "format_instructions": parser.get_format_instructions()
        })

        if response and isinstance(response, dict):
            suggestion = AttackSuggestion(
                id=str(uuid.uuid4()),
                traffic_id=entry.id,
                flaw_type=response.get("flaw_type", "Unknown"),
                description=response.get("description", ""),
                suggested_payload=response.get("suggested_payload", ""),
                status="pending"
            )
            attack_suggestions.append(suggestion)
    except Exception as e:
        print(f"Error during AI analysis: {e}")
        pass

@app.post("/traffic")
async def ingest_traffic(request: Request):
    data = await request.json()
    entry = TrafficEntry(
        id=str(uuid.uuid4()),
        method=data.get("method"),
        url=data.get("url"),
        headers=data.get("headers"),
        request_body=data.get("request_body"),
        response_status=data.get("response_status"),
        response_body_size=data.get("response_body_size"),
        timestamp=datetime.datetime.now()
    )
    traffic_log.append(entry)

    # Security Header Scan (VA)
    if entry.headers:
        alerts = scan_security_headers(entry.headers)
        for a in alerts:
            va_alerts.append(VAAlertModel(
                id=a.id,
                traffic_id=entry.id,
                title=a.title,
                severity=a.severity,
                description=a.description,
                recommendation=a.recommendation
            ))

    await analyze_traffic(entry)

    return {"status": "ok", "entry_id": entry.id}

@app.get("/traffic")
async def get_traffic():
    return traffic_log

@app.get("/attacks")
async def get_attacks():
    return attack_suggestions

@app.get("/va/alerts")
async def get_va_alerts():
    return va_alerts

@app.post("/attacks/{attack_id}/approve")
async def approve_attack(attack_id: str):
    for attack in attack_suggestions:
        if attack.id == attack_id:
            attack.status = "approved"

            # Save successful pattern to Knowledge Base with VSS
            try:
                # 1. Get embedding for the attack context (description + payload)
                text_to_embed = f"{attack.description} {attack.suggested_payload}"
                embedding = embed_model.encode([text_to_embed])[0].tolist()

                conn = get_db_connection()
                cursor = conn.cursor()

                # 2. Insert into main KB
                cursor.execute("INSERT INTO knowledge_base (vulnerability_type, payload, fingerprint) VALUES (?, ?, ?)",
                               (attack.flaw_type, attack.suggested_payload, "mock_fp"))
                kb_id = cursor.lastrowid

                # 3. Insert into VSS table
                cursor.execute("INSERT INTO vss_kb(rowid, embedding) VALUES (?, ?)", (kb_id, json.dumps(embedding)))

                # 4. Map it (redundant if using rowid but safer)
                cursor.execute("INSERT INTO kb_vss_map(rowid, kb_id) VALUES (?, ?)", (kb_id, kb_id))

                conn.commit()
                conn.close()
            except Exception as e:
                print(f"Error saving to VSS KB: {e}")

            return {"status": "approved"}

    raise HTTPException(status_code=404, detail="Attack suggestion not found")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
