from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel
from typing import List, Optional, Dict
import uuid
import datetime
import os
import json
import requests
from bs4 import BeautifulSoup
import re
import sqlite3
import sqlite_vss
import asyncio
from playwright.async_api import async_playwright
from fastapi.middleware.cors import CORSMiddleware

from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import JsonOutputParser

from sentence_transformers import SentenceTransformer
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

class MutationInstructions(BaseModel):
    method: str
    url: str
    headers: Optional[Dict[str, List[str]]] = None
    body: str

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
    mutation_instructions: Optional[MutationInstructions] = None

class VAAlertModel(BaseModel):
    id: str
    traffic_id: str
    title: str
    severity: str
    description: str
    recommendation: str

class ExplorerLaunchRequest(BaseModel):
    url: str

traffic_log: List[TrafficEntry] = []
attack_suggestions: List[AttackSuggestion] = []
va_alerts: List[VAAlertModel] = []
ai_reasoning_logs: List[str] = []

parser = JsonOutputParser(pydantic_object=AttackSuggestion)

def generate_autonomous_report(flaw_type: str, description: str, payload: str):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report_entry = f"\n### [{timestamp}] Potential {flaw_type} Identified\n"
    report_entry += f"- **Description:** {description}\n"
    report_entry += f"- **Payload:** `{payload}`\n"
    report_entry += "---\n"
    with open("live_summary.md", "a") as f:
        f.write(report_entry)

def add_ai_log(message: str):
    ai_reasoning_logs.append(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {message}")
    if len(ai_reasoning_logs) > 50:
        ai_reasoning_logs.pop(0)

async def run_autonomous_explorer(target_url: str):
    add_ai_log(f"🚀 Launching Autonomous Explorer for {target_url}")
    async with async_playwright() as p:
        try:
            browser = await p.firefox.launch(headless=True, proxy={"server": "http://localhost:8080"})
            context = await browser.new_context(ignore_https_errors=True)
            page = await context.new_page()

            await page.goto(target_url, wait_until="networkidle")
            add_ai_log(f"Page loaded: {target_url}. Starting DOM analysis...")

            for i in range(5):
                elements = await page.evaluate("""
                    () => {
                        return Array.from(document.querySelectorAll('a, button, input[type="submit"]'))
                            .map(el => ({
                                tag: el.tagName,
                                text: (el.innerText || el.value || "").trim(),
                                id: el.id,
                                class: el.className
                            })).filter(el => el.text.length > 0).slice(0, 10);
                    }
                """)

                if not elements:
                    add_ai_log("No interactable elements found. Ending session.")
                    break

                add_ai_log(f"Found {len(elements)} interactable elements. Deciding next move...")

                found = False
                for el in elements:
                    if any(k in el['text'].lower() for k in ["cart", "check", "buy", "pay", "ticket", "login", "aggiungi"]):
                        add_ai_log(f"AI decided to click: '{el['text']}' (Priority Match)")
                        await page.get_by_text(el['text']).first.click()
                        found = True
                        break

                if not found:
                    add_ai_log(f"No priority element found. Clicking first available: '{elements[0]['text']}'")
                    await page.get_by_text(elements[0]['text']).first.click()

                await page.wait_for_timeout(3000)
                add_ai_log(f"Interaction {i+1} complete. Current URL: {page.url}")

            await browser.close()
            add_ai_log("🏁 Autonomous Explorer session finished.")
        except Exception as e:
            add_ai_log(f"Explorer Error: {e}")

@app.post("/explorer/launch")
async def launch_explorer(request: ExplorerLaunchRequest):
    asyncio.create_task(run_autonomous_explorer(request.url))
    return {"status": "launched"}

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
    db_path = os.getenv("DATABASE_PATH", "/app/traffic.db")
    if not os.path.exists(db_path):
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
        cursor.execute("CREATE VIRTUAL TABLE IF NOT EXISTS vss_kb USING vss0(embedding(384))")
        cursor.execute("CREATE TABLE IF NOT EXISTS kb_vss_map (rowid INTEGER PRIMARY KEY, kb_id INTEGER)")
        conn.commit()
    except Exception as e:
        print(f"Warning: Could not initialize VSS tables: {e}")
    finally:
        conn.close()

init_vss()

def semantic_lookup(query: str, top_k: int = 3):
    try:
        query_embedding = embed_model.encode([query])[0].tolist()
        conn = get_db_connection()
        cursor = conn.cursor()
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
    You are an expert in Business Logic Flaws. Give ABSOLUTE PRIORITY to business logic vulnerabilities over common technical flaws like XSS or SQLi.
    Look for inconsistencies in:
    - Payment flows (price manipulation, negative quantities).
    - Authentication bypasses and Session Management flaws.
    - IDOR (Insecure Direct Object References) in sensitive endpoints.
    - Race conditions in logic-heavy fields (e.g., coupons, balances).

    Analyze the following HTTP request.
    Method: {method}
    URL: {url}
    Request Body: {body}

    Relevant Knowledge Base:
    {knowledge_base}

    Context: {context}

    If you find a potential flaw, propose a specific attack and provide "mutation_instructions" to replay the request with the exploit.
    Special Case: If a discrepancy is found between a displayed price ({displayed_price}) and a submitted price, suggest "Parameter Pollution".

    Your response must be a JSON object with the following fields:
    - flaw_type: A short name (e.g., "IDOR", "Price Manipulation")
    - description: Clear explanation.
    - suggested_payload: Specific payload.
    - mutation_instructions: An object with 'method', 'url', 'headers' (dict mapping keys to lists of strings), and 'body'.

    If no flaw is found, return the string "NONE".

    {format_instructions}
    """
)

async def analyze_traffic(entry: TrafficEntry):
    add_ai_log(f"Analyzing {entry.url}: searching for business logic flaws...")
    kb_relevant = semantic_lookup(entry.url + entry.request_body)

    displayed_price = None
    context = ""

    if any(k in entry.url for k in ["checkout", "purchase", "cart", "ticket"]):
        add_ai_log(f"Sensitive context detected in {entry.url}. Crawling for price discrepancies...")
        referer = None
        if entry.headers:
            referer_raw = entry.headers.get("Referer") or entry.headers.get("referer")
            if isinstance(referer_raw, list) and len(referer_raw) > 0:
                referer = referer_raw[0]
            elif isinstance(referer_raw, str):
                referer = referer_raw

        if referer:
            displayed_price = extract_price_from_url(referer)
            if displayed_price:
                context = f"Price discrepancy analysis active. Page shows ${displayed_price}."
                add_ai_log(f"Extracted displayed price: ${displayed_price}")
            else:
                context = "E-commerce context detected, but no price found in referer."
        else:
            context = "E-commerce context detected, but no Referer available."

    if not llm:
        if any(keyword in entry.url.lower() for keyword in ["cart", "checkout", "ticket", "trenord"]):
            flaw_type = "Price Manipulation"
            payload = "price=0.01"
            description = "[MOCK] Business Logic Flaw: Numeric parameter manipulation suspected."

            mutation = MutationInstructions(
                method=entry.method,
                url=entry.url,
                headers=entry.headers,
                body=entry.request_body.replace("price=", "price=0.01") if "price=" in entry.request_body else "price=0.01"
            )

            suggestion = AttackSuggestion(
                id=str(uuid.uuid4()),
                traffic_id=entry.id,
                flaw_type=flaw_type,
                description=description,
                suggested_payload=payload,
                status="pending",
                mutation_instructions=mutation
            )
            attack_suggestions.append(suggestion)
            generate_autonomous_report(flaw_type, description, payload)
            add_ai_log(f"Mock AI identified potential {flaw_type} in {entry.url}")
            return suggestion
        return None

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
            flaw_type = response.get("flaw_type", "Unknown")
            description = response.get("description", "")
            payload = response.get("suggested_payload", "")

            mutation_data = response.get("mutation_instructions")
            mutation = None
            if mutation_data:
                mutation = MutationInstructions(**mutation_data)

            suggestion = AttackSuggestion(
                id=str(uuid.uuid4()),
                traffic_id=entry.id,
                flaw_type=flaw_type,
                description=description,
                suggested_payload=payload,
                status="pending",
                mutation_instructions=mutation
            )
            attack_suggestions.append(suggestion)
            generate_autonomous_report(flaw_type, description, payload)
            add_ai_log(f"AI identified potential {flaw_type}: {description}")
            return suggestion
    except Exception as e:
        add_ai_log(f"Error during AI analysis: {e}")
    return None

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

    suggestion = await analyze_traffic(entry)

    return {
        "status": "ok",
        "entry_id": entry.id,
        "mutation_instructions": suggestion.mutation_instructions if suggestion else None
    }

@app.get("/traffic")
async def get_traffic():
    return traffic_log

@app.get("/attacks")
async def get_attacks():
    return attack_suggestions

@app.get("/va/alerts")
async def get_va_alerts():
    return va_alerts

@app.get("/ai-logs")
async def get_ai_logs():
    return ai_reasoning_logs

@app.post("/attacks/{attack_id}/approve")
async def approve_attack(attack_id: str):
    for attack in attack_suggestions:
        if attack.id == attack_id:
            attack.status = "approved"
            try:
                text_to_embed = f"{attack.description} {attack.suggested_payload}"
                embedding = embed_model.encode([text_to_embed])[0].tolist()
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute("INSERT INTO knowledge_base (vulnerability_type, payload, fingerprint) VALUES (?, ?, ?)",
                               (attack.flaw_type, attack.suggested_payload, "mock_fp"))
                kb_id = cursor.lastrowid
                cursor.execute("INSERT INTO vss_kb(rowid, embedding) VALUES (?, ?)", (kb_id, json.dumps(embedding)))
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
