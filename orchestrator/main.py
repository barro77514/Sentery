from fastapi import FastAPI, Request
from pydantic import BaseModel
from typing import List, Optional
import uuid
import datetime
import os
import json
from fastapi.middleware.cors import CORSMiddleware

from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import JsonOutputParser

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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

traffic_log: List[TrafficEntry] = []
attack_suggestions: List[AttackSuggestion] = []

parser = JsonOutputParser(pydantic_object=AttackSuggestion)

prompt_template = ChatPromptTemplate.from_template(
    """
    You are an expert in Business Logic Flaws for E-commerce and Ticketing systems.
    Analyze the following HTTP request.

    Method: {method}
    URL: {url}
    Request Body: {body}

    Determine if this request is related to a shopping cart (cart), checkout process, or ticketing system (e.g., Trenord, Airline, etc.).
    If it is, identify sensitive parameters such as 'price', 'quantity', 'user_id', 'amount', etc.

    If you find a potential business logic flaw (like price manipulation, quantity tampering, IDOR), propose a specific attack.
    Example attack: "Negative Price Injection" if 'price' is found.

    Your response must be a JSON object with the following fields:
    - flaw_type: A short name for the flaw (e.g., "Price Manipulation")
    - description: A clear explanation of what to test.
    - suggested_payload: A specific payload or modification to try.

    If the request is not sensitive or no flaw is found, return the string "NONE".

    {format_instructions}
    """
)

async def analyze_traffic(entry: TrafficEntry):
    if not llm:
        # Fallback to mock reasoning if no LLM
        if any(keyword in entry.url.lower() for keyword in ["cart", "checkout", "ticket", "trenord"]):
            suggestion = AttackSuggestion(
                id=str(uuid.uuid4()),
                traffic_id=entry.id,
                flaw_type="Price Manipulation",
                description="[MOCK] Detected sensitive context. Attempting to modify numeric parameters.",
                suggested_payload="Change 'price' or 'amount' to -1 or 0.01",
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
        # If it fails to parse as JSON, it might have returned "NONE"
        pass

@app.post("/traffic")
async def ingest_traffic(request: Request):
    data = await request.json()
    entry = TrafficEntry(
        id=str(uuid.uuid4()),
        method=data.get("method"),
        url=data.get("url"),
        request_body=data.get("request_body"),
        response_status=data.get("response_status"),
        response_body_size=data.get("response_body_size"),
        timestamp=datetime.datetime.now()
    )
    traffic_log.append(entry)

    await analyze_traffic(entry)

    return {"status": "ok", "entry_id": entry.id}

@app.get("/traffic")
async def get_traffic():
    return traffic_log

@app.get("/attacks")
async def get_attacks():
    return attack_suggestions

@app.post("/attacks/{attack_id}/approve")
async def approve_attack(attack_id: str):
    for attack in attack_suggestions:
        if attack.id == attack_id:
            attack.status = "approved"
            return {"status": "approved"}
    return {"status": "not_found"}, 404

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
