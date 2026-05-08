from fastapi import FastAPI, Request
from pydantic import BaseModel
from typing import List, Optional
import uuid
import datetime
import os
import google.generativeai as genai
import json
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure Gemini
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)
    model = genai.GenerativeModel('gemini-pro')
else:
    model = None

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

async def analyze_traffic(entry: TrafficEntry):
    if not model:
        # Fallback to mock reasoning
        if "checkout" in entry.url or "cart" in entry.url:
            suggestion = AttackSuggestion(
                id=str(uuid.uuid4()),
                traffic_id=entry.id,
                flaw_type="Price Manipulation",
                description="[MOCK] Detected potential checkout process. Attempting to modify item prices.",
                suggested_payload="Change price parameter to 0.01",
                status="pending"
            )
            attack_suggestions.append(suggestion)
        return

    prompt = f"""
    Analyze the following HTTP traffic for potential business logic flaws, especially in e-commerce or ticketing contexts.

    Method: {entry.method}
    URL: {entry.url}
    Request Body: {entry.request_body}
    Response Status: {entry.response_status}

    If you find a potential flaw, respond with a JSON object containing:
    "flaw_type": short name of the flaw
    "description": detailed explanation
    "suggested_payload": a specific payload to test the flaw

    If no obvious business logic flaw is found, respond with "NONE".
    """

    try:
        response = model.generate_content(prompt)
        text = response.text.strip()
        if text != "NONE":
            # Basic JSON extraction from response
            if "```json" in text:
                text = text.split("```json")[1].split("```")[0].strip()
            elif "```" in text:
                text = text.split("```")[1].split("```")[0].strip()

            data = json.loads(text)
            suggestion = AttackSuggestion(
                id=str(uuid.uuid4()),
                traffic_id=entry.id,
                flaw_type=data.get("flaw_type", "Unknown"),
                description=data.get("description", ""),
                suggested_payload=data.get("suggested_payload", ""),
                status="pending"
            )
            attack_suggestions.append(suggestion)
    except Exception as e:
        print(f"Error during AI analysis: {e}")

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
            # Here you would trigger the actual attack via the Core Engine
            return {"status": "approved"}
    return {"status": "not_found"}, 404

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
