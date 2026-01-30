from fastapi import FastAPI, Header, HTTPException, Request, Body
from fastapi.responses import HTMLResponse
import json
import uuid
from datetime import datetime

from detection import detect_scam
from agent import agent_reply
from storage import get_session
from intelligence import extract_intelligence
from callback import send_final_callback
from config import API_KEY

app = FastAPI()

# High-risk content triggers
LINK_KEYWORDS = ["http", "https", "link"]
CRITICAL_KEYWORDS = ["otp", "upi"]


# -------------------------------------------------
# ROOT LANDING PAGE (Human Friendly Only)
# -------------------------------------------------
@app.get("/", response_class=HTMLResponse)
def home():
    return """
    <html>
    <head><title>Agentic Honeypot API</title></head>
    <body style="font-family:Arial;text-align:center;padding-top:50px;">
        <h2>Agentic Honeypot API</h2>
        <p>API-first scam detection & intelligence extraction system</p>
        <p><a href="/docs">Open API Docs</a></p>
        <p><a href="/chat">Demo UI (Human Testing Only)</a></p>
    </body>
    </html>
    """


# -------------------------------------------------
# MAIN EVALUATION ENDPOINT (DO NOT CHANGE)
# -------------------------------------------------
@app.post("/honeypot")
async def honeypot_api(
    request: Request,
    payload: dict = Body(...),
    x_api_key: str = Header(None)
):
    # -------------------------------------------------
    # API KEY AUTH (MANDATORY)
    # -------------------------------------------------
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")

    # -------------------------------------------------
    # EXTRACT DATA
    # -------------------------------------------------
    session_id = payload["sessionId"]
    incoming_text = payload["message"]["text"]
    text_lower = incoming_text.lower()

    # -------------------------------------------------
    # SESSION LOAD
    # -------------------------------------------------
    session = get_session(session_id)
    session["messages"].append(incoming_text)
    msg_count = len(session["messages"])

    # -------------------------------------------------
    # SCAM DETECTION
    # -------------------------------------------------
    if not session["scam_detected"]:
        session["scam_detected"] = detect_scam(incoming_text)

    # -------------------------------------------------
    # STAGE DECISION
    # -------------------------------------------------
    if any(k in text_lower for k in LINK_KEYWORDS):
        session["stage"] = "exit"
    elif any(k in text_lower for k in CRITICAL_KEYWORDS) and msg_count >= 2:
        session["stage"] = "delaying"
    else:
        if msg_count <= 2:
            session["stage"] = "confused"
        elif msg_count <= 4:
            session["stage"] = "probing"
        elif msg_count <= 7:
            session["stage"] = "delaying"
        else:
            session["stage"] = "exit"

    # -------------------------------------------------
    # FINAL CALLBACK (MANDATORY, ONLY ONCE)
    # -------------------------------------------------
    if (
        session["scam_detected"]
        and session["stage"] == "exit"
        and not session["completed"]
        and msg_count >= 4
    ):
        intelligence = extract_intelligence(session["messages"])

        send_final_callback(
            session_id=session_id,
            total_messages=msg_count,
            intelligence=intelligence,
            agent_notes="Scammer used urgency, payment redirection, and phishing tactics"
        )

        session["completed"] = True

        return {
            "status": "success",
            "reply": "I will visit the bank branch and confirm this."
        }

    # -------------------------------------------------
    # AGENT RESPONSE
    # -------------------------------------------------
    if session["scam_detected"]:
        reply = agent_reply(session["stage"], incoming_text)
    else:
        reply = "Thank you for the information."

    return {
        "status": "success",
        "reply": reply
    }


# -------------------------------------------------
# DEMO UI (HUMAN TESTING ONLY)
# -------------------------------------------------
@app.get("/chat", response_class=HTMLResponse)
def chat_demo_ui():
    session_id = str(uuid.uuid4())

    return f"""
    <html>
    <head><title>Agentic Honeypot – Demo UI</title></head>
    <body style="font-family:Arial;background:#f4f6f8;padding:30px;">
        <div style="max-width:600px;margin:auto;background:white;padding:20px;border-radius:8px;">
            <h3>Agentic Honeypot – Demo UI</h3>
            <p style="font-size:12px;color:#555;">
                Demo UI (Human Testing Only). Uses the same backend logic as automated evaluation.
            </p>
            <p><b>Session ID:</b> {session_id}</p>

            <div id="chat"></div>

            <textarea id="input" style="width:100%;height:80px;" placeholder="Type scammer message..."></textarea>
            <br><br>
            <button onclick="sendMsg()">Send</button>
        </div>

        <script>
            const sessionId = "{session_id}";

            async function sendMsg() {{
                const text = document.getElementById("input").value;
                document.getElementById("input").value = "";

                document.getElementById("chat").innerHTML +=
                    `<p><b>Scammer:</b> ${{text}}</p>`;

                const res = await fetch("/chat/send", {{
                    method: "POST",
                    headers: {{ "Content-Type": "application/json" }},
                    body: JSON.stringify({{
                        sessionId: sessionId,
                        text: text
                    }})
                }});

                const data = await res.json();

                document.getElementById("chat").innerHTML +=
                    `<p style="color:#2563eb;"><b>Agent:</b> ${{data.reply}}</p>`;
            }}
        </script>
    </body>
    </html>
    """


# -------------------------------------------------
# DEMO → API BRIDGE
# -------------------------------------------------
@app.post("/chat/send")
async def chat_send(payload: dict):
    honeypot_payload = {
        "sessionId": payload["sessionId"],
        "message": {
            "sender": "scammer",
            "text": payload["text"],
            "timestamp": datetime.utcnow().isoformat() + "Z"
        },
        "conversationHistory": [],
        "metadata": {
            "channel": "DemoUI",
            "language": "English",
            "locale": "IN"
        }
    }

    return await honeypot_api(
        request=None,
        payload=honeypot_payload,
        x_api_key=API_KEY
    )
