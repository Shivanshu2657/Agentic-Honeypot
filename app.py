from fastapi import FastAPI, Header, HTTPException, Request, Body
from fastapi.responses import HTMLResponse
import uuid
from datetime import datetime

from detection import detect_scam
from agent import agent_reply
from storage import get_session
from intelligence import extract_intelligence
from callback import send_final_callback
from config import API_KEY

app = FastAPI()

# Risk triggers
LINK_KEYWORDS = ["http", "https", "link"]
CRITICAL_KEYWORDS = ["otp", "upi"]


# -------------------------------------------------
# LANDING PAGE (Professional, Human-Friendly)
# -------------------------------------------------
@app.get("/", response_class=HTMLResponse)
def home():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Agentic Honeypot API</title>
        <style>
            body {
                font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI";
                background: #f6f7fb;
                height: 100vh;
                margin: 0;
                display: flex;
                justify-content: center;
                align-items: center;
            }
            .card {
                background: white;
                padding: 40px;
                border-radius: 10px;
                box-shadow: 0 10px 25px rgba(0,0,0,0.08);
                width: 360px;
                text-align: center;
            }
            h2 { margin-bottom: 10px; }
            p { color: #555; font-size: 14px; margin-bottom: 25px; }
            a {
                display: block;
                margin: 10px 0;
                padding: 12px;
                border-radius: 6px;
                text-decoration: none;
                font-size: 14px;
                background: #2563eb;
                color: white;
            }
            a.secondary {
                background: #e5e7eb;
                color: #111;
            }
        </style>
    </head>
    <body>
        <div class="card">
            <h2>Agentic Honeypot API</h2>
            <p>
                AI-powered scam detection & intelligence extraction.<br>
                API-first. Evaluation-ready.
            </p>
            <a href="/docs">Open API Documentation</a>
            <a href="/chat" class="secondary">Demo UI (Human Testing Only)</a>
        </div>
    </body>
    </html>
    """


# -------------------------------------------------
# MAIN EVALUATION ENDPOINT (AUTHORITATIVE)
# -------------------------------------------------
@app.post("/honeypot")
async def honeypot_api(
    request: Request,
    payload: dict = Body(...),
    x_api_key: str = Header(None)
):
    # API key auth
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")

    session_id = payload["sessionId"]
    incoming_text = payload["message"]["text"]
    text_lower = incoming_text.lower()

    # Load session
    session = get_session(session_id)
    session["messages"].append(incoming_text)
    msg_count = len(session["messages"])

    # Scam detection
    if not session["scam_detected"]:
        session["scam_detected"] = detect_scam(incoming_text)

    # Stage logic
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

    # Mandatory final callback (only once)
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

    # Agent reply
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
# DEMO UI → API BRIDGE (FIXED WITH CONTEXT)
# -------------------------------------------------
@app.post("/chat/send")
async def chat_send(payload: dict):
    session_id = payload["sessionId"]
    text = payload["text"]

    # Use SAME session memory as /honeypot
    session = get_session(session_id)

    conversation_history = []
    for msg in session["messages"]:
        conversation_history.append({
            "sender": "scammer",
            "text": msg,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        })

    honeypot_payload = {
        "sessionId": session_id,
        "message": {
            "sender": "scammer",
            "text": text,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        },
        "conversationHistory": conversation_history,
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
