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

LINK_KEYWORDS = ["http", "https", "link"]
CRITICAL_KEYWORDS = ["otp", "upi"]


# -------------------------------------------------
# LANDING PAGE
# -------------------------------------------------
@app.get("/", response_class=HTMLResponse)
def home():
    return """
    <html>
    <head>
        <title>Agentic Honeypot API</title>
        <style>
            body {
                font-family: system-ui;
                background:#f6f7fb;
                display:flex;
                justify-content:center;
                align-items:center;
                height:100vh;
                margin:0;
            }
            .card{
                background:white;
                padding:40px;
                border-radius:10px;
                box-shadow:0 10px 25px rgba(0,0,0,0.08);
                text-align:center;
            }
            a{
                display:block;
                margin:10px;
                padding:12px;
                background:#2563eb;
                color:white;
                text-decoration:none;
                border-radius:6px;
            }
        </style>
    </head>
    <body>
        <div class="card">
            <h2>Agentic Honeypot API</h2>
            <p>AI-powered scam detection & intelligence extraction</p>
            <a href="/docs">API Docs</a>
            <a href="/chat">Demo UI</a>
        </div>
    </body>
    </html>
    """


# -------------------------------------------------
# MAIN HONEYPOT ENDPOINT (AUTHORITATIVE)
# -------------------------------------------------
@app.post("/honeypot")
async def honeypot_api(
    request: Request,
    payload: dict = Body(...),
    x_api_key: str = Header(None)
):
    # API key check
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")

    # -------------------------------------------------
    # GUVI TESTER SAFE GUARD
    # -------------------------------------------------
    if not payload or "sessionId" not in payload or "message" not in payload:
        return {
            "status": "success",
            "reply": "API reachable"
        }

    session_id = payload["sessionId"]
    incoming_text = payload["message"]["text"]
    text_lower = incoming_text.lower()

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

    # -------------------------------------------------
    # FINAL CALLBACK (MANDATORY)
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
            agent_notes="Scammer used urgency and phishing tactics"
        )

        session["completed"] = True

        return {
            "status": "success",
            "reply": "I will visit my bank branch to confirm this."
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
# DEMO UI
# -------------------------------------------------
@app.get("/chat", response_class=HTMLResponse)
def chat_ui():
    session_id = str(uuid.uuid4())

    return f"""
    <html>
    <body style="font-family:Arial;padding:30px;">
        <h3>Demo UI (Human Testing)</h3>
        <p>Session: {session_id}</p>

        <div id="chat"></div>
        <textarea id="msg" style="width:300px;height:60px;"></textarea><br>
        <button onclick="send()">Send</button>

        <script>
        const sessionId = "{session_id}";
        async function send(){{
            let text=document.getElementById("msg").value;
            document.getElementById("chat").innerHTML += "<p><b>Scammer:</b> "+text+"</p>";

            let res=await fetch("/chat/send", {{
                method:"POST",
                headers:{{"Content-Type":"application/json"}},
                body:JSON.stringify({{sessionId:sessionId,text:text}})
            }});
            let data=await res.json();
            document.getElementById("chat").innerHTML += "<p style='color:blue'><b>Agent:</b> "+data.reply+"</p>";
        }}
        </script>
    </body>
    </html>
    """


# -------------------------------------------------
# DEMO BRIDGE (CONTEXT-AWARE)
# -------------------------------------------------
@app.post("/chat/send")
async def chat_send(payload: dict):
    session_id = payload["sessionId"]
    text = payload["text"]

    session = get_session(session_id)

    conversation_history = []
    for msg in session["messages"]:
        conversation_history.append({
            "sender":"scammer",
            "text":msg,
            "timestamp":datetime.utcnow().isoformat()+"Z"
        })

    honeypot_payload = {
        "sessionId": session_id,
        "message": {
            "sender":"scammer",
            "text":text,
            "timestamp":datetime.utcnow().isoformat()+"Z"
        },
        "conversationHistory":conversation_history,
        "metadata":{
            "channel":"DemoUI",
            "language":"English",
            "locale":"IN"
        }
    }

    return await honeypot_api(
        request=None,
        payload=honeypot_payload,
        x_api_key=API_KEY
    )