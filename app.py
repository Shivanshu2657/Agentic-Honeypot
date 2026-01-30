from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse
import json

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
# ROOT LANDING PAGE
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
                height: 100vh;
                margin: 0;
                display: flex;
                justify-content: center;
                align-items: center;
                background: #f6f7fb;
                font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI";
            }
            .box {
                background: white;
                padding: 40px;
                border-radius: 10px;
                box-shadow: 0 10px 25px rgba(0,0,0,0.08);
                text-align: center;
            }
            button {
                padding: 12px 22px;
                font-size: 15px;
                border: none;
                border-radius: 6px;
                background: #2563eb;
                color: white;
                cursor: pointer;
            }
            button:hover {
                background: #1e40af;
            }
        </style>
    </head>
    <body>
        <div class="box">
            <h2>Agentic Honeypot API</h2>
            <p>AI-powered scam detection & intelligence extraction</p>
            <a href="/docs"><button>Open API Docs</button></a>
        </div>
    </body>
    </html>
    """


# -------------------------------------------------
# MAIN HONEYPOT ENDPOINT
# -------------------------------------------------
@app.post("/honeypot")
async def honeypot_api(
    request: Request,
    x_api_key: str = Header(None)
):
    # -------------------------------------------------
    # SMART-QUOTE SAFE JSON PARSING
    # -------------------------------------------------
    raw_body = await request.body()
    body_str = raw_body.decode("utf-8")

    body_str = (
        body_str
        .replace("“", "\"")
        .replace("”", "\"")
        .replace("‘", "'")
        .replace("’", "'")
    )

    try:
        payload = json.loads(body_str)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON format")

    # -------------------------------------------------
    # API KEY AUTH
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
    # SCAM DETECTION (ML + RULES)
    # -------------------------------------------------
    if not session["scam_detected"]:
        session["scam_detected"] = detect_scam(incoming_text)

    # -------------------------------------------------
    # STAGE DECISION (SMART + SCALABLE)
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
    # FINAL CALLBACK (ONLY ONCE)
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
        last_msg = session["messages"][-1]
        reply = agent_reply(session["stage"], last_msg)
    else:
        reply = "Thank you for the information."

    # -------------------------------------------------
    # RESPONSE
    # -------------------------------------------------
    return {
        "status": "success",
        "reply": reply
    }
