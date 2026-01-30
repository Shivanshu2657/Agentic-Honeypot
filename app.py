from fastapi import FastAPI, Header, HTTPException
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


@app.post("/honeypot")
async def honeypot_api(
    payload: dict,
    x_api_key: str = Header(None)
):
    # -------------------------------------------------
    # 1. API KEY AUTH
    # -------------------------------------------------
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")

    # -------------------------------------------------
    # 2. EXTRACT DATA
    # -------------------------------------------------
    session_id = payload["sessionId"]
    incoming_text = payload["message"]["text"]
    text_lower = incoming_text.lower()

    # -------------------------------------------------
    # 3. SESSION LOAD
    # -------------------------------------------------
    session = get_session(session_id)
    session["messages"].append(incoming_text)

    msg_count = len(session["messages"])

    # -------------------------------------------------
    # 4. SCAM DETECTION (ML + RULES)
    # -------------------------------------------------
    if not session["scam_detected"]:
        session["scam_detected"] = detect_scam(incoming_text)

    # -------------------------------------------------
    # 5. STAGE DECISION (SMART + SCALABLE)
    # -------------------------------------------------
    # Priority overrides (content-based)
    if any(k in text_lower for k in LINK_KEYWORDS):
        session["stage"] = "exit"
    elif any(k in text_lower for k in CRITICAL_KEYWORDS) and msg_count >= 2:
        session["stage"] = "delaying"
    else:
        # Fallback to progression logic (count-based but flexible)
        if msg_count <= 2:
            session["stage"] = "confused"
        elif msg_count <= 4:
            session["stage"] = "probing"
        elif msg_count <= 7:
            session["stage"] = "delaying"
        else:
            session["stage"] = "exit"

    # -------------------------------------------------
    # 6. FINAL CALLBACK (ONLY ONCE)
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
    # 7. AGENT RESPONSE
    # -------------------------------------------------
    if session["scam_detected"]:
        last_msg = session["messages"][-1]
        reply = agent_reply(session["stage"], last_msg)
    else:
        reply = "Thank you for the information."

    # -------------------------------------------------
    # 8. RESPONSE
    # -------------------------------------------------
    return {
        "status": "success",
        "reply": reply
    }
