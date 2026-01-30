import requests
from config import GUVI_CALLBACK_URL

def send_final_callback(
    session_id: str,
    total_messages: int,
    intelligence: dict,
    agent_notes: str
):
    payload = {
        "sessionId": session_id,
        "scamDetected": True,
        "totalMessagesExchanged": total_messages,
        "extractedIntelligence": intelligence,
        "agentNotes": agent_notes
    }

    try:
        requests.post(
            GUVI_CALLBACK_URL,
            json=payload,
            timeout=5
        )
    except Exception as e:
        print("Callback failed:", e)
