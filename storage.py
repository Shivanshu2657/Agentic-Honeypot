SESSIONS = {}

def get_session(session_id: str):
    if session_id not in SESSIONS:
        SESSIONS[session_id] = {
            "messages": [],
            "scam_detected": False,
            "completed": False,
            "stage": "confused"   # confused → probing → delaying → exit
        }
    return SESSIONS[session_id]
