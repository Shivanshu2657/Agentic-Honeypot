import random

CONFUSED_TEMPLATES = [
    "I am not understanding this properly. You said '{last_msg}', what does that mean?",
    "Why is this happening now? You mentioned '{last_msg}'.",
]

PROBING_TEMPLATES = [
    "Why do you need {keyword} for this issue?",
    "How will sharing {keyword} solve the problem?",
    "Can you explain again why this is required?"
]

DELAYING_TEMPLATES = [
    "I am outside right now, can I do this later?",
    "My phone battery is low, please wait.",
    "I need some time to check this."
]

EXIT_TEMPLATES = [
    "I will visit the bank branch and confirm this.",
    "I will talk to customer care and get back to you.",
    "I have shared this with my family, I will respond later.",
    "Network is poor right now, I will check later."
]

def extract_keyword(text: str) -> str:
    text = text.lower()
    if "upi" in text:
        return "UPI"
    if "otp" in text:
        return "OTP"
    if "link" in text or "http" in text:
        return "this link"
    return "this information"

def agent_reply(stage: str, last_message: str) -> str:
    keyword = extract_keyword(last_message)

    if stage == "confused":
        return random.choice(CONFUSED_TEMPLATES).format(
            last_msg=last_message
        )

    elif stage == "probing":
        return random.choice(PROBING_TEMPLATES).format(
            keyword=keyword
        )

    elif stage == "delaying":
        return random.choice(DELAYING_TEMPLATES)

    else:
        return random.choice(EXIT_TEMPLATES)
