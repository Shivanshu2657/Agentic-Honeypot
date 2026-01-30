import re
from config import SCAM_KEYWORDS

def extract_intelligence(messages: list):
    text = " ".join(messages)

    upi_ids = re.findall(r"\b[\w.-]+@[\w.-]+\b", text)
    phone_numbers = re.findall(r"\+91\d{10}|\b\d{10}\b", text)
    links = re.findall(r"https?://\S+", text)

    suspicious_keywords = [
        word for word in SCAM_KEYWORDS if word in text.lower()
    ]

    return {
        "upiIds": list(set(upi_ids)),
        "phoneNumbers": list(set(phone_numbers)),
        "phishingLinks": list(set(links)),
        "suspiciousKeywords": suspicious_keywords
    }
