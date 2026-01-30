import os

# API security
API_KEY = os.getenv("API_KEY", "shivanshu-honeypot-key")

# GUVI callback
GUVI_CALLBACK_URL = os.getenv(
    "GUVI_CALLBACK_URL",
    "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"
)

# Keywords for intelligence extraction (REQUIRED)
SCAM_KEYWORDS = [
    "blocked",
    "verify",
    "urgent",
    "upi",
    "otp",
    "click",
    "link",
    "suspend",
    "account"
]
