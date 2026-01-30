import os

API_KEY = os.getenv("API_KEY", "shivanshu-honeypot-key")

GUVI_CALLBACK_URL = os.getenv(
    "GUVI_CALLBACK_URL",
    "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"
)
