import joblib

# Load ML artifacts
model = joblib.load("model/scam_model.pkl")
vectorizer = joblib.load("model/tfidf.pkl")

HIGH_RISK_KEYWORDS = ["otp", "upi", "verify", "click", "link"]

def detect_scam(text: str) -> bool:
    text_lower = text.lower()

    # Rule-based override (critical signals)
    for word in HIGH_RISK_KEYWORDS:
        if word in text_lower:
            return True

    # ML-based probability
    X = vectorizer.transform([text])
    prob = model.predict_proba(X)[0][1]

    return prob > 0.7
