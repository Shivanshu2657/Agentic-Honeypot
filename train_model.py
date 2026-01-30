import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
import joblib
import os

# Load data
df = pd.read_csv("data/scam_dataset.csv")

X = df["text"]
y = df["label"]

# Vectorizer
vectorizer = TfidfVectorizer(
    lowercase=True,
    stop_words="english",
    ngram_range=(1, 2)
)

X_vec = vectorizer.fit_transform(X)

# Model
model = LogisticRegression()
model.fit(X_vec, y)

# Save artifacts
os.makedirs("model", exist_ok=True)

joblib.dump(model, "model/scam_model.pkl")
joblib.dump(vectorizer, "model/tfidf.pkl")

print("✅ ML model trained and saved")
