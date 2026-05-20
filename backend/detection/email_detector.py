import pandas as pd
import numpy as np
import os
import pickle
import re
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
from sklearn.pipeline import Pipeline

# ─── Paths ───────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
DATA_PATH = os.path.join(BASE_DIR, "data", "raw", "phishing_email.csv")
MODEL_PATH = os.path.join(BASE_DIR, "data", "saved_models", "email_detector.pkl")


# ─── Clean email text ────────────────────────────────────
def clean_text(text):
    if not isinstance(text, str):
        return ""
    text = text.lower()
    text = re.sub(r"http\S+|www\S+", " url ", text)
    text = re.sub(r"\S+@\S+", " email ", text)
    text = re.sub(r"[^a-z\s]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


# ─── Load and prepare data ───────────────────────────────
def load_data():
    print("📂 Loading phishing email dataset...")
    df = pd.read_csv(DATA_PATH, usecols=["text_combined", "label"])
    df = df.dropna()
    df["text_combined"] = df["text_combined"].apply(clean_text)
    df = df[df["text_combined"].str.strip() != ""]

    # Shuffle
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)

    print(f"✅ Dataset loaded: {len(df)} emails")
    print(f"   Phishing    : {df['label'].sum().astype(int)}")
    print(f"   Legitimate  : {(df['label'] == 0).sum()}")

    return df["text_combined"], df["label"]


# ─── Train the model ─────────────────────────────────────
def train_model():
    X, y = load_data()

    print("\n🔀 Splitting data...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    print("🤖 Training email classifier...")
    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(
            max_features=8000,
            ngram_range=(1, 2),
            stop_words="english",
            min_df=3,
            max_df=0.85
        )),
        ("clf", LogisticRegression(
            max_iter=1000,
            random_state=42,
            C=1.0
        ))
    ])

    pipeline.fit(X_train, y_train)

    print("\n📊 Evaluating model...")
    y_pred = pipeline.predict(X_test)
    print(classification_report(
        y_test, y_pred,
        target_names=["Legitimate", "Phishing"]
    ))

    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    with open(MODEL_PATH, "wb") as f:
        pickle.dump(pipeline, f)
    print(f"💾 Model saved to {MODEL_PATH}")

    return pipeline


# ─── Load saved model ────────────────────────────────────
def load_model():
    with open(MODEL_PATH, "rb") as f:
        model = pickle.load(f)
    return model


# ─── Predict a single email ──────────────────────────────
def predict(subject: str, body: str) -> dict:
    model = load_model()
    text = clean_text(subject + " " + body)
    prob = model.predict_proba([text])[0]
    phishing_prob = round(float(prob[1]), 4)

    return {
        "phishing_probability": phishing_prob,
        "legitimate_probability": round(float(prob[0]), 4),
        "prediction": "phishing" if phishing_prob >= 0.5 else "legitimate",
        "confidence": f"{max(prob) * 100:.1f}%"
    }


# ─── Run training ────────────────────────────────────────
if __name__ == "__main__":
    train_model()