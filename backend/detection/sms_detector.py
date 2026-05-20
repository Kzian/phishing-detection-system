import pandas as pd
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
DATA_PATH = os.path.join(BASE_DIR, "data", "raw", "spam.csv")
MODEL_PATH = os.path.join(BASE_DIR, "data", "saved_models", "sms_detector.pkl")


# ─── Clean SMS text ──────────────────────────────────────
def clean_text(text):
    if not isinstance(text, str):
        return ""
    text = text.lower()
    text = re.sub(r"http\S+|www\S+", " url ", text)
    text = re.sub(r"\S+@\S+", " email ", text)
    text = re.sub(r"\d+", " number ", text)
    text = re.sub(r"[^a-z\s]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


# ─── Load and prepare data ───────────────────────────────
def load_data():
    print("📂 Loading SMS dataset...")

    # Only load v1 and v2, ignore empty columns
    df = pd.read_csv(DATA_PATH, usecols=["v1", "v2"], encoding="latin-1")
    df = df.dropna()
    df = df.rename(columns={"v1": "label", "v2": "text"})

    # Convert label: spam = 1, ham = 0
    df["label"] = df["label"].map({"spam": 1, "ham": 0})
    df = df.dropna(subset=["label"])

    # Clean text
    df["text"] = df["text"].apply(clean_text)
    df = df[df["text"].str.strip() != ""]

    # Shuffle
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)

    print(f"✅ Dataset loaded: {len(df)} messages")
    print(f"   Spam/Smishing : {df['label'].sum().astype(int)}")
    print(f"   Legitimate    : {(df['label'] == 0).sum()}")

    return df["text"], df["label"]


# ─── Train the model ─────────────────────────────────────
def train_model():
    X, y = load_data()

    print("\n🔀 Splitting data...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    print("🤖 Training SMS classifier...")
    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(
            max_features=3000,
            ngram_range=(1, 2),
            stop_words="english",
            min_df=2,
            max_df=0.9
        )),
        ("clf", LogisticRegression(
            max_iter=1000,
            random_state=42,
            C=1.0,
            class_weight="balanced"  # fixes class imbalance
        ))
    ])

    pipeline.fit(X_train, y_train)

    print("\n📊 Evaluating model...")
    y_pred = pipeline.predict(X_test)
    print(classification_report(
        y_test, y_pred,
        target_names=["Legitimate", "Spam/Smishing"]
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


# ─── Predict a single SMS ────────────────────────────────
def predict(message: str) -> dict:
    model = load_model()
    text = clean_text(message)
    prob = model.predict_proba([text])[0]
    spam_prob = round(float(prob[1]), 4)

    # Lower threshold for SMS — better to flag than miss a smishing attack
    threshold = 0.35

    return {
        "phishing_probability": spam_prob,
        "legitimate_probability": round(float(prob[0]), 4),
        "prediction": "smishing" if spam_prob >= threshold else "legitimate",
        "confidence": f"{max(prob) * 100:.1f}%",
        "threshold_used": threshold
    }


# ─── Run training ────────────────────────────────────────
if __name__ == "__main__":
    train_model()