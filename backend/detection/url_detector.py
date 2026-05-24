import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import pickle
import os

# ─── Paths ───────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
DATA_PATH = os.path.join(BASE_DIR, "data", "raw", "phishing_urls.csv")
MODEL_PATH = os.path.join(BASE_DIR, "data", "saved_models", "url_detector.pkl")


# ─── Load and prepare data ───────────────────────────────
def load_data():
    print("📂 Loading dataset...")
    df = pd.read_csv(DATA_PATH)

    # Drop rows with missing values
    df = df.dropna()

    # Separate features and label
    X = df.drop(columns=["phishing"])
    y = df["phishing"]

    print(f"✅ Dataset loaded: {len(df)} rows, {X.shape[1]} features")
    print(f"   Phishing URLs : {y.sum()}")
    print(f"   Legitimate URLs: {(y == 0).sum()}")

    return X, y


# ─── Train the model ─────────────────────────────────────
def train_model():
    X, y = load_data()

    print("\n🔀 Splitting data into train/test sets...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    print("🤖 Training Random Forest classifier...")
    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        n_jobs=-1  # use all CPU cores
    )
    model.fit(X_train, y_train)

    print("\n📊 Evaluating model...")
    y_pred = model.predict(X_test)
    print(classification_report(y_test, y_pred,
          target_names=["Legitimate", "Phishing"]))

    # Save the model
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    with open(MODEL_PATH, "wb") as f:
        pickle.dump(model, f)
    print(f"💾 Model saved to {MODEL_PATH}")

    return model


# ─── Load saved model ────────────────────────────────────
def load_model():
    with open(MODEL_PATH, "rb") as f:
        model = pickle.load(f)
    return model


# ─── Predict a single URL's features ────────────────────
def predict(features: dict) -> dict:
    """
    Takes a dictionary of URL features and returns
    a prediction with threat score.
    """
    model = load_model()

    # Convert to dataframe row
    df = pd.DataFrame([features])
    df = df[model.feature_names_in_]  # enforce training column order

    prob = model.predict_proba(df)[0]
    phishing_prob = round(float(prob[1]), 4)

    return {
        "phishing_probability": phishing_prob,
        "legitimate_probability": round(float(prob[0]), 4),
        "prediction": "phishing" if phishing_prob >= 0.5 else "legitimate",
        "confidence": f"{max(prob) * 100:.1f}%"
    }


# ─── Run training directly ───────────────────────────────
if __name__ == "__main__":
    train_model()