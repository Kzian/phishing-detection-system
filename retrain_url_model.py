"""
Retrain URL detector on 109 features.
Drops only url_google_index and domain_google_index (rank 84 & 89, importance ~0.0001 each).
All other 12 network features are kept — they will be properly computed at inference time.
"""
import pandas as pd
import pickle
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

# Only drop features we truly cannot compute
DROP = ["url_google_index", "domain_google_index"]

print("📂 Loading dataset...")
df = pd.read_csv("data/raw/phishing_urls.csv").dropna()

# Verify columns exist
missing = [c for c in DROP if c not in df.columns]
if missing:
    print(f"⚠️  Columns not found (already absent): {missing}")
    DROP = [c for c in DROP if c in df.columns]

X = df.drop(columns=["phishing"] + DROP)
y = df["phishing"]

print(f"✅ {len(df):,} rows | {X.shape[1]} features | dropped {DROP}")
print(f"   Label split: {(y==0).sum():,} legitimate | {(y==1).sum():,} phishing")

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

print("\n🤖 Training Random Forest (100 trees, all CPU cores)...")
model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced",   # handles any class imbalance
)
model.fit(X_train, y_train)

y_pred = model.predict(X_test)
print("\n📊 Evaluation on held-out 20%:")
print(classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"]))
print(f"Overall accuracy: {accuracy_score(y_test, y_pred)*100:.2f}%")

# Show top 10 features in this model
importances = pd.Series(model.feature_importances_, index=X.columns)
print("\n🏆 Top 10 features:")
print(importances.nlargest(10).to_string())

with open("data/saved_models/url_detector.pkl", "wb") as f:
    pickle.dump(model, f)
print(f"\n💾 Model saved → data/saved_models/url_detector.pkl")
print(f"   Feature count: {len(model.feature_names_in_)}")
