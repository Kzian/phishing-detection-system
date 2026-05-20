import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from backend.detection.url_detector import predict as predict_url
from backend.detection.email_detector import predict as predict_email
from backend.detection.sms_detector import predict as predict_sms

# ─── Severity Levels ─────────────────────────────────────
SEVERITY_LEVELS = {
    "CLEAN":    (0.0,  0.3),
    "LOW":      (0.3,  0.5),
    "MEDIUM":   (0.5,  0.7),
    "HIGH":     (0.7,  0.85),
    "CRITICAL": (0.85, 1.0),
}

# ─── Actions per severity ────────────────────────────────
RESPONSE_ACTIONS = {
    "CLEAN":    ["log_only"],
    "LOW":      ["log_incident", "flag_message"],
    "MEDIUM":   ["log_incident", "flag_message", "notify_user"],
    "HIGH":     ["log_incident", "quarantine", "notify_admin", "block_sender"],
    "CRITICAL": ["log_incident", "quarantine", "notify_admin",
                 "block_sender", "lock_account", "generate_report"],
}


# ─── Get severity from score ─────────────────────────────
def get_severity(score: float) -> str:
    for level, (low, high) in SEVERITY_LEVELS.items():
        if low <= score < high:
            return level
    return "CRITICAL"


# ─── Analyze URL ─────────────────────────────────────────
def analyze_url(features: dict) -> dict:
    result = predict_url(features)
    score = result["phishing_probability"]
    severity = get_severity(score)

    return {
        "input_type": "url",
        "threat_score": score,
        "severity": severity,
        "prediction": result["prediction"],
        "confidence": result["confidence"],
        "actions": RESPONSE_ACTIONS[severity],
    }


# ─── Analyze Email ───────────────────────────────────────
def analyze_email(subject: str, body: str) -> dict:
    result = predict_email(subject, body)
    score = result["phishing_probability"]
    severity = get_severity(score)

    return {
        "input_type": "email",
        "threat_score": score,
        "severity": severity,
        "prediction": result["prediction"],
        "confidence": result["confidence"],
        "actions": RESPONSE_ACTIONS[severity],
        "subject": subject,
    }


# ─── Analyze SMS ─────────────────────────────────────────
def analyze_sms(message: str) -> dict:
    result = predict_sms(message)
    score = result["phishing_probability"]
    severity = get_severity(score)

    return {
        "input_type": "sms",
        "threat_score": score,
        "severity": severity,
        "prediction": result["prediction"],
        "confidence": result["confidence"],
        "actions": RESPONSE_ACTIONS[severity],
    }


# ─── Test all three ──────────────────────────────────────
if __name__ == "__main__":
    import json

    print("\n" + "="*50)
    print("🔍 THREAT SCORING ENGINE TEST")
    print("="*50)

    # Test email
    email_result = analyze_email(
        subject="URGENT: Your patient portal access will be suspended",
        body="Dear user, click here immediately to verify your healthcare credentials or lose access."
    )
    print("\n📧 EMAIL ANALYSIS:")
    print(json.dumps(email_result, indent=2))

    # Test SMS
    sms_result = analyze_sms(
        "URGENT: Your hospital account suspended. Verify now: http://fake-hospital.com"
    )
    print("\n📱 SMS ANALYSIS:")
    print(json.dumps(sms_result, indent=2))

    print("\n" + "="*50)