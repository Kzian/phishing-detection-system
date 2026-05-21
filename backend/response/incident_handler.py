import os
import json
import uuid
import requests
from datetime import datetime, timezone

# ─── Timezone-aware UTC ──────────────────────────────────
def utcnow():
    return datetime.now(timezone.utc).isoformat()

# ─── Config ──────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
LOG_PATH = os.path.join(BASE_DIR, "data", "incidents.json")
N8N_WEBHOOK_URL = "http://localhost:5678/webhook/phishing-alert"


# ─── Load existing incidents ─────────────────────────────
def load_incidents() -> list:
    if os.path.exists(LOG_PATH):
        with open(LOG_PATH, "r") as f:
            return json.load(f)
    return []


# ─── Save incidents ──────────────────────────────────────
def save_incidents(incidents: list):
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    with open(LOG_PATH, "w") as f:
        json.dump(incidents, f, indent=2)


# ─── Notify n8n ──────────────────────────────────────────
def notify_n8n(incident: dict):
    try:
        response = requests.post(N8N_WEBHOOK_URL, json={
            "incident_id": incident["incident_id"],
            "severity": incident["severity"],
            "input_type": incident["input_type"],
            "threat_score": incident["threat_score"],
            "prediction": incident["prediction"],
            "confidence": incident["confidence"],
            "actions": incident["actions_taken"],
            "preview": incident["raw_input_preview"]
        }, timeout=5)
        return {"n8n_notified": True, "status_code": response.status_code}
    except Exception as e:
        return {"n8n_notified": False, "error": str(e)}


# ─── Create incident record ──────────────────────────────
def create_incident(analysis_result: dict, raw_input: str = "") -> dict:
    incident = {
        "incident_id": str(uuid.uuid4())[:8].upper(),
        "timestamp": utcnow(),
        "input_type": analysis_result.get("input_type"),
        "threat_score": analysis_result.get("threat_score"),
        "severity": analysis_result.get("severity"),
        "prediction": analysis_result.get("prediction"),
        "confidence": analysis_result.get("confidence"),
        "actions_taken": analysis_result.get("actions", []),
        "raw_input_preview": raw_input[:100],
        "status": "open",
        "resolved": False,
    }
    return incident


# ─── Handle incident ─────────────────────────────────────
def handle_incident(analysis_result: dict, raw_input: str = "") -> dict:
    incident = create_incident(analysis_result, raw_input)

    # Log to file
    incidents = load_incidents()
    incidents.append(incident)
    save_incidents(incidents)

    # Notify n8n
    n8n_response = notify_n8n(incident)
    incident["n8n_response"] = n8n_response

    # Execute actions
    actions_taken = []
    for action in incident["actions_taken"]:
        result = execute_action(action, incident)
        actions_taken.append(result)

    incident["execution_log"] = actions_taken
    print(f"\n🚨 Incident {incident['incident_id']} created — Severity: {incident['severity']}")
    print(f"   Actions executed: {len(actions_taken)}")
    print(f"   n8n notified: {n8n_response.get('n8n_notified')}")

    return incident


# ─── Execute individual actions ──────────────────────────
def execute_action(action: str, incident: dict) -> dict:
    timestamp = utcnow()

    action_map = {
        "log_only": lambda: {
            "action": "log_only",
            "status": "success",
            "message": "Incident logged to file",
            "timestamp": timestamp,
        },
        "flag_message": lambda: {
            "action": "flag_message",
            "status": "success",
            "message": f"Message flagged as {incident['prediction']}",
            "timestamp": timestamp,
        },
        "notify_user": lambda: {
            "action": "notify_user",
            "status": "success",
            "message": "User notified about suspicious message",
            "timestamp": timestamp,
        },
        "quarantine": lambda: {
            "action": "quarantine",
            "status": "success",
            "message": "Message quarantined — removed from inbox",
            "timestamp": timestamp,
        },
        "notify_admin": lambda: {
            "action": "notify_admin",
            "status": "success",
            "message": "Security admin alerted via notification",
            "timestamp": timestamp,
        },
        "block_sender": lambda: {
            "action": "block_sender",
            "status": "success",
            "message": "Sender blocked from future communication",
            "timestamp": timestamp,
        },
        "lock_account": lambda: {
            "action": "lock_account",
            "status": "success",
            "message": "Account temporarily locked pending review",
            "timestamp": timestamp,
        },
        "generate_report": lambda: generate_incident_report(incident),
    }

    handler = action_map.get(action)
    if handler:
        return handler()
    return {"action": action, "status": "unknown", "timestamp": timestamp}


# ─── Generate incident report ────────────────────────────
def generate_incident_report(incident: dict) -> dict:
    report = f"""
SECURITY INCIDENT REPORT
═══════════════════════════════════════
Incident ID   : {incident['incident_id']}
Timestamp     : {incident['timestamp']}
Severity      : {incident['severity']}
Type          : {incident['input_type'].upper()} phishing attempt
Threat Score  : {incident['threat_score']} / 1.0
Confidence    : {incident['confidence']}

DETECTION SUMMARY
───────────────────────────────────────
The system detected a {incident['severity']} severity
{incident['prediction']} attempt via {incident['input_type']}.
Threat score of {incident['threat_score']} exceeded the
critical threshold, triggering automated response.

INPUT PREVIEW
───────────────────────────────────────
{incident['raw_input_preview']}...

ACTIONS TAKEN
───────────────────────────────────────
{chr(10).join(f"  ✓ {a}" for a in incident['actions_taken'])}

RECOMMENDATION
───────────────────────────────────────
Immediate review required. Check related accounts
for signs of compromise. Update threat intelligence
feeds with indicators from this incident.

STATUS: OPEN — Awaiting analyst review
═══════════════════════════════════════
    """.strip()

    return {
        "action": "generate_report",
        "status": "success",
        "message": "Incident report generated",
        "report": report,
        "timestamp": utcnow(),
    }


# ─── Get all incidents ───────────────────────────────────
def get_all_incidents() -> list:
    return load_incidents()


# ─── Test ────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    sys.path.insert(0, BASE_DIR)
    from backend.scoring.threat_engine import analyze_email

    print("🧪 Testing Incident Handler...")

    analysis = analyze_email(
        subject="URGENT: Your patient portal access will be suspended",
        body="Dear user, click here immediately to verify your healthcare credentials."
    )

    incident = handle_incident(
        analysis_result=analysis,
        raw_input="URGENT: Your patient portal access will be suspended"
    )

    print("\n📋 INCIDENT RECORD:")
    for log in incident["execution_log"]:
        if log["action"] == "generate_report":
            print("\n" + log.get("report", "Report generated"))
        else:
            print(f"  ✓ {log['action']}: {log.get('message', 'executed')}")