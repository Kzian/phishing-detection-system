"""
PhishGuard AI — FastAPI Backend v2.0
======================================
Added:
  - Auth routes (/auth/register, /auth/login, /auth/me)
  - Hospital staff user management
  - Enhanced email analysis with sender domain layer
  - /my/incidents — personal incident history per logged-in user
  - Incidents now tagged with user email when sender matches a registered user
"""

import os, sys, json, uuid, re
from datetime import datetime
from typing import Optional
from urllib.parse import urlparse
import ipaddress

import requests
from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from backend.scoring.threat_engine     import analyze_email, analyze_sms, analyze_url
from backend.response.incident_handler import handle_incident
from backend.detection.network_features import resolve_network_features
from backend.models.user               import init_db, get_db, User
from backend.api.auth                  import router as auth_router, get_current_user

# ── Trusted Nigerian institutional TLDs ───────────────────────────────────────
# NiRA-registered domains — RDAP unavailable but institutionally trusted
TRUSTED_NG_TLDS = {".edu.ng", ".gov.ng", ".org.ng", ".mil.ng", ".ac.ng"}

app = FastAPI(
    title="PhishGuard AI",
    description="AI-powered phishing detection and automated incident response for healthcare environments",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register auth routes
app.include_router(auth_router)

INCIDENTS_PATH  = os.path.join(BASE_DIR, "data", "incidents.json")
N8N_WEBHOOK_URL = os.getenv("N8N_WEBHOOK_URL", "")


# ═══════════════════════════════════════════════════════════════════════════════
# STARTUP
# ═══════════════════════════════════════════════════════════════════════════════

@app.on_event("startup")
def startup():
    init_db()
    print("✅ PhishGuard AI v2.0 — database initialised")


# ═══════════════════════════════════════════════════════════════════════════════
# SCHEMAS
# ═══════════════════════════════════════════════════════════════════════════════

class URLRequest(BaseModel):
    url: str = Field(..., json_schema_extra={"example": "http://paypal-secure-login.xyz/verify"})

class EmailRequest(BaseModel):
    subject:      str
    body:         str
    sender:       Optional[str] = None   # full sender email e.g. admin@nhis.gov.ng
    recipient:    Optional[str] = None   # registered staff email (for attribution)

class SMSRequest(BaseModel):
    message:       str
    sender_number: Optional[str] = None
    recipient:     Optional[str] = None  # registered staff email


# ═══════════════════════════════════════════════════════════════════════════════
# LEXICAL FEATURE EXTRACTOR (97 features)
# ═══════════════════════════════════════════════════════════════════════════════

_SPECIAL = {
    "dot":".", "hyphen":"-", "underline":"_", "slash":"/",
    "questionmark":"?", "equal":"=", "at":"@", "and":"&",
    "exclamation":"!", "space":" ", "tilde":"~", "comma":",",
    "plus":"+", "asterisk":"*", "hashtag":"#", "dollar":"$", "percent":"%",
}

def _cnt(text, char):  return text.count(char) if text else 0
def _cnt_vowels(text): return sum(c in "aeiou" for c in text.lower()) if text else 0
def _is_ip(h):
    try:    ipaddress.ip_address(h); return 1
    except: return 0

def extract_lexical_features(url: str) -> dict:
    parsed   = urlparse(url)
    full_url = url
    domain   = parsed.hostname or ""
    path     = parsed.path or ""
    query    = parsed.query or ""
    tld      = domain.split(".")[-1] if "." in domain else ""
    dir_part  = path.rsplit("/",1)[0]+"/" if "/" in path else ""
    file_part = path.rsplit("/",1)[1]     if "/" in path else path
    f = {}
    for name, char in _SPECIAL.items(): f[f"qty_{name}_url"] = _cnt(full_url, char)
    f["qty_tld_url"] = len(tld);  f["length_url"] = len(full_url)
    for name, char in _SPECIAL.items(): f[f"qty_{name}_domain"] = _cnt(domain, char)
    f["qty_vowels_domain"]=_cnt_vowels(domain); f["domain_length"]=len(domain)
    f["domain_in_ip"]=_is_ip(domain)
    f["server_client_domain"]=int("server" in domain.lower() or "client" in domain.lower())
    for name, char in _SPECIAL.items(): f[f"qty_{name}_directory"] = _cnt(dir_part, char)
    f["directory_length"] = len(dir_part)
    for name, char in _SPECIAL.items(): f[f"qty_{name}_file"] = _cnt(file_part, char)
    f["file_length"] = len(file_part)
    for name, char in _SPECIAL.items(): f[f"qty_{name}_params"] = _cnt(query, char)
    f["params_length"]=len(query)
    f["tld_present_params"]=int(any(f".{t}" in query for t in ["com","org","net","xyz","tk","ml"]))
    f["qty_params"]=len(query.split("&")) if query else 0
    f["email_in_url"]=int(bool(re.search(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", full_url)))
    return f

def build_full_feature_vector(url: str) -> dict:
    import pickle
    model_path = os.path.join(BASE_DIR, "data", "saved_models", "url_detector.pkl")
    with open(model_path, "rb") as fh:
        model = pickle.load(fh)
    hostname = urlparse(url).hostname or ""
    lexical  = extract_lexical_features(url)
    network  = resolve_network_features(url, hostname)
    combined = {**lexical, **network}
    return {col: combined[col] for col in model.feature_names_in_}


# ═══════════════════════════════════════════════════════════════════════════════
# ENHANCED EMAIL ANALYSIS — 3-layer detection
# ═══════════════════════════════════════════════════════════════════════════════

def _sender_domain_score(sender_email: str) -> tuple[float, str]:
    """
    Layer 2: Sender domain reputation.
    Returns (adjustment, reason) where adjustment modifies the base content score.
    Negative adjustment = more legitimate. Positive = more suspicious.
    """
    if not sender_email or "@" not in sender_email:
        return 0.0, "no_sender"

    domain = sender_email.split("@")[-1].lower()

    # Nigerian institutional TLDs — RDAP unavailable but institutionally trusted
    for tld in TRUSTED_NG_TLDS:
        if domain.endswith(tld):
            return -0.15, f"trusted_ng_tld:{tld}"

    # Global trusted TLDs
    trusted_global = {".edu", ".gov", ".mil", ".ac.uk", ".nhs.uk"}
    for tld in trusted_global:
        if domain.endswith(tld):
            return -0.10, f"trusted_global_tld:{tld}"

    # Suspicious TLDs
    suspicious = {".xyz", ".tk", ".ml", ".ga", ".cf", ".click",
                  ".top", ".work", ".date", ".loan", ".win", ".online"}
    for tld in suspicious:
        if domain.endswith(tld):
            return +0.15, f"suspicious_tld:{tld}"

    return 0.0, "neutral_domain"


def _spf_check_sender(sender_email: str) -> tuple[float, str]:
    """
    Layer 3: SPF record check on sender domain.
    No SPF + claims to be institutional = likely spoofing.
    """
    if not sender_email or "@" not in sender_email:
        return 0.0, "no_sender"

    domain = sender_email.split("@")[-1].lower()

    try:
        import dns.resolver
        txt_records = dns.resolver.resolve(domain, "TXT", lifetime=3)
        for rdata in txt_records:
            if "v=spf1" in rdata.to_text().lower():
                return -0.05, "spf_present"
        return +0.05, "no_spf_record"
    except Exception:
        return 0.0, "spf_unresolvable"


def analyze_email_enhanced(subject: str, body: str, sender: str = None) -> dict:
    """
    3-layer email analysis:
      Layer 1 — NLP content (TF-IDF + Logistic Regression)
      Layer 2 — Sender domain reputation (.gov.ng trusted, .xyz suspicious)
      Layer 3 — SPF record validation
    """
    # Layer 1 — base content score
    result = analyze_email(subject, body)
    base_score = result.get("threat_score", 0.5)

    # Layers 2 & 3 — sender-based adjustments
    domain_adj, domain_reason = _sender_domain_score(sender)
    spf_adj,    spf_reason    = _spf_check_sender(sender)

    total_adj   = domain_adj + spf_adj
    final_score = max(0.0, min(1.0, base_score + total_adj))

    # Recalculate severity
    if final_score < 0.3:   severity = "CLEAN"
    elif final_score < 0.5: severity = "LOW"
    elif final_score < 0.7: severity = "MEDIUM"
    elif final_score < 0.85:severity = "HIGH"
    else:                    severity = "CRITICAL"

    result["threat_score"] = round(final_score, 4)
    result["severity"]     = severity
    result["confidence"]   = f"{round(final_score * 100, 1)}%"
    result["sender_analysis"] = {
        "domain_adjustment": domain_adj,
        "domain_reason":     domain_reason,
        "spf_adjustment":    spf_adj,
        "spf_reason":        spf_reason,
        "base_content_score": round(base_score, 4),
    }
    return result


# ═══════════════════════════════════════════════════════════════════════════════
# INCIDENT HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def _load_incidents():
    if not os.path.exists(INCIDENTS_PATH): return []
    with open(INCIDENTS_PATH) as f: return json.load(f)

def _save_incident(record):
    incidents = _load_incidents()
    incidents.append(record)
    os.makedirs(os.path.dirname(INCIDENTS_PATH), exist_ok=True)
    with open(INCIDENTS_PATH, "w") as f: json.dump(incidents, f, indent=2)

def _notify_n8n(record):
    if not N8N_WEBHOOK_URL: return
    try: requests.post(N8N_WEBHOOK_URL, json=record, timeout=5)
    except: pass

def _build_response(result, metadata=None, user_email=None):
    record = {
        "incident_id": str(uuid.uuid4())[:8].upper(),
        "timestamp":   datetime.utcnow().isoformat() + "Z",
        "metadata":    metadata or {},
        "user_email":  user_email,
        **result,
    }
    _save_incident(record)
    _notify_n8n(record)
    return record


# ═══════════════════════════════════════════════════════════════════════════════
# ROUTES
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/health", tags=["System"])
def health_check():
    model_dir = os.path.join(BASE_DIR, "data", "saved_models")
    models = {k: os.path.exists(os.path.join(model_dir, f"{k}_detector.pkl"))
              for k in ("url","email","sms")}
    return {
        "status":    "healthy" if all(models.values()) else "degraded",
        "models":    models,
        "version":   "2.0.0",
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


@app.post("/analyze/url", tags=["Detection"])
def analyze_url_endpoint(
    request: URLRequest,
    current_user: User = Depends(get_current_user),
):
    """109 features — 97 lexical + 12 network (RDAP, ipinfo.io, DNS)."""
    try:
        features = build_full_feature_vector(request.url)
        result   = analyze_url(features)
        parsed   = urlparse(request.url)
        record = _build_response(result, {
            "raw_url":  request.url,
            "hostname": parsed.hostname or "",
             "is_https": int(parsed.scheme == "https"),
}, user_email=current_user.email)
        return record
    except Exception as e:
        raise HTTPException(500, str(e))


@app.post("/analyze/email", tags=["Detection"])
def analyze_email_endpoint(
    request: EmailRequest,
    current_user: User = Depends(get_current_user),
):
    """
    3-layer email analysis: NLP content + sender domain reputation + SPF check.
    Sender emails from .gov.ng / .edu.ng / .org.ng receive trust adjustment.
    """
    try:
        result = analyze_email_enhanced(request.subject, request.body, request.sender)
        record = _build_response(result, {
            "sender":    request.sender or "unknown",
            "subject":   request.subject,
            "recipient": request.recipient or current_user.email,
        }, user_email=request.recipient or current_user.email)
        return record
    except Exception as e:
        raise HTTPException(500, str(e))


@app.post("/analyze/sms", tags=["Detection"])
def analyze_sms_endpoint(
    request: SMSRequest,
    current_user: User = Depends(get_current_user),
):
    try:
        result = analyze_sms(request.message)
        record = _build_response(result, {
            "sender_number": request.sender_number or "unknown",
            "recipient":     request.recipient or current_user.email,
        }, user_email=request.recipient or current_user.email)
        return record
    except Exception as e:
        raise HTTPException(500, str(e))


# ── Incidents ─────────────────────────────────────────────────────────────────

@app.get("/incidents", tags=["Incidents"])
def get_all_incidents(
    severity:     Optional[str] = None,
    input_type:   Optional[str] = None,
    limit:        int = 50,
    current_user: User = Depends(get_current_user),
):
    incidents = _load_incidents()
    if current_user.role not in ("it", "admin"):
        incidents = [
            i for i in incidents
            if i.get("user_email") == current_user.email
            or i.get("metadata", {}).get("recipient") == current_user.email
        ]
    if severity:   incidents = [i for i in incidents if i.get("severity")   == severity.upper()]
    if input_type: incidents = [i for i in incidents if i.get("input_type") == input_type.lower()]
    incidents = sorted(incidents, key=lambda x: x.get("timestamp",""), reverse=True)
    return {"total": len(incidents), "incidents": incidents[:limit]}


@app.get("/incidents/stats/summary", tags=["Incidents"])
def get_incident_stats():
    incidents = _load_incidents()
    if not incidents:
        return {"total":0,"by_severity":{},"by_type":{},"avg_threat_score":0,"critical_count":0}
    by_severity, by_type, scores = {}, {}, []
    for inc in incidents:
        by_severity[inc.get("severity","UNKNOWN")] = by_severity.get(inc.get("severity","UNKNOWN"),0)+1
        by_type[inc.get("input_type","unknown")]   = by_type.get(inc.get("input_type","unknown"),0)+1
        scores.append(inc.get("threat_score",0))
    return {
        "total":            len(incidents),
        "by_severity":      by_severity,
        "by_type":          by_type,
        "avg_threat_score": round(sum(scores)/len(scores),4),
        "critical_count":   by_severity.get("CRITICAL",0),
    }


@app.get("/my/incidents", tags=["Incidents"])
def my_incidents(
    current_user: User = Depends(get_current_user),
    limit: int = 50,
):
    """Return incidents attributed to the logged-in user's email."""
    incidents = _load_incidents()
    mine = [i for i in incidents if i.get("user_email") == current_user.email
            or i.get("metadata",{}).get("recipient") == current_user.email]
    mine = sorted(mine, key=lambda x: x.get("timestamp",""), reverse=True)
    return {"total": len(mine), "user": current_user.email, "incidents": mine[:limit]}


@app.get("/incidents/{incident_id}", tags=["Incidents"])
def get_incident(incident_id: str):
    for inc in _load_incidents():
        if inc.get("incident_id") == incident_id.upper():
            return inc
    raise HTTPException(404, f"Incident {incident_id} not found.")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)


# ═══════════════════════════════════════════════════════════════════════════════
# ADMIN ROUTES
# ═══════════════════════════════════════════════════════════════════════════════

def _require_admin(current_user: User = Depends(get_current_user)):
    """Only IT and admin roles can access admin routes."""
    if current_user.role not in ("it", "admin"):
        raise HTTPException(
            status_code=403,
            detail="Access denied — admin or IT role required."
        )
    return current_user


@app.get("/admin/stats", tags=["Admin"])
def admin_stats(current_user: User = Depends(_require_admin)):
    """Per-staff incident breakdown for admin overview panel."""
    incidents = _load_incidents()
    db        = next(get_db())
    users     = db.query(User).all()
    db.close()

    staff_map = {u.email: {"name": u.name, "role": u.role, "email": u.email,
                       "department": u.department, "count": 0,
                       "critical": 0, "highest": "CLEAN"}
             for u in users}

    severity_rank = {"CLEAN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

    for inc in incidents:
        email = inc.get("user_email") or inc.get("metadata", {}).get("recipient")
        if email and email in staff_map:
            staff_map[email]["count"] += 1
            if inc.get("severity") == "CRITICAL":
                staff_map[email]["critical"] += 1
            current_high  = staff_map[email]["highest"]
            incident_sev  = inc.get("severity", "CLEAN")
            if severity_rank.get(incident_sev, 0) > severity_rank.get(current_high, 0):
                staff_map[email]["highest"] = incident_sev

    return {
        "total_incidents": len(incidents),
        "total_staff":     len(users),
        "staff_breakdown": list(staff_map.values()),
    }


@app.patch("/incidents/{incident_id}/action", tags=["Admin"])
def admin_action(
    incident_id: str,
    payload: dict,
    current_user: User = Depends(_require_admin),
):
    """
    Admin takes manual action on an incident.
    payload: { "action": "blocked" | "cleared" | "escalated", "note": "..." }
    """
    incidents = _load_incidents()
    for inc in incidents:
        if inc.get("incident_id") == incident_id.upper():
            inc["admin_action"]  = payload.get("action")
            inc["admin_note"]    = payload.get("note", "")
            inc["actioned_by"]   = current_user.email
            inc["actioned_at"]   = datetime.utcnow().isoformat() + "Z"
            with open(INCIDENTS_PATH, "w") as f:
                json.dump(incidents, f, indent=2)
            return {"status": "updated", "incident_id": incident_id, **payload}
    raise HTTPException(404, f"Incident {incident_id} not found.")


@app.get("/incidents/{incident_id}/report", tags=["Admin"],
         response_model=None)
def incident_report(incident_id: str, token: Optional[str] = None):
    """Generate incident report — accepts JWT as query param for browser downloads."""
    from backend.api.auth import SECRET_KEY, ALGORITHM
    from jose import jwt, JWTError
    from backend.models.user import Session as DBSession

    if not token:
        raise HTTPException(401, "Not authenticated")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email   = payload.get("sub")
        db      = DBSession()
        current_user = db.query(User).filter(User.email == email).first()
        db.close()
    except JWTError:
        raise HTTPException(401, "Invalid token")

    if not current_user or current_user.role not in ("it", "admin"):
        raise HTTPException(403, "Admin access required")

    for inc in _load_incidents():
        if inc.get("incident_id") == incident_id.upper():
            meta    = inc.get("metadata", {})
            actions = ", ".join(inc.get("actions", []))
            report  = f"""PHISHGUARD AI — INCIDENT REPORT
================================
Incident ID   : {inc.get('incident_id')}
Date / Time   : {inc.get('timestamp','').replace('T',' ').replace('Z',' UTC')}
Generated by  : {current_user.name} ({current_user.role})

THREAT SUMMARY
--------------
Severity      : {inc.get('severity')}
Threat Score  : {inc.get('confidence')}
Prediction    : {inc.get('prediction')}
Channel       : {inc.get('input_type')}
Staff account : {inc.get('user_email', 'unattributed')}

METADATA
--------
Sender        : {meta.get('sender', meta.get('sender_number', 'N/A'))}
Subject       : {meta.get('subject', 'N/A')}
Raw URL       : {meta.get('raw_url', 'N/A')}
Recipient     : {meta.get('recipient', 'N/A')}

AUTOMATED ACTIONS TAKEN
-----------------------
{actions}

ADMIN REVIEW
------------
Action taken  : {inc.get('admin_action', 'Pending review')}
Actioned by   : {inc.get('actioned_by', 'N/A')}
Actioned at   : {inc.get('actioned_at', 'N/A')}
Note          : {inc.get('admin_note', 'N/A')}

RECOMMENDATION
--------------
{"Block sender domain and notify affected staff immediately." if inc.get('severity') in ("CRITICAL","HIGH") else "Monitor for repeated activity from this source."}

--
PhishGuard AI v2.0 | MSc Cybersecurity Research | FUTO""".strip()

            from fastapi.responses import PlainTextResponse
            return PlainTextResponse(
                content=report,
                headers={
                    "Content-Disposition":
                        f"attachment; filename=incident_{incident_id}.txt"
                }
            )
    raise HTTPException(404, f"Incident {incident_id} not found.")

# ═══════════════════════════════════════════════════════════════════════════════
# AGENTMAIL WEBHOOK
# ═══════════════════════════════════════════════════════════════════════════════

@app.post("/webhook/agentmail", tags=["Webhooks"], response_model=None)
async def agentmail_webhook(payload: dict):
    """
    Receives email events from AgentMail.
    Extracts email content, identifies staff recipient,
    runs 3-layer analysis, auto-suspends on CRITICAL.
    """
    try:
        # Only process message.received events
        if payload.get("event_type") != "message.received":
            return {"status": "ignored", "reason": "not a message event"}

        msg       = payload.get("message", {})
        subject   = msg.get("subject", "")
        body      = msg.get("text", "") or msg.get("extracted_text", "")
        sender    = msg.get("from", "") or msg.get("from_", "")
        inbox_id  = msg.get("inbox_id", "")  # which staff inbox received it

        # Extract plain email from "Name <email>" format
        import re
        sender_email = ""
        match = re.search(r'<([^>]+)>', sender)
        if match:
            sender_email = match.group(1)
        else:
            sender_email = sender.strip()

        # Find registered staff member by inbox_id
        db   = next(get_db())
        user = db.query(User).filter(User.email == inbox_id).first()
        db.close()

        staff_email = user.email if user else inbox_id
        staff_name  = user.name  if user else "Unknown"

        # Run 3-layer email analysis
        result = analyze_email_enhanced(subject, body, sender_email)

        # Build incident record
        record = _build_response(result, {
            "sender":    sender_email,
            "subject":   subject,
            "recipient": staff_email,
            "channel":   "agentmail_auto",
        }, user_email=staff_email)

        severity = result.get("severity", "CLEAN")

        # Auto-suspend staff account on CRITICAL — automated monitoring only
        if severity == "CRITICAL" and user:
            db = next(get_db())
            target = db.query(User).filter(User.email == staff_email).first()
            if target:
                target.is_suspended = True
                db.commit()
                print(f"🔒 Auto-suspended {staff_name} ({staff_email}) — CRITICAL threat")
            db.close()

        # Notify n8n for downstream alerting
        _notify_n8n({
            **record,
            "staff_name":  staff_name,
            "staff_email": staff_email,
            "auto_scanned": True,
        })

        print(f"✅ AgentMail: {subject[:40]} | {severity} | {staff_email}")
        return {"status": "processed", "incident_id": record["incident_id"],
                "severity": severity, "staff": staff_email}

    except Exception as e:
        print(f"❌ AgentMail webhook error: {e}")
        raise HTTPException(500, str(e))


@app.patch("/admin/users/{email}/restore", tags=["Admin"], response_model=None)
def restore_user(
    email: str,
    current_user: User = Depends(_require_admin),
):
    """Admin restores a suspended staff account."""
    db   = next(get_db())
    user = db.query(User).filter(User.email == email).first()
    if not user:
        db.close()
        raise HTTPException(404, "User not found")
    user.is_suspended = False
    db.commit()
    db.close()
    return {"status": "restored", "email": email, "name": user.name}
