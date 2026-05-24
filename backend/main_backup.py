"""
PhishGuard AI — FastAPI Backend v1.2
======================================
Network features now properly resolved via:
  - RDAP           → domain age + expiration (free, no key)
  - ipinfo.io      → ASN number (free, 50k/month, no key)
  - HTTP HEAD      → response time (seconds) + redirect count
  - dnspython      → SPF, NS, MX, TTL
  - socket         → IP count
  Dropped: url_google_index, domain_google_index (rank 84/89, ~0.01% importance)
"""

import os, sys, json, uuid, re
from datetime import datetime
from typing import Optional
from urllib.parse import urlparse
import ipaddress

import requests
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from backend.scoring.threat_engine   import analyze_email, analyze_sms, analyze_url
from backend.response.incident_handler import handle_incident
from backend.detection.network_features import resolve_network_features

app = FastAPI(
    title="PhishGuard AI",
    description="AI-powered phishing detection and automated incident response for healthcare environments",
    version="1.2.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

INCIDENTS_PATH  = os.path.join(BASE_DIR, "data", "incidents.json")
N8N_WEBHOOK_URL = os.getenv("N8N_WEBHOOK_URL", "")


# ═══════════════════════════════════════════════════════════════════════════════
# SCHEMAS
# ═══════════════════════════════════════════════════════════════════════════════

class URLRequest(BaseModel):
    url: str = Field(..., json_schema_extra={"example": "http://paypal-secure-login.xyz/verify"})

class EmailRequest(BaseModel):
    subject: str
    body:    str
    sender:  Optional[str] = None

class SMSRequest(BaseModel):
    message:       str
    sender_number: Optional[str] = None


# ═══════════════════════════════════════════════════════════════════════════════
# LEXICAL FEATURE EXTRACTOR  (97 pure URL-string features)
# ═══════════════════════════════════════════════════════════════════════════════

_SPECIAL = {
    "dot": ".", "hyphen": "-", "underline": "_", "slash": "/",
    "questionmark": "?", "equal": "=", "at": "@", "and": "&",
    "exclamation": "!", "space": " ", "tilde": "~", "comma": ",",
    "plus": "+", "asterisk": "*", "hashtag": "#", "dollar": "$",
    "percent": "%",
}

def _cnt(text, char):       return text.count(char) if text else 0
def _cnt_vowels(text):      return sum(c in "aeiou" for c in text.lower()) if text else 0
def _is_ip(hostname):
    try:    ipaddress.ip_address(hostname); return 1
    except: return 0


def extract_lexical_features(url: str) -> dict:
    """Extract 97 lexical/structural features from a raw URL string."""
    parsed   = urlparse(url)
    full_url = url
    domain   = parsed.hostname or ""
    path     = parsed.path or ""
    query    = parsed.query or ""
    tld      = domain.split(".")[-1] if "." in domain else ""

    if "/" in path:
        dir_part  = path.rsplit("/", 1)[0] + "/"
        file_part = path.rsplit("/", 1)[1]
    else:
        dir_part  = ""
        file_part = path

    f = {}

    # URL-level (19)
    for name, char in _SPECIAL.items():
        f[f"qty_{name}_url"] = _cnt(full_url, char)
    f["qty_tld_url"] = len(tld)
    f["length_url"]  = len(full_url)

    # Domain-level (21)
    for name, char in _SPECIAL.items():
        f[f"qty_{name}_domain"] = _cnt(domain, char)
    f["qty_vowels_domain"]    = _cnt_vowels(domain)
    f["domain_length"]        = len(domain)
    f["domain_in_ip"]         = _is_ip(domain)
    f["server_client_domain"] = int(
        "server" in domain.lower() or "client" in domain.lower()
    )

    # Directory-level (18)
    for name, char in _SPECIAL.items():
        f[f"qty_{name}_directory"] = _cnt(dir_part, char)
    f["directory_length"] = len(dir_part)

    # File-level (18)
    for name, char in _SPECIAL.items():
        f[f"qty_{name}_file"] = _cnt(file_part, char)
    f["file_length"] = len(file_part)

    # Params-level (20)
    for name, char in _SPECIAL.items():
        f[f"qty_{name}_params"] = _cnt(query, char)
    f["params_length"]      = len(query)
    f["tld_present_params"] = int(
        any(f".{t}" in query for t in ["com","org","net","xyz","tk","ml"])
    )
    f["qty_params"] = len(query.split("&")) if query else 0

    # Email-in-URL (1)
    f["email_in_url"] = int(bool(
        re.search(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", full_url)
    ))

    return f  # 97 keys


def build_full_feature_vector(url: str) -> dict:
    """
    Combine lexical features (97) with network features (12) = 109 features.
    Enforces model column order before returning.
    """
    import pickle
    model_path = os.path.join(BASE_DIR, "data", "saved_models", "url_detector.pkl")
    with open(model_path, "rb") as fh:
        model = pickle.load(fh)

    parsed   = urlparse(url)
    hostname = parsed.hostname or ""

    lexical  = extract_lexical_features(url)
    network  = resolve_network_features(url, hostname)

    combined = {**lexical, **network}

    # Reorder to match training column order exactly
    ordered = {col: combined[col] for col in model.feature_names_in_}
    return ordered


# ═══════════════════════════════════════════════════════════════════════════════
# INCIDENT HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def _load_incidents():
    if not os.path.exists(INCIDENTS_PATH):
        return []
    with open(INCIDENTS_PATH) as f:
        return json.load(f)

def _save_incident(record):
    incidents = _load_incidents()
    incidents.append(record)
    os.makedirs(os.path.dirname(INCIDENTS_PATH), exist_ok=True)
    with open(INCIDENTS_PATH, "w") as f:
        json.dump(incidents, f, indent=2)

def _notify_n8n(record):
    if not N8N_WEBHOOK_URL:
        return
    try:
        requests.post(N8N_WEBHOOK_URL, json=record, timeout=5)
    except Exception:
        pass

def _build_response(result, metadata=None):
    record = {
        "incident_id": str(uuid.uuid4())[:8].upper(),
        "timestamp":   datetime.utcnow().isoformat() + "Z",
        "metadata":    metadata or {},
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
              for k in ("url", "email", "sms")}
    return {
        "status":    "healthy" if all(models.values()) else "degraded",
        "models":    models,
        "version":   "1.2.0",
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


@app.post("/analyze/url", tags=["Detection"])
def analyze_url_endpoint(request: URLRequest):
    """
    Analyze a URL using 109 features (97 lexical + 12 network).
    Network lookups: RDAP (domain age), ipinfo.io (ASN), HTTP HEAD (timing).
    Expect 2-5s response time per unique domain (first call per session).
    """
    try:
        features = build_full_feature_vector(request.url)
        result   = analyze_url(features)
        parsed   = urlparse(request.url)
        record   = _build_response(result, {
            "raw_url":    request.url,
            "hostname":   parsed.hostname or "",
            "is_https":   int(parsed.scheme == "https"),
        })
        return record
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/analyze/email", tags=["Detection"])
def analyze_email_endpoint(request: EmailRequest):
    try:
        result = analyze_email(request.subject, request.body)
        record = _build_response(result, {
            "sender":  request.sender or "unknown",
            "subject": request.subject,
        })
        return record
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/analyze/sms", tags=["Detection"])
def analyze_sms_endpoint(request: SMSRequest):
    try:
        result = analyze_sms(request.message)
        record = _build_response(result, {
            "sender_number": request.sender_number or "unknown"
        })
        return record
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/incidents", tags=["Incidents"])
def get_all_incidents(
    severity:   Optional[str] = None,
    input_type: Optional[str] = None,
    limit: int = 50,
):
    incidents = _load_incidents()
    if severity:
        incidents = [i for i in incidents if i.get("severity") == severity.upper()]
    if input_type:
        incidents = [i for i in incidents if i.get("input_type") == input_type.lower()]
    incidents = sorted(incidents, key=lambda x: x.get("timestamp",""), reverse=True)
    return {"total": len(incidents), "incidents": incidents[:limit]}


@app.get("/incidents/stats/summary", tags=["Incidents"])
def get_incident_stats():
    incidents = _load_incidents()
    if not incidents:
        return {"total": 0, "by_severity": {}, "by_type": {}, "avg_threat_score": 0, "critical_count": 0}
    by_severity, by_type, scores = {}, {}, []
    for inc in incidents:
        sev = inc.get("severity", "UNKNOWN")
        typ = inc.get("input_type", "unknown")
        by_severity[sev] = by_severity.get(sev, 0) + 1
        by_type[typ]     = by_type.get(typ, 0) + 1
        scores.append(inc.get("threat_score", 0))
    return {
        "total":            len(incidents),
        "by_severity":      by_severity,
        "by_type":          by_type,
        "avg_threat_score": round(sum(scores) / len(scores), 4),
        "critical_count":   by_severity.get("CRITICAL", 0),
    }


@app.get("/incidents/{incident_id}", tags=["Incidents"])
def get_incident(incident_id: str):
    for inc in _load_incidents():
        if inc.get("incident_id") == incident_id.upper():
            return inc
    raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found.")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)
