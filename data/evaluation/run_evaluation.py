"""
PhishGuard AI — Phase 8 Formal Evaluation
==========================================
Runs all four experiments and generates results tables.
"""

import sys, os, json, time, pickle
import pandas as pd
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

from backend.detection.network_features import resolve_network_features
from backend.scoring.threat_engine import analyze_email, analyze_sms, analyze_url
from backend.response.incident_handler import handle_incident

# ── Load models once ──────────────────────────────────────────────────────────
print("Loading models...")
with open("data/saved_models/url_detector.pkl",   "rb") as f: url_model   = pickle.load(f)
with open("data/saved_models/email_detector.pkl", "rb") as f: email_model = pickle.load(f)
with open("data/saved_models/sms_detector.pkl",   "rb") as f: sms_model   = pickle.load(f)
print("✅ All models loaded\n")


# ═══════════════════════════════════════════════════════════════════════════════
# EXPERIMENT 2 — DETECTION ACCURACY ON KNOWN SAMPLES
# ═══════════════════════════════════════════════════════════════════════════════

# Known phishing URLs (from PhishTank + common patterns)
PHISHING_URLS = [
    "http://paypal-secure-login.xyz/verify",
    "http://nhis-account-verify.tk/login",
    "http://amazon-prize-winner.ml/claim",
    "http://bankofafrica-secure.cf/update",
    "http://apple-id-suspended.xyz/unlock",
    "http://microsoft-alert-security.tk/verify",
    "http://gmail-account-recovery.ml/reset",
    "http://hospital-staff-verify.xyz/login",
    "http://nhis-gov-ng-verify.tk/staff",
    "http://secure-banking-update.cf/confirm",
]

# Known legitimate URLs
LEGITIMATE_URLS = [
    "https://www.google.com",
    "https://web.facebook.com",
    "https://www.microsoft.com",
    "https://unn.edu.ng",
    "https://www.ui.edu.ng",
    "https://nhis.gov.ng",
    "https://www.futo.edu.ng",
    "https://www.firstbanknigeria.com",
    "https://www.gtbank.com",
    "https://www.who.int",
]

# Known phishing emails
PHISHING_EMAILS = [
    {
        "subject": "URGENT: Your NHIS account will be suspended",
        "body": "Click here immediately to verify your credentials or lose access to patient records: http://nhis-verify.xyz/login",
        "sender": "noreply@nhis-alert.xyz",
        "label": "phishing"
    },
    {
        "subject": "Your hospital account password has expired",
        "body": "Dear Doctor, your password expired. Reset now at http://hospital-reset.tk/password to avoid losing access.",
        "sender": "admin@hospital-security.ml",
        "label": "phishing"
    },
    {
        "subject": "FREE COVID-19 Palliative — Claim Now",
        "body": "The Federal Government is giving free palliatives. Click here to claim yours before it expires: http://palliative-claim.xyz",
        "sender": "fg-palliative@gov-ng.tk",
        "label": "phishing"
    },
    {
        "subject": "Verify your GTBank account immediately",
        "body": "Your GTBank account has been flagged. Verify at http://gtbank-secure.cf/verify or your account will be frozen.",
        "sender": "security@gtbank-alert.ml",
        "label": "phishing"
    },
    {
        "subject": "Your NIN has been deactivated",
        "body": "NIMC has deactivated your NIN due to inactivity. Reactivate now: http://nimc-verify.xyz/nin",
        "sender": "nimc-alert@nin-verify.tk",
        "label": "phishing"
    },
]

# Known legitimate emails
LEGITIMATE_EMAILS = [
    {
        "subject": "Staff Meeting — Friday 10am",
        "body": "Dear team, please be reminded of the staff meeting scheduled for Friday at 10am in the boardroom. Attendance is compulsory.",
        "sender": "admin@lagoshospital.gov.ng",
        "label": "legitimate"
    },
    {
        "subject": "Patient Appointment Confirmation",
        "body": "Your appointment with Dr. Okafor has been confirmed for Monday 25th May at 2pm. Please arrive 15 minutes early.",
        "sender": "appointments@unn.edu.ng",
        "label": "legitimate"
    },
    {
        "subject": "NHIS Monthly Bulletin — May 2026",
        "body": "Dear healthcare provider, please find attached the NHIS monthly bulletin for May 2026 containing updates to the drug formulary.",
        "sender": "bulletin@nhis.gov.ng",
        "label": "legitimate"
    },
    {
        "subject": "Payslip for April 2026",
        "body": "Dear staff member, your payslip for April 2026 is now available on the staff portal. Log in with your staff ID to access it.",
        "sender": "payroll@hospital.gov.ng",
        "label": "legitimate"
    },
    {
        "subject": "Annual Leave Approval",
        "body": "Your annual leave request for 10th-17th June 2026 has been approved. Please ensure handover notes are completed before departure.",
        "sender": "hr@lagoshospital.gov.ng",
        "label": "legitimate"
    },
]

# Known phishing SMS
PHISHING_SMS = [
    {"text": "URGENT: Your BVN has been deactivated. Call 0800-VERIFY or click http://bvn-verify.xyz now", "label": "phishing"},
    {"text": "You have won N500,000 in the MTN promo. Claim at http://mtn-promo.tk/claim before midnight", "label": "phishing"},
    {"text": "Your GTBank account is blocked. Unblock now: http://gtbank-unblock.ml/verify", "label": "phishing"},
    {"text": "FG Palliative: You qualify for N30,000 relief. Click http://fg-palliative.xyz to claim", "label": "phishing"},
    {"text": "NHIS: Your hospital access card expires today. Renew: http://nhis-renew.tk/card", "label": "phishing"},
]

# Known legitimate SMS
LEGITIMATE_SMS = [
    {"text": "Your OTP for GTBank login is 482910. Valid for 5 minutes. Do not share.", "label": "legitimate"},
    {"text": "Reminder: Your appointment with Dr. Okafor is tomorrow at 2pm. Reply CANCEL to cancel.", "label": "legitimate"},
    {"text": "Your MTN airtime recharge of N1000 was successful. Balance: N1,247.50", "label": "legitimate"},
    {"text": "LASG: Your vehicle particulars renewal is due. Visit any MVAA office or lasgov.ng", "label": "legitimate"},
    {"text": "Your UBA transfer of N5,000 to JOHN DOE was successful. Ref: UBA2026052512345", "label": "legitimate"},
]


# ═══════════════════════════════════════════════════════════════════════════════
# HELPER — run one URL through the full pipeline
# ═══════════════════════════════════════════════════════════════════════════════

def test_url(url, expected_label):
    from urllib.parse import urlparse
    import re, ipaddress

    _SPECIAL = {
        "dot":".", "hyphen":"-", "underline":"_", "slash":"/",
        "questionmark":"?", "equal":"=", "at":"@", "and":"&",
        "exclamation":"!", "space":" ", "tilde":"~", "comma":",",
        "plus":"+", "asterisk":"*", "hashtag":"#", "dollar":"$", "percent":"%",
    }

    def _cnt(text, char): return text.count(char) if text else 0
    def _cnt_vowels(text): return sum(c in "aeiou" for c in text.lower()) if text else 0
    def _is_ip(h):
        try: ipaddress.ip_address(h); return 1
        except: return 0

    parsed   = urlparse(url)
    domain   = parsed.hostname or ""
    path     = parsed.path or ""
    query    = parsed.query or ""
    tld      = domain.split(".")[-1] if "." in domain else ""
    dir_part  = path.rsplit("/",1)[0]+"/" if "/" in path else ""
    file_part = path.rsplit("/",1)[1]     if "/" in path else path

    f = {}
    for name, char in _SPECIAL.items(): f[f"qty_{name}_url"] = _cnt(url, char)
    f["qty_tld_url"] = len(tld); f["length_url"] = len(url)
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
    f["email_in_url"]=int(bool(re.search(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", url)))

    try:
        network = resolve_network_features(url, domain)
    except Exception:
        network = {}

    combined = {**f, **network}

    # Fill any missing features with -1 rather than crashing
    ordered = {}
    for col in url_model.feature_names_in_:
        ordered[col] = combined.get(col, -1)

        
    t0     = time.time()
    result = analyze_url(ordered)
    elapsed = (time.time() - t0) * 1000

    predicted = result.get("prediction", "unknown")
    correct   = (predicted == expected_label)

    return {
        "input":     url[:50],
        "expected":  expected_label,
        "predicted": predicted,
        "severity":  result.get("severity"),
        "score":     f"{result.get('threat_score',0)*100:.1f}%",
        "correct":   correct,
        "time_ms":   f"{elapsed:.1f}ms",
    }


def test_email(subject, body, sender, expected_label):
    t0     = time.time()
    result = analyze_email(subject, body)
    elapsed = (time.time() - t0) * 1000

    predicted = result.get("prediction", "unknown")
    correct   = (predicted == expected_label)

    return {
        "input":     subject[:45],
        "expected":  expected_label,
        "predicted": predicted,
        "severity":  result.get("severity"),
        "score":     f"{result.get('threat_score',0)*100:.1f}%",
        "correct":   correct,
        "time_ms":   f"{elapsed:.1f}ms",
    }


def test_sms(text, expected_label):
    t0     = time.time()
    result = analyze_sms(text)
    elapsed = (time.time() - t0) * 1000

    predicted = result.get("prediction", "unknown")
    # SMS model returns "smishing" — normalize to "phishing" for comparison
    pred_normalized = "phishing" if predicted == "smishing" else predicted
    correct   = (pred_normalized == expected_label)

    return {
        "input":     text[:45],
        "expected":  expected_label,
        "predicted": predicted,
        "severity":  result.get("severity"),
        "score":     f"{result.get('threat_score',0)*100:.1f}%",
        "correct":   correct,
        "time_ms":   f"{elapsed:.1f}ms",
    }


# ═══════════════════════════════════════════════════════════════════════════════
# RUN ALL EXPERIMENTS
# ═══════════════════════════════════════════════════════════════════════════════

results = {"url": [], "email": [], "sms": [], "response_time": []}

print("=" * 60)
print("EXPERIMENT 2 — URL DETECTION")
print("=" * 60)
print(f"{'Input':<52} {'Expected':<12} {'Got':<12} {'Score':<8} {'✓'}")
print("-" * 60)

for url in PHISHING_URLS:
    r = test_url(url, "phishing")
    results["url"].append(r)
    print(f"{r['input']:<52} {r['expected']:<12} {r['predicted']:<12} {r['score']:<8} {'✅' if r['correct'] else '❌'}")

for url in LEGITIMATE_URLS:
    r = test_url(url, "legitimate")
    results["url"].append(r)
    print(f"{r['input']:<52} {r['expected']:<12} {r['predicted']:<12} {r['score']:<8} {'✅' if r['correct'] else '❌'}")

url_correct = sum(1 for r in results["url"] if r["correct"])
url_total   = len(results["url"])
url_fp      = sum(1 for r in results["url"] if r["expected"]=="legitimate" and r["predicted"]!="legitimate")
print(f"\nURL Accuracy: {url_correct}/{url_total} = {url_correct/url_total*100:.1f}%")
print(f"False Positive Rate: {url_fp}/{len(LEGITIMATE_URLS)} = {url_fp/len(LEGITIMATE_URLS)*100:.1f}%")


print("\n" + "=" * 60)
print("EXPERIMENT 2 — EMAIL DETECTION")
print("=" * 60)
print(f"{'Subject':<47} {'Expected':<12} {'Got':<12} {'✓'}")
print("-" * 60)

for e in PHISHING_EMAILS + LEGITIMATE_EMAILS:
    r = test_email(e["subject"], e["body"], e["sender"], e["label"])
    results["email"].append(r)
    print(f"{r['input']:<47} {r['expected']:<12} {r['predicted']:<12} {'✅' if r['correct'] else '❌'}")

email_correct = sum(1 for r in results["email"] if r["correct"])
email_total   = len(results["email"])
email_fp      = sum(1 for r in results["email"] if r["expected"]=="legitimate" and r["predicted"]!="legitimate")
print(f"\nEmail Accuracy: {email_correct}/{email_total} = {email_correct/email_total*100:.1f}%")
print(f"False Positive Rate: {email_fp}/{len(LEGITIMATE_EMAILS)} = {email_fp/len(LEGITIMATE_EMAILS)*100:.1f}%")


print("\n" + "=" * 60)
print("EXPERIMENT 2 — SMS DETECTION")
print("=" * 60)
print(f"{'Message':<47} {'Expected':<12} {'Got':<12} {'✓'}")
print("-" * 60)

for s in PHISHING_SMS + LEGITIMATE_SMS:
    r = test_sms(s["text"], s["label"])
    results["sms"].append(r)
    print(f"{r['input']:<47} {r['expected']:<12} {r['predicted']:<12} {'✅' if r['correct'] else '❌'}")

sms_correct = sum(1 for r in results["sms"] if r["correct"])
sms_total   = len(results["sms"])
sms_fp      = sum(1 for r in results["sms"] if r["expected"]=="legitimate" and r["predicted"]!="legitimate")
print(f"\nSMS Accuracy: {sms_correct}/{sms_total} = {sms_correct/sms_total*100:.1f}%")
print(f"False Positive Rate: {sms_fp}/{len(LEGITIMATE_SMS)} = {sms_fp/len(LEGITIMATE_SMS)*100:.1f}%")


print("\n" + "=" * 60)
print("EXPERIMENT 3 — RESPONSE TIME")
print("=" * 60)

times = [float(r["time_ms"].replace("ms","")) for r in
         results["url"] + results["email"] + results["sms"]]
url_times   = [float(r["time_ms"].replace("ms","")) for r in results["url"]]
email_times = [float(r["time_ms"].replace("ms","")) for r in results["email"]]
sms_times   = [float(r["time_ms"].replace("ms","")) for r in results["sms"]]

print(f"URL    — mean: {sum(url_times)/len(url_times):.1f}ms  "
      f"min: {min(url_times):.1f}ms  max: {max(url_times):.1f}ms")
print(f"Email  — mean: {sum(email_times)/len(email_times):.1f}ms  "
      f"min: {min(email_times):.1f}ms  max: {max(email_times):.1f}ms")
print(f"SMS    — mean: {sum(sms_times)/len(sms_times):.1f}ms  "
      f"min: {min(sms_times):.1f}ms  max: {max(sms_times):.1f}ms")
print(f"Overall mean response time: {sum(times)/len(times):.1f}ms")
print(f"Manual review baseline: ~20 minutes (1,200,000ms)")
print(f"Speedup factor: {1200000/(sum(times)/len(times)):.0f}x faster than manual")


print("\n" + "=" * 60)
print("EXPERIMENT 4 — FALSE POSITIVE SUMMARY")
print("=" * 60)
total_legit = len(LEGITIMATE_URLS) + len(LEGITIMATE_EMAILS) + len(LEGITIMATE_SMS)
total_fp    = url_fp + email_fp + sms_fp
print(f"Total legitimate samples tested : {total_legit}")
print(f"Incorrectly flagged (FP)        : {total_fp}")
print(f"Overall False Positive Rate     : {total_fp/total_legit*100:.1f}%")
print(f"URL FPR    : {url_fp}/{len(LEGITIMATE_URLS)} = {url_fp/len(LEGITIMATE_URLS)*100:.1f}%")
print(f"Email FPR  : {email_fp}/{len(LEGITIMATE_EMAILS)} = {email_fp/len(LEGITIMATE_EMAILS)*100:.1f}%")
print(f"SMS FPR    : {sms_fp}/{len(LEGITIMATE_SMS)} = {sms_fp/len(LEGITIMATE_SMS)*100:.1f}%")


print("\n" + "=" * 60)
print("OVERALL SUMMARY")
print("=" * 60)
total_correct = url_correct + email_correct + sms_correct
total_samples = url_total + email_total + sms_total
print(f"Total samples tested : {total_samples}")
print(f"Total correct        : {total_correct}")
print(f"Overall accuracy     : {total_correct/total_samples*100:.1f}%")

# Save results to JSON
output = {
    "generated_at": datetime.utcnow().isoformat(),
    "summary": {
        "url_accuracy":    f"{url_correct/url_total*100:.1f}%",
        "email_accuracy":  f"{email_correct/email_total*100:.1f}%",
        "sms_accuracy":    f"{sms_correct/sms_total*100:.1f}%",
        "overall_accuracy":f"{total_correct/total_samples*100:.1f}%",
        "url_fpr":         f"{url_fp/len(LEGITIMATE_URLS)*100:.1f}%",
        "email_fpr":       f"{email_fp/len(LEGITIMATE_EMAILS)*100:.1f}%",
        "sms_fpr":         f"{sms_fp/len(LEGITIMATE_SMS)*100:.1f}%",
        "mean_response_ms":f"{sum(times)/len(times):.1f}",
    },
    "url_results":   results["url"],
    "email_results": results["email"],
    "sms_results":   results["sms"],
}

with open("data/evaluation/results.json", "w") as f:
    json.dump(output, f, indent=2)

print("\n💾 Full results saved to data/evaluation/results.json")
print("📸 Screenshot this output for your thesis Chapter 5")
