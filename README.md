# PhishGuard AI 🛡️

> **Design and Implementation of an AI-Powered Phishing Detection and Automated Incident Response System for Healthcare Environments**

MSc Cybersecurity Research Project — FUTO
Cyb3rry (Cassia Anwar) | [@Kzian](https://github.com/Kzian)

---

## 🧠 Overview

PhishGuard AI is a complete intelligent cybersecurity platform that detects phishing attacks across three channels — URLs, emails, and SMS — and responds automatically. Built specifically for healthcare environments in Nigeria where phishing attacks targeting patient data and clinical systems are a growing threat.

The system combines machine learning, NLP, real-time network feature resolution, automated incident response, role-aware hospital staff portal, and AgentMail-based domain-wide email monitoring into a single deployable platform.

---

## 🏗️ System Architecture

                    ┌──────────────────────────────────────┐
                    │           INPUT CHANNELS             │
                    └───────┬──────────────┬───────────────┘
                            │              │
                ┌───────────▼───┐   ┌──────▼────────────┐
                │ AgentMail     │   │  React Dashboard   │
                │ IMAP Webhook  │   │  Hospital Portal   │
                │ (auto-scan)   │   │  (on-demand)       │
                └───────┬───────┘   └──────┬─────────────┘
                        └──────────┬────────┘
                                   ▼
                    ┌──────────────────────────┐
                    │   FastAPI REST Backend   │
                    │   JWT Auth + SQLite      │
                    │   11 endpoints           │
                    └──────┬───────────────────┘
                           │
          ┌────────────────┼────────────────┐
          ▼                ▼                ▼
   ┌─────────────┐  ┌─────────────┐  ┌─────────────┐
   │URL Detector │  │Email Detect │  │SMS Detector │
   │Rnd Forest   │  │TF-IDF + LR  │  │NLP Classify │
   │109 features │  │3-layer anal │  │thresh=0.35  │
   │97% accuracy │  │99% accuracy │  │95% accuracy │
   └──────┬──────┘  └──────┬──────┘  └──────┬──────┘
          └────────────────┼─────────────────┘
                           ▼
              ┌────────────────────────┐
              │  Threat Scoring Engine │
              │  CLEAN / LOW / MEDIUM  │
              │    HIGH / CRITICAL     │
              └────────────┬───────────┘
                           ▼
              ┌────────────────────────┐
              │    Incident Handler    │
              │  6 automated actions   │
              │  Auto-suspend HIGH+    │
              └────────────┬───────────┘
                           ▼
              ┌────────────────────────┐
              │  n8n Workflow Engine   │
              │  Alerts + Admin Email  │
              └────────────────────────┘

---

## 📊 Model Performance (Experiment 1 — Training Data Evaluation)

### URL Detection
Dataset: GregaVrbancic Phishing Dataset (88,647 URLs, 109 features)
Features: 97 lexical + 12 network (RDAP, ipinfo.io, DNS, HTTP HEAD)

| Class | Precision | Recall | F1-Score | Support |
|---|---|---|---|---|
| Legitimate | 0.98 | 0.98 | 0.98 | 11,600 |
| Phishing | 0.95 | 0.96 | 0.96 | 6,130 |
| **Overall Accuracy** | | | **0.97** | 17,730 |

### Email Detection
Dataset: Kaggle Phishing Email Dataset (82,486 emails — Naser Abdullah Alam)
Model: TF-IDF (8,000 features, bigrams) + Logistic Regression

| Class | Precision | Recall | F1-Score | Support |
|---|---|---|---|---|
| Legitimate | 0.99 | 0.98 | 0.99 | 7,919 |
| Phishing | 0.98 | 0.99 | 0.99 | 8,579 |
| **Overall Accuracy** | | | **0.99** | 16,498 |

### SMS Smishing Detection
Dataset: UCI SMS Spam Collection (5,572 messages)
Model: TF-IDF + Logistic Regression, threshold=0.35

| Class | Precision | Recall | F1-Score | Support |
|---|---|---|---|---|
| Legitimate | 0.94 | 1.00 | 0.97 | 966 |
| Smishing | 1.00 | 0.60 | 0.75 | 149 |
| **Overall Accuracy** | | | **0.95** | 1,115 |

> SMS class imbalance (747 smishing vs 4,825 legitimate) addressed via
> class_weight="balanced" and detection threshold=0.35 — prioritising
> recall since missing a smishing attack carries higher risk than a false positive.

---

## 🧪 Formal Evaluation Results (Phase 8)

### Experiment 2 — Real-World Detection Accuracy (40 samples)

| Channel | Phishing Detected | Legitimate Correct | Accuracy | FPR |
|---|---|---|---|---|
| URL | 10/10 (100%) | 5/10 (50%) | 75% | 50% |
| Email | 4/5 (80%) | 4/5 (80%) | 80% | 20% |
| SMS | 4/5 (80%) | 2/5 (40%) | 60% | 60% |
| **Overall** | **18/20 (90%)** | **11/20 (55%)** | **72.5%** | **45%** |

> URL false positives primarily attributable to Nigerian ccTLD domains
> (.edu.ng, .gov.ng) absent from IANA RDAP registry — documented known
> limitation. See Key Design Decisions below.

### Experiment 3 — Response Time

| Channel | Mean | Min | Max |
|---|---|---|---|
| URL | 210.9ms | 137.3ms | 336.1ms |
| Email | 7.5ms | 5.7ms | 12.1ms |
| SMS | 3.3ms | 2.5ms | 5.2ms |
| **Overall mean** | **108.1ms** | | |

    Manual security review baseline: ~20 minutes (1,200,000ms)
    PhishGuard automated response: 108.1ms mean
    Speedup factor: 11,097x faster than manual review

### Experiment 4 — False Positive Rate Summary

| Channel | FP Count | Total Legitimate | FPR |
|---|---|---|---|
| URL | 5/10 | 10 | 50% |
| Email | 1/5 | 5 | 20% |
| SMS | 3/5 | 5 | 60% |
| **Overall** | **9/20** | **20** | **45%** |

### Experiment 5 — PhishGuard vs ChatGPT (GPT-4) Email Comparison

| Email | Ground Truth | PhishGuard | ChatGPT |
|---|---|---|---|
| URGENT: NHIS account suspended | Phishing | ✅ | ✅ |
| Your NIN has been deactivated | Phishing | ❌ | ✅ |
| Hospital account password expired | Phishing | ✅ | ❌ |
| FREE COVID-19 Palliative | Phishing | ✅ | ✅ |
| Verify your GTBank account | Phishing | ✅ | ✅ |
| NHIS Monthly Bulletin May 2026 | Legitimate | ❌ | ✅ |
| Staff Meeting — Friday 10am | Legitimate | ✅ | ✅ |
| Patient Appointment Confirmation | Legitimate | ✅ | ✅ |
| Payslip for April 2026 | Legitimate | ✅ | ✅ |
| Annual Leave Approval | Legitimate | ✅ | ✅ |
| **Accuracy** | | **80%** | **88%** |

> PhishGuard operates at zero marginal cost per query vs ChatGPT API pricing
> (~$0.002/query). At 1,000 daily emails, PhishGuard saves ~$730/year while
> operating 11,097x faster than manual review. ChatGPT demonstrated superior
> contextual reasoning on ambiguous samples, suggesting a hybrid architecture
> as a productive direction for future work.

---

## 🚀 Getting Started

### Prerequisites
- Python 3.10+
- Node.js 20+
- Git
- n8n (workflow automation)
- ngrok (for AgentMail webhook tunnel)

### Installation

    git clone https://github.com/Kzian/phishing-detection-system.git
    cd phishing-detection-system

    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt

    python3 backend/detection/url_detector.py
    python3 backend/detection/email_detector.py
    python3 backend/detection/sms_detector.py

    python -m backend.main

    # Second terminal — frontend
    cd frontend
    npm install
    npx vite

- Dashboard: http://localhost:3000
- API docs:   http://localhost:8000/docs

---

## 🔌 API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | /health | System health + model status |
| POST | /analyze/url | Analyze URL — 109 features auto-extracted |
| POST | /analyze/email | 3-layer email analysis |
| POST | /analyze/sms | SMS smishing detection |
| GET | /incidents | Role-filtered incident list |
| GET | /incidents/stats/summary | Dashboard statistics |
| GET | /incidents/{id} | Single incident detail |
| GET | /incidents/{id}/report | Download incident report (admin) |
| GET | /my/incidents | Authenticated user's incidents |
| PATCH | /incidents/{id}/action | Admin action — block/clear/escalate |
| POST | /auth/register | Register hospital staff |
| POST | /auth/login | Login — returns JWT token |
| GET | /auth/me | Current user profile |
| GET | /admin/stats | Per-staff incident breakdown |
| PATCH | /admin/users/{email}/restore | Restore suspended account |
| POST | /webhook/agentmail | AgentMail email webhook receiver |

---

## 🏥 Hospital Staff Portal

Role-aware security portal for Nigerian healthcare environments.

**Roles:** Doctor · Nurse · Admin · IT

**Features:**
- Secure JWT registration and authentication
- Role and department assignment
- Personal incident history per staff member
- Real-time threat analysis dashboard (URL, Email, SMS)
- Incident attribution — AgentMail emails linked to staff accounts automatically
- Admin dashboard — all incidents, staff breakdown, action buttons
- Incident PDF/text report download
- Auto-suspend on HIGH/CRITICAL incoming email threats

**Sender Domain Intelligence:**
- .gov.ng / .edu.ng / .org.ng → trust score reduced (legitimate signal)
- .xyz / .tk / .ml / .cf → suspicion score increased
- SPF record presence factored into final score

---

## ⚡ Automated Incident Response

| Severity | Score | Actions Triggered |
|---|---|---|
| CLEAN | < 30% | log_incident |
| LOW | 30–49% | log + flag_message |
| MEDIUM | 50–69% | log + flag + notify_user |
| HIGH | 70–84% | log + quarantine + notify_admin + block_sender |
| CRITICAL | ≥ 85% | log + quarantine + notify_admin + block + lock_account + generate_report |

Auto-suspend on HIGH/CRITICAL from AgentMail monitoring only.
Dashboard-initiated analysis never triggers auto-suspend.

---

## 🔄 AgentMail Automated Email Monitoring

    Staff inbox (xxx@agentmail.to)
            |
            | Webhook — instant delivery
            ▼
    ngrok tunnel → POST /webhook/agentmail
            |
            | 3-layer threat analysis
            ▼
    Threat score computed
            |
            | IF severity = HIGH or CRITICAL
            ▼
    Staff account auto-suspended
    Admin dashboard alert
    n8n notification triggered
            |
            | IF severity = CLEAN/LOW/MEDIUM
            ▼
    Incident logged silently
    No account action taken

---

## 🗺️ Development Roadmap

- [x] Phase 1 — Environment setup and project structure
- [x] Phase 2 — URL phishing detection (Random Forest, 97%, 109 features)
- [x] Phase 3 — Email phishing detection (TF-IDF + LR, 99%)
- [x] Phase 4 — SMS smishing detection (95%)
- [x] Phase 5 — Automated incident response engine
- [x] Phase 6 — FastAPI REST backend (16 endpoints, JWT auth, SQLite)
- [x] Phase 7 — React dashboard + Hospital staff portal (4 roles)
- [x] Phase 7b — AgentMail webhook + auto-suspend on HIGH/CRITICAL
- [x] Phase 8 — Formal evaluation (40 samples, ChatGPT comparison)
- [ ] Phase 9 — Docker containerisation
- [ ] Phase 10 — MSc thesis writing

---

## 🧪 Key Design Decisions

**URL Feature Resolution:** Network features (domain age, ASN, SPF, DNS)
resolved at inference time using RDAP, ipinfo.io, and dnspython — no paid
APIs required. Google index features excluded from model (rank 84/89, ~0.01%
importance).

**Nigerian ccTLD Handling:** .edu.ng, .gov.ng, .org.ng are not indexed in the
IANA RDAP registry (NiRA does not expose RDAP). These domains produce false
positives in URL analysis. A curated institutional whitelist partially
mitigates this. NiRA RDAP integration or Google Safe Browsing API integration
is recommended for production deployment.

**SMS Threshold:** Detection threshold lowered to 0.35 to prioritise recall —
in healthcare environments, missing a smishing attack carries significantly
higher risk than a false positive.

**Agentic Architecture:** PhishGuard exhibits agentic behaviour through
autonomous monitoring (AgentMail), ML-based threat reasoning, and automated
response (account suspension, admin notification) without human intervention —
consistent with Russell and Norvig's definition of an intelligent agent.

**Auto-Suspend Policy:** Accounts are automatically quarantined when incoming
emails score HIGH (≥70%) or CRITICAL (≥85%), reflecting the risk profile of
healthcare environments. Dashboard-initiated analysis never triggers suspension
as the analyst is the initiator, not the victim.

---

## 👤 Author

**Cyb3rry (Cassia Anwar)**
MSc Cybersecurity Candidate — FUTO
Lecturer | Cybersecurity Researcher | AI Enthusiast
GitHub: [@Kzian](https://github.com/Kzian)

---

## 📄 License

Academic research project — MSc Cybersecurity, FUTO.

---

## 🙏 Acknowledgements

- GregaVrbancic Phishing Dataset
- Kaggle Phishing Email Dataset (Naser Abdullah Alam)
- UCI SMS Spam Collection
- RDAP (IANA) — free domain registration lookup
- ipinfo.io — free ASN resolution
- AgentMail — email infrastructure for monitoring
- Anthropic Claude API
- FUTO Department of Computer Science
