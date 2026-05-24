# PhishGuard AI 🛡️

> **Design and Implementation of an AI-Powered Phishing Detection and Automated Incident Response System for Healthcare Environments**

MSc Cybersecurity Research Project — FUTO
Cyb3rry (Cassia Anwar) | [@Kzian](https://github.com/Kzian)

---

## 🧠 Overview

PhishGuard AI is a complete intelligent cybersecurity platform that detects phishing attacks across three channels — URLs, emails, and SMS — and responds automatically. Built specifically for healthcare environments in Nigeria where phishing attacks targeting patient data and clinical systems are a growing threat.

The system combines machine learning, NLP, real-time network analysis, automated incident response, and a role-aware hospital staff portal into a single deployable platform.

---

## 🏗️ System Architecture

                    ┌─────────────────────────────────┐
                    │         INPUT CHANNELS          │
                    └──────┬───────────┬──────────────┘
                           │           │
               ┌───────────▼──┐   ┌───▼──────────────┐
               │ n8n IMAP     │   │  React Dashboard  │
               │ (Gmail poll) │   │  Hospital Portal  │
               └───────┬──────┘   └────────┬──────────┘
                       └──────────┬─────────┘
                                  ▼
                    ┌─────────────────────────┐
                    │   FastAPI REST Backend  │
                    │   localhost:8000        │
                    │   JWT Auth + SQLite     │
                    └──────┬──────────────────┘
                           │
          ┌────────────────┼────────────────┐
          ▼                ▼                ▼
   ┌─────────────┐  ┌─────────────┐  ┌─────────────┐
   │URL Detector │  │Email Detect │  │SMS Detector │
   │Rnd Forest   │  │TF-IDF + LR  │  │NLP Classify │
   │109 features │  │3-layer anly │  │thresh=0.35  │
   │94% accuracy │  │98% accuracy │  │97% accuracy │
   └──────┬──────┘  └──────┬──────┘  └──────┬──────┘
          └────────────────┼─────────────────┘
                           ▼
              ┌────────────────────────┐
              │   Threat Scoring Engine│
              │  CLEAN / LOW / MEDIUM  │
              │    HIGH / CRITICAL     │
              └────────────┬───────────┘
                           ▼
              ┌────────────────────────┐
              │    Incident Handler    │
              │  6 automated actions   │
              │  incidents.json audit  │
              └────────────┬───────────┘
                           ▼
              ┌────────────────────────┐
              │   n8n Workflow Engine  │
              │  Alerts + Admin Email  │
              └────────────────────────┘

---

## 📊 Model Performance

### URL Detection — Phase 2
Dataset: GregaVrbancic Phishing Dataset (88,647 URLs, 109 features)
Features: 97 lexical + 12 network (RDAP, ipinfo.io, DNS, HTTP HEAD)

| Metric | Legitimate | Phishing |
|---|---|---|
| Precision | 95% | 93% |
| Recall | 96% | 90% |
| F1-Score | 95% | 91% |
| **Accuracy** | **94%** | |

### Email Detection — Phase 3
Dataset: Combined Phishing Email Dataset — Kaggle (82,484 emails)
Enhancement: 3-layer — NLP content + sender domain reputation + SPF validation

| Metric | Legitimate | Phishing |
|---|---|---|
| Precision | 99% | 98% |
| Recall | 98% | 99% |
| F1-Score | 98% | 98% |
| **Accuracy** | **98%** | |

### SMS Smishing Detection — Phase 4
Dataset: UCI SMS Spam Collection (5,570 messages)

| Metric | Legitimate | Spam/Smishing |
|---|---|---|
| Precision | 99% | 86% |
| Recall | 98% | 95% |
| F1-Score | 98% | 90% |
| **Accuracy** | **97%** | |

> SMS class imbalance (747 spam vs 4,823 legitimate) addressed via
> class_weight="balanced" and threshold=0.35 — prioritising recall
> since missing a smishing attack carries higher risk than a false positive.

---

## 🚀 Getting Started

### Prerequisites
- Python 3.10+
- Node.js 20+
- Git
- n8n (workflow automation)

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
| POST | /analyze/url | Analyze a URL (109 features auto-extracted) |
| POST | /analyze/email | 3-layer email analysis |
| POST | /analyze/sms | SMS smishing detection |
| GET | /incidents | All incidents (filterable by severity/type) |
| GET | /incidents/stats/summary | Dashboard statistics |
| GET | /incidents/{id} | Single incident detail |
| GET | /my/incidents | Authenticated user's incidents |
| POST | /auth/register | Register hospital staff |
| POST | /auth/login | Login — returns JWT token |
| GET | /auth/me | Current user profile |

---

## 🏥 Hospital Staff Portal

Role-aware security portal for Nigerian healthcare environments.

**Roles:** Doctor · Nurse · Admin · IT

**Features:**
- Secure registration and JWT authentication
- Role and department assignment
- Personal incident history per staff member
- Real-time threat analysis dashboard
- Incident attribution via n8n IMAP monitoring

**Sender Domain Intelligence:**
- .gov.ng / .edu.ng / .org.ng → trust score reduced (legitimate signal)
- .xyz / .tk / .ml → suspicion score increased
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

---

## 🔄 n8n Automated Email Monitoring

    Dedicated Gmail inbox (phishguard.monitor.ng@gmail.com)
            |
            | IMAP polling every 2 minutes
            ▼
    n8n Email Trigger node
            |
            | HTTP Request
            ▼
    POST /analyze/email  →  3-layer threat analysis
            |
            | IF severity != CLEAN
            ▼
    Alert email → IT Admin account
    Incident logged → Staff dashboard (My Incidents)
            |
            | IF severity == CLEAN
            ▼
    Silent log only (no alert)

The IMAP trigger monitors the dedicated inbox continuously.
Hospital staff forward suspicious emails to this address.
n8n processes each email automatically within 2 minutes of arrival.

---

## 🗺️ Development Roadmap

- [x] Phase 1 — Environment setup and project structure
- [x] Phase 2 — URL phishing detection (Random Forest, 94%, 109 features)
- [x] Phase 3 — Email phishing detection (TF-IDF + LR, 98%, 3-layer analysis)
- [x] Phase 4 — SMS smishing detection (97%)
- [x] Phase 5 — Automated incident response engine
- [x] Phase 6 — FastAPI REST backend (11 endpoints, JWT auth, SQLite)
- [x] Phase 7 — React dashboard + Hospital staff portal
- [x] Phase 7b — n8n IMAP automated email monitoring
- [ ] Phase 8 — Formal evaluation and results
- [ ] Phase 9 — MSc thesis writing

---

## 🧪 Key Design Decisions

**URL Feature Resolution:** Network features (domain age, ASN, SPF, DNS) resolved at inference time using RDAP, ipinfo.io, and dnspython — no paid APIs required. Google index features excluded from model (rank 84/89, importance ~0.01%).

**Nigerian ccTLD Handling:** .edu.ng, .gov.ng, .org.ng are not indexed in the IANA RDAP registry (NiRA does not expose RDAP). These receive sender trust adjustments in the email analysis layer. Domain age resolution for .ng ccTLDs is a documented known limitation — whitelist-based mitigation recommended for production deployment.

**SMS Threshold:** Detection threshold lowered to 0.35 to prioritise recall over precision — in healthcare environments, missing a smishing attack carries significantly higher risk than a false positive.

---

## 👤 Author

**Cyb3rry (Cassia Anwar)** |
MSc Cybersecurity Candidate — FUTO |
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
- Anthropic Claude API
- FUTO Department of Computer Science
