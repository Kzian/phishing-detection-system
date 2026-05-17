# 🛡️ AI-Powered Phishing Detection and Automated Incident Response System

> MSc Cybersecurity Thesis Project — Federal University of Technology Owerri (FUTO)

---

## 📌 Overview

This system is an intelligent, automated cybersecurity defense platform designed to detect phishing attacks across multiple vectors — URLs, emails, and SMS — and automatically respond to threats without human intervention.

It combines classical Machine Learning, Natural Language Processing (NLP), and workflow automation to create a lightweight Security Operations Center (SOC) tailored for healthcare environments.

---

## 🎯 Key Features

- 🔗 **URL Phishing Detection** — Random Forest classifier trained on 88,000+ URLs (97% accuracy)
- 📧 **Email Phishing Detection** — NLP-based detection using DistilBERT transformer model
- 📱 **SMS/Smishing Detection** — Lightweight NLP classifier for short-text phishing
- ⚡ **Automated Incident Response** — n8n-powered workflows for real-time threat response
- 📊 **Security Dashboard** — React-based frontend for monitoring and analysis
- 🤖 **AI Incident Reports** — Auto-generated reports via Claude API
- 🏥 **Healthcare Context** — Optimized for phishing patterns targeting healthcare environments

---

## 🏗️ System Architecture

```
Incoming Input (URL / Email / SMS)
              ↓
       FastAPI Backend
              ↓
    ┌─────────────────────┐
    │  ML Detection Layer │ ← Random Forest / XGBoost
    └─────────┬───────────┘
              │
    ┌─────────▼───────────┐
    │  NLP Detection Layer│ ← DistilBERT
    └─────────┬───────────┘
              │
    ┌─────────▼───────────┐
    │  Threat Scoring     │ ← Weighted combination
    └─────────┬───────────┘
              │
    ┌─────────▼───────────┐
    │  Automated Response │ ← n8n workflows
    └─────────┬───────────┘
              │
    ┌─────────▼───────────┐
    │  Dashboard +        │ ← React frontend
    │  Incident Reports   │
    └─────────────────────┘
```

---

## 🧰 Tech Stack

| Layer | Technology |
|---|---|
| Language | Python 3.12 |
| Backend API | FastAPI |
| ML Models | Scikit-learn, XGBoost |
| NLP Models | HuggingFace Transformers (DistilBERT) |
| Deep Learning | PyTorch (CPU) |
| Automation | n8n |
| Frontend | React |
| Database | PostgreSQL |
| Containerization | Docker |
| AI Reports | Claude API (Anthropic) |
| Version Control | Git / GitHub |

---

## 📁 Project Structure

```
phishing-detection-system/
├── backend/
│   ├── api/                  # API route handlers
│   ├── detection/
│   │   ├── url_detector.py   # URL phishing detection
│   │   ├── email_detector.py # Email phishing detection
│   │   └── sms_detector.py   # SMS phishing detection
│   ├── scoring/
│   │   └── threat_engine.py  # Threat scoring engine
│   ├── response/
│   │   └── incident_handler.py # Automated response logic
│   └── main.py               # FastAPI application entry point
├── data/
│   ├── raw/                  # Raw datasets
│   ├── processed/            # Cleaned/processed data
│   └── saved_models/         # Trained ML models (.pkl)
├── frontend/                 # React dashboard
├── notebooks/                # Jupyter notebooks for EDA
├── n8n/                      # n8n workflow definitions
├── tests/                    # Unit and integration tests
├── .env                      # Environment variables (not committed)
├── requirements.txt          # Python dependencies
└── README.md
```

---

## 🚀 Getting Started

### Prerequisites
- Python 3.10+
- Git
- Node.js (for frontend)
- n8n (for automation workflows)

### Installation

```bash
# Clone the repository
git clone https://github.com/Kzian/phishing-detection-system.git
cd phishing-detection-system

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the backend
uvicorn backend.main:app --reload
```

---

## 📊 Model Performance (Phase 2 — URL Detection)

| Metric | Legitimate | Phishing |
|---|---|---|
| Precision | 98% | 95% |
| Recall | 97% | 96% |
| F1-Score | 98% | 96% |
| **Accuracy** | **97%** | |

Dataset: GregaVrbancic Phishing Dataset (88,647 URLs, 111 features)

---

## 🗺️ Development Roadmap

- [x] Phase 1 — Environment setup and project structure
- [x] Phase 2 — URL phishing detection (Random Forest, 97% accuracy)
- [ ] Phase 3 — Email phishing detection (NLP / DistilBERT)
- [ ] Phase 4 — SMS phishing detection
- [ ] Phase 5 — Automated incident response (n8n)
- [ ] Phase 6 — Dashboard and full system integration
- [ ] Phase 7 — Evaluation and thesis writing

---

## 👤 Author

**Cyb3rry**
MSc Cybersecurity Candidate — FUTO


Lecturer | Cybersecurity Researcher | AI Enthusiast
GitHub: [@Kzian](https://github.com/Kzian)

---

## 📄 License

This project is developed for academic research purposes.

---

## 🙏 Acknowledgements

- GregaVrbancic Phishing Dataset
- HuggingFace Transformers
- Anthropic Claude API
- FUTO Department of Computer Science
```

---

