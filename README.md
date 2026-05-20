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
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Train all models
python3 backend/detection/url_detector.py
python3 backend/detection/email_detector.py
python3 backend/detection/sms_detector.py

# Run the backend
uvicorn backend.main:app --reload
```

---

## 📊 Model Performance

### Phase 2 — URL Detection
Dataset: GregaVrbancic Phishing Dataset (88,647 URLs, 111 features)

| Metric | Legitimate | Phishing |
|---|---|---|
| Precision | 98% | 95% |
| Recall | 97% | 96% |
| F1-Score | 98% | 96% |
| **Accuracy** | **97%** | |

### Phase 3 — Email Detection
Dataset: Combined Phishing Email Dataset — Kaggle (82,484 emails)

| Metric | Legitimate | Phishing |
|---|---|---|
| Precision | 99% | 98% |
| Recall | 98% | 99% |
| F1-Score | 98% | 98% |
| **Accuracy** | **98%** | |

### Phase 4 — SMS/Smishing Detection
Dataset: UCI SMS Spam Collection (5,570 messages)

| Metric | Legitimate | Spam/Smishing |
|---|---|---|
| Precision | 99% | 86% |
| Recall | 98% | 95% |
| F1-Score | 98% | 90% |
| **Accuracy** | **97%** | |

> Note: SMS dataset class imbalance (747 spam vs 4,823 legitimate) 
> was addressed using class_weight="balanced" and a lowered 
> detection threshold of 0.35 — prioritising recall over precision 
> since missing a smishing attack carries higher risk than a false alarm.

---

## 🗺️ Development Roadmap

- [x] Phase 1 — Environment setup and project structure
- [x] Phase 2 — URL phishing detection (Random Forest, 97% accuracy)
- [x] Phase 3 — Email phishing detection (TF-IDF + LR, 98% accuracy)
- [x] Phase 4 — SMS smishing detection (97% accuracy)
- [ ] Phase 5 — Automated incident response (n8n)
- [ ] Phase 6 — Dashboard and full system integration
- [ ] Phase 7 — Evaluation and thesis writing

---

## 👤 Author

**Cyb3rry**  
MSc Cybersecurity Candidate — FUTO  

| Lecturer | Cybersecurity Researcher | AI Enthusiast  
GitHub: [@Kzian](https://github.com/Kzian)

---

## 📄 License

This project is developed for academic research purposes.

---

## 🙏 Acknowledgements

- GregaVrbancic Phishing Dataset
- Kaggle Phishing Email Dataset (Naser Abdullah Alam)
- UCI SMS Spam Collection
- HuggingFace Transformers
- Anthropic Claude API
- FUTO Department of Computer Science