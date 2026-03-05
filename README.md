# 🔒 Phishing Detection with SHAP

This project implements a rigorous phishing detection system using multiple machine learning models (Random Forest, XGBoost, and Ensembles) complemented by **SHAP (SHapley Additive exPlanations)** for mathematical transparency and explainability.

## 🚀 Live App
Access the live application here: **[https://shap-phishing-detection.streamlit.app/](https://shap-phishing-detection.streamlit.app/)**

## ✨ Features
- **Multi-Model Analysis:** Compare predictions from Random Forest, XGBoost, Weighted Ensemble, and Stacking Ensemble.
- **Explainable AI (XAI):** Detailed SHAP waterfall and force plots for every prediction, showing exactly which features contributed to the result.
- **Real-time Feature Extraction:** Extracts lexical, DNS, SSL, and HTML features directly from any URL.
- **Academic Rigor:** Mathematically sound explanations including space-aware probability calculations.

## 🛠️ Installation & Local Setup

### 1. Clone the Repository
```bash
git clone git@github.com:ifeoseni/phishing-detection-with-shap.git
cd phishing-detection-with-shap
```

### 2. Set Up Environment
It is recommended to use a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
playwright install
```

### 4. Run the App
```bash
streamlit run discover_ai_streamlit.py
```

## 📦 Deployment Note
This repository is optimized for deployment on **Streamlit Cloud**. 
- `packages.txt` contains required system-level dependencies (Playwright/Chromium).
- `requirements.txt` contains all necessary Python packages.
- **Git LFS** is required to handle the large model bundle (`model_bundle_feb_15_2026.pkl`) and datasets.

## 📄 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
