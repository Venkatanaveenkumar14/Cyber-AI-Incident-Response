# AIRS – Cyber AI Incident Response System
```
AIRS is a modular, AI-powered incident response framework designed to detect and respond to WebDDoS and other network anomalies in real-time. It combines deep feature engineering, ML-based threat classification, automated Incident Response and mitigation strategies, and dynamic YARA rule generation—all integrated into a unified pipeline.
```
---

## Project Structure
```
Automated_Incident_Response/
│
├── data_preprocessing/
│   ├── ddos_preprocessor.py         # Prepares raw traffic data
│   └── feature_engineering.py       # Extracts advanced features
│
├── dataset/
│   ├── alerts.txt
│   ├── datasets_drive/              # External dataset links or temp files
│   └── synthetic_data.py            # Generates synthetic benign & attack data
│
├── generated_yara_rules/
│   └── ddos_alert_.yara            # Auto-generated rules based on anomalies
│
├── incident_response/
│   ├── alerting_system.py           # Sends alerts
│   ├── custom_yararules_generator.py
│   ├── firewall_automation.py       # Future Work - Interacts with iptables or APIs
│   └── response_engine.py           # Executes automated responses
│
├── ml_model/
│   ├── class_mapping_utils.py
│   ├── feature_generator.py
│   ├── model_predictor.py           # Loads trained models for predictions
│   └── train_model.py               # Model training (CatBoost, XGBoost, etc.)
│
├── models/
│   └── retrained_.cbm/.pkl         # Git LFS-tracked models
│
├── rest_api/
│   ├── init.py
│   └── rest_api.py                  # Flask endpoints to trigger AIRS components
│
├── templates/
│   └── dashboard.html               # Streamlit/Flask UI HTML
│
├── .env                             # Config and credentials
├── .gitignore
├── .gitattributes
├── requirements.txt
├── environment.yml                  # Conda environment spec
│
├── AIRS_Architecture Diagram_FlowChart.png
├── Actual_ROC_Figure_15Features.png
├── roc_curves.png
│
├── extract_catboost_features.py
├── log_ingestion_simulator.py
├── manual_test_recovery.py
├── predictions_log.csv
├── recovery.csv
├── roc_calculation.py
├── select_top_features.py
└── flow.txt / commands.txt
```
---

## How to Run the System

```bash
# 1. Clone the repo
git clone https://github.com/Venkatanaveenkumar14/Cyber-AI-Incident-Response.git
cd Cyber-AI-Incident-Response

# 2. Setup the environment
conda env create -f environment.yml
conda activate AIRS

# 3. Run the API or Dashboard
1. OTX_API_KEY=<YOUR_OTX_KEY> > python rest_api/rest_api.py  # For backend API mode
2. python log_ingestion_simulator.py    # Ingesting logs
```

# ML Model Highlights
	•	16-feature optimized training on CIC-DDoS 2017/2019 datasets
	•	CatBoost, XGBoost, and Stacked Ensemble used

# Dataset Access (Google Drive)
```
Due to GitHub size limits (>2GB), full datasets are available here:
https://drive.google.com/drive/folders/1clqG3DGWNHu21SXrgvlsqbs3G9ooek8F?usp=drive_link
```

# Real-Time Incident Response
	•	Alerts are raised based on model predictions
	•	Simulated IP blocks and alerting handled by:
	  •	response_engine.py
	  •	alerting_system.py
    •	custom_yararules_generator.py
	•	Custom YARA rules are generated and stored in generated_yara_rules/

# Outputs and Artifacts
	•	alerts.json & alerts_cache.json: Real-time predictions
	•	recovery.csv: Incident auto-triage history
	•	roc_curves.png, Actual_ROC_Figure_15Features.png: Model performance

# Author
```
Venkata Naveen Kumar Prabhuleti
🎓 Master’s in Cybersecurity Analytics and Operations @ Penn State University
GitHub: https://github.com/Venkatanaveenkumar14/
```
LinkedIn: https://www.linkedin.com/in/naveen-kumar93/

# License
```
This project is under the MIT License. Use it for academic or research purposes freely.
```
