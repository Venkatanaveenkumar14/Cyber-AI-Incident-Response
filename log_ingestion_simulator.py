# log_ingestion_simulator.py
import numpy as np
import os
import json
import time
import pandas as pd
import requests
from datetime import datetime
from ml_model.model_predictor import ModelManager
import logging

logger = logging.getLogger(__name__)

# CONFIGURATION
CSV_FILE = os.environ.get('INGESTION_CSV_FILE', '<username>/<drive>/Automated_Incident_Response/dataset/test_logs_1000.csv')
BULK_POST_ENDPOINT = os.environ.get('LOG_BULK_ENDPOINT', 'http://localhost:5050/log_bulk')
BATCH_SIZE = int(os.environ.get('INGESTION_BATCH_SIZE', 100))

def clear_alerts_file():
    # Clears alerts.json AND resets in-memory alerts from server.
    try:
        alerts_file = os.environ.get('ALERTS_FILE', 'alerts.json')
        with open(alerts_file, 'w') as f:
            json.dump([], f)
        print(f"[INFO] Cleared {alerts_file} locally before ingestion...")

        # Also clear server memory
        response = requests.post('http://localhost:5050/reset_alerts_memory')
        if response.status_code == 200:
            print("[INFO] Cleared in-memory alerts on server...")
        else:
            print(f"[ERROR] Failed to clear server memory: {response.text}")

    except Exception as e:
        print(f"[ERROR] Failed to clear alerts: {e}")

def clear_events_file():
    """Clears events_log.json to reset system events."""
    try:
        events_file = "incident_response/events_log.json"
        if os.path.exists(events_file):
            with open(events_file, "w") as f:
                json.dump([], f)
            print(f"[INFO] Cleared {events_file} locally before ingestion...")
    except Exception as e:
        print(f"[ERROR] Failed to clear {events_file}: {e}")

def main():
    clear_alerts_file()
    clear_events_file()
    print("[INFO] Cleared alerts.json and events_log.json before ingestion...")
    print("[INFO] Starting log ingestion simulator...")

    # 1. Load CSV
    df = pd.read_csv(CSV_FILE)
    print(f"[INFO] Loaded {len(df)} rows from {CSV_FILE}")

    # 2. Model Prediction
    preds, probs = ModelManager.predict(df)
    print("[INFO] Predictions completed.")

    # 3. Build logs
    logs = []
    for i in range(len(df)):
        try:
            log_row = df.iloc[i].to_dict()
            pred_class = int(preds[i]) if preds is not None and len(preds) > i else -1
            conf_score = float(max(probs[i])) if probs is not None and len(probs) > i else 0.0

            log_entry = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "prediction": pred_class,
                "confidence": conf_score,
                "log": log_row
            }
            logs.append(log_entry)
        except Exception as e:
            print(f"[WARNING] Failed processing row {i}: {e}")

    print(f"[INFO] Prepared {len(logs)} log entries.")

    # 4. Push in batches
    for i in range(0, len(logs), BATCH_SIZE):
        batch_logs = logs[i:i+BATCH_SIZE]
        try:
            res = requests.post(BULK_POST_ENDPOINT, json={"logs": batch_logs})
            if res.status_code == 200:
                print(f"[INFO] Successfully pushed {len(batch_logs)} logs.")
            else:
                print(f"[ERROR] Failed pushing batch: {res.status_code}")
        except Exception as e:
            print(f"[ERROR] Error sending logs to {BULK_POST_ENDPOINT}: {e}")

# THIS IS IMPORTANT
if __name__ == "__main__":
    main()