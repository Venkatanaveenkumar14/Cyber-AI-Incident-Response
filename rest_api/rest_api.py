#rest_api/rest_api.py
from flask import Flask, request, jsonify, render_template
import requests
from datetime import datetime
import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '<username>/<drive>/Automated_Incident_Response'))) 
import json
import pandas as pd
from ml_model.model_predictor import ModelManager
import logging
import jsonschema  # For input validation
from incident_response.response_engine import simulate_response
from incident_response.alerting_system import simulate_alert
from incident_response.custom_yararules_generator import generate_yara_rule
from ml_model.class_mapping_utils import get_class_label

logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['APPLICATION_ROOT'] = '/'
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
TEMPLATE_FOLDER = os.path.join(BASE_DIR, "..", "templates")
EVENTS_FILE = os.environ.get('EVENTS_FILE', 'incident_response/events_log.json')

def save_events():
    """Save system events to the events file."""
    try:
        with open(EVENTS_FILE, "w") as f:
            json.dump(event_logs, f, indent=2)
        logger.info(f"Saved {len(event_logs)} system events to {EVENTS_FILE}")
    except Exception as e:
        logger.error(f"Error saving system events: {e}")

def load_events():
    """Load system events from the events file."""
    global event_logs
    try:
        if os.path.exists(EVENTS_FILE):
            with open(EVENTS_FILE, "r") as f:
                event_logs = json.load(f)
            logger.info(f"Loaded {len(event_logs)} system events from {EVENTS_FILE}")
        else:
            event_logs = []
            logger.warning(f"Events file not found: {EVENTS_FILE}")
    except Exception as e:
        logger.error(f"Error loading system events: {e}")
app = Flask(__name__, template_folder=TEMPLATE_FOLDER)
# Constants/Env Vars
ALERTS_FILE = os.environ.get('ALERTS_FILE', 'alerts.json')
alerts = []
event_logs = []
def save_alerts():
    """Saves alerts to the ALERTS_FILE."""
    try:
        with open(ALERTS_FILE, "w") as f:
            json.dump(alerts, f, indent=2)
        logger.info(f"Saved {len(alerts)} alerts to {ALERTS_FILE}")
    except Exception as e:
        logger.error(f"Error saving alerts to {ALERTS_FILE}: {e}")
def save_events():
    """Saves event_logs to events_log.json."""
    try:
        events_file = "incident_response/events_log.json"
        with open(events_file, "w") as f:
            json.dump(event_logs, f, indent=2)
        logger.info(f"Saved {len(event_logs)} events to {events_file}")
    except Exception as e:
        logger.error(f"Error saving system events: {e}")
alerts = []
save_alerts()
print("[REST API] Cleared alerts.json and memory on server startup...")
API_PORT = int(os.environ.get('API_PORT', 5050))
otx_api_key = os.getenv('OTX_API_KEY')
otx_url = os.getenv('OTX_INDICATOR_URL', "https://otx.alienvault.com/api/v1/pulses/subscribed")

# Schemas for input validation
log_alert_schema = {
    "type": "object",
    "properties": {
        "log": {"type": "object", "required": []}  # Define properties of log
    },
    "required": ["log"]
}

log_bulk_schema = {
    "type": "object",
    "properties": {
        "logs": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "log": {"type": "object", "required": []}  # Define properties of log
                },
                "required": ["log"]
            }
        }
    },
    "required": ["logs"]
}

alerts = []


def load_alerts():
    """Loads alerts from the ALERTS_FILE."""
    global alerts
    try:
        if os.path.exists(ALERTS_FILE):
            with open(ALERTS_FILE, "r") as f:
                alerts = json.load(f)
            logger.info(f"Loaded {len(alerts)} alerts from {ALERTS_FILE}")
        else:
            logger.warning(f"Alerts file not found: {ALERTS_FILE}")
    except Exception as e:
        logger.error(f"Error loading alerts from {ALERTS_FILE}: {e}")

def fetch_otx_threats():
    """Fetches detailed threat intelligence from AlienVault OTX."""
    otx_api_key = os.environ.get('OTX_API_KEY')
    otx_url = os.environ.get('OTX_INDICATOR_URL', "https://otx.alienvault.com/api/v1/pulses/subscribed")

    if not otx_api_key or not otx_url:
        logger.warning("OTX API key or URL not configured. Skipping OTX feed.")
        return []

    headers = {"X-OTX-API-KEY": otx_api_key}
    try:
        response = requests.get(otx_url, headers=headers)
        if response.status_code == 200:
            pulses = response.json().get("results", [])
            threats = []
            for pulse in pulses:
                threats.append({
                    "name": pulse.get("name", "Unknown Threat"),
                    "description": pulse.get("description", "No description available"),
                    "adversary": pulse.get("adversary", "Unknown"),
                    "tags": pulse.get("tags", []),
                    "targeted_countries": pulse.get("targeted_countries", []),
                    "industries": pulse.get("industries", [])
                })
            logger.info(f"Fetched {len(threats)} OTX threats with details.")
            return threats
        else:
            logger.warning(f"OTX API request failed: {response.status_code} - {response.text}")
            return []
    except Exception as e:
        logger.error(f"Error fetching OTX threats: {e}")
        return []

@app.route("/")
def index():
    """Serves the dashboard."""
    load_alerts()
    otx_threats = fetch_otx_threats()
    return render_template("dashboard.html", alerts=alerts[::-1], otx_threats=otx_threats)

@app.route("/log_alert", methods=["POST"])
def log_alert():
    """
    Handles single log entry, validates input, and returns the prediction.
    """
    
    try:
        data = request.get_json()
        print("[DEBUG] /log_bulk triggered!")
        print(f"[DEBUG] Number of logs received: {len(data.get('logs', []))}")
        jsonschema.validate(data, log_alert_schema)  # Validate input
        logger.debug(f"Received log_alert: {data}")

        df = pd.DataFrame([data["log"]])
        preds, probs = ModelManager.predict(df)

        pred_class = int(preds[0]) if preds else -1  # Handle empty preds
        conf_score = float(max(probs[0])) if probs else 0.0
        pred_label = get_class_label(pred_class)

        alert_entry = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "prediction": pred_class,
            "prediction_label": pred_label,
            "confidence": round(conf_score, 4),
            "log": data["log"]
        }

        alerts.append(alert_entry)
        save_alerts()
        logger.info(f"Processed log_alert, prediction: {pred_class}, confidence: {conf_score}")
        return jsonify({"status": "success", "entry": alert_entry}), 200

    except jsonschema.ValidationError as e:
        logger.warning(f"Invalid input to /log_alert: {e.message}")
        return jsonify({"status": "error", "message": f"Invalid input: {e.message}"}), 400
    except Exception as e:
        logger.exception("Error processing /log_alert")
        return jsonify({"status": "error", "message": "Internal Server Error"}), 500

@app.route("/log_bulk", methods=["POST"])
def log_bulk():
    """
    Handles bulk log entries, validates input, predicts, simulates, and records alerts & system events.
    Ignores benign predictions for alert generation.
    """
    try:
        from incident_response.response_engine import simulate_response
        from incident_response.alerting_system import simulate_alert
        from incident_response.custom_yararules_generator import generate_yara_rule
        from ml_model.class_mapping_utils import get_class_label

        data = request.get_json()
        jsonschema.validate(data, log_bulk_schema)
        logger.debug(f"Received log_bulk with {len(data.get('logs', []))} entries")

        logs_df = pd.DataFrame([log["log"] for log in data.get("logs", [])])
        preds, probs = ModelManager.predict(logs_df)

        new_alerts = []

        for i, log_row in enumerate(data.get("logs", [])):
            pred_class = int(preds[i]) if preds is not None and len(preds) > i else -1
            conf_score = round(float(max(probs[i])), 4) if probs is not None and len(probs) > i else 0.0
            pred_label = get_class_label(pred_class)

            match = "DDoS" if pred_label.lower().find("ddos") != -1 else "None"

            # SKIP benign traffic
            if pred_label.upper() == "BENIGN":
                continue

            alert = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "prediction": pred_class,
                "prediction_label": pred_label,
                "confidence": conf_score,
                "match": match,
                "log": log_row["log"]
            }

            alerts.append(alert)
            new_alerts.append(alert)

            # Only simulate for DDoS-related attacks
            if pred_label.upper() != "BENIGN":
                event1 = simulate_response(alert)
                event2 = simulate_alert(alert)
                yara_event = generate_yara_rule(alert)

                if event1:
                    event_logs.append(event1)
                if event2:
                    event_logs.append(event2)
                if yara_event:
                    event_logs.append(yara_event)

        save_alerts()
        save_events()
        events_file = "incident_response/events_log.json"
        try:
            with open(events_file, "w") as f:
                json.dump(event_logs, f, indent=2)
            logger.info(f"Saved {len(event_logs)} system events to {events_file}")
        except Exception as e:
            logger.error(f"Error saving system events: {e}")
        logger.info(f"Processed {len(new_alerts)} filtered alerts and {len(event_logs)} system events in /log_bulk")
        return jsonify({"status": "success", "count": len(new_alerts)}), 200

    except jsonschema.ValidationError as e:
        logger.warning(f"Invalid input to /log_bulk: {e.message}")
        return jsonify({"status": "error", "message": f"Invalid input: {e.message}"}), 400
    except Exception as e:
        logger.exception("Error processing /log_bulk")
        return jsonify({"status": "error", "message": "Internal Server Error"}), 500
    
@app.route("/alerts", methods=["GET"])
def get_alerts():
    """Returns all stored alerts."""
    try:
        with open(ALERTS_FILE, "r") as f:
            loaded_alerts = json.load(f)

        enriched_alerts = []
        for alert in loaded_alerts:
            if "prediction_label" not in alert and "prediction" in alert:
                try:
                    alert["prediction_label"] = get_class_label(int(alert["prediction"]))
                except Exception as e:
                    logger.warning(f"Failed to map prediction label for alert: {e}")
                    alert["prediction_label"] = "Unknown"
            enriched_alerts.append(alert)

        logger.info(f"Returned {len(enriched_alerts)} alerts (with prediction labels).")
        return jsonify(enriched_alerts[::-1]), 200  # Return most recent first

    except FileNotFoundError:
        logger.warning(f"Alerts file not found: {ALERTS_FILE}")
        return jsonify([]), 200  # Return empty list
    except Exception as e:
        logger.exception("Error in /alerts")
        return jsonify({"status": "error", "message": "Error retrieving alerts"}), 500

@app.route("/reset_alerts_memory", methods=["POST"])
def reset_alerts_memory():
    """Clears in-memory alerts."""
    global alerts
    alerts = []
    save_alerts()  # Also saves empty to alerts.json
    logger.info("In-memory alerts reset successfully.")
    return jsonify({"status": "success", "message": "Alerts memory reset"}), 200

@app.route("/otx_feed")
def fetch_otx_threats_api():
    """Endpoint to get OTX threats."""
    threats = fetch_otx_threats()
    return jsonify(threats)

@app.route("/events", methods=["GET"])
def get_events():
    """Returns stored system events."""
    try:
        events_file = "incident_response/events_log.json"
        if os.path.exists(events_file):
            with open(events_file, "r") as f:
                loaded_events = json.load(f)
            return jsonify(loaded_events[::-1]), 200
        else:
            return jsonify([]), 200
    except Exception as e:
        logger.exception("Error in /events")
        return jsonify([]), 200

if __name__ == "__main__":
    load_alerts()
    load_events()
    app.run(debug=True, port=5050)



