# incident_response/alerting_system.py
import json
import os
from datetime import datetime

ALERT_LOG = os.environ.get("ALERT_LOG", "incident_response/alerts_log.json")
os.makedirs(os.path.dirname(ALERT_LOG), exist_ok=True)

def simulate_alert(alert):
    """
    Simulate sending an alert and return an event.
    """
    try:
        pred_label = alert.get("prediction_label", "").lower()

        if "ddos" in pred_label:
            alert_type = "DDoS Alert"
        elif "suspicious" in pred_label:
            alert_type = "Suspicious Activity"
        else:
            alert_type = "General Alert"

        alert_entry = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "alert": alert,
            "type": alert_type
        }

        if os.path.exists(ALERT_LOG):
            with open(ALERT_LOG, "r") as f:
                alerts = json.load(f)
        else:
            alerts = []

        alerts.append(alert_entry)
        with open(ALERT_LOG, "w") as f:
            json.dump(alerts, f, indent=2)

        print(f"[ALERTING SYSTEM] {alert_type} simulated for {alert.get('log', {}).get('source_ip', 'Unknown')}")

        return {
            "timestamp": alert_entry["timestamp"],
            "type": "Alert",
            "message": f"{alert_type}: {alert['prediction']} (confidence {alert['confidence']*100:.2f}%)"
        }

    except Exception as e:
        print(f"[ERROR] simulate_alert: {e}")
        return None