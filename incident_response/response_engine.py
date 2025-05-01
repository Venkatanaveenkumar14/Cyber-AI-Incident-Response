# incident_response/response_engine.py
import json
import os
from datetime import datetime

RESPONSE_LOG = os.environ.get("RESPONSE_LOG", "incident_response/response_log.json")
os.makedirs(os.path.dirname(RESPONSE_LOG), exist_ok=True)

def simulate_response(alert):

    #Simulate automated incident response based on prediction label.

    try:
        pred_label = alert.get("prediction_label", "").lower()
        src_ip = alert.get("log", {}).get("source_ip", "Unknown")

        if "ddos" in pred_label:  #Important new handling
            action = f"Simulated Action: Block IP {src_ip} due to DDoS Attack"
        elif "udp" in pred_label:
            action = f"Simulated Action: Apply UDP Rate Limiting for IP {src_ip}"
        elif "syn" in pred_label:
            action = f"Simulated Action: Block IP {src_ip} and trigger TCP SYN Flood Investigation"
        elif "ssdp" in pred_label:
            action = f"Simulated Action: Block or Monitor SSDP Device {src_ip}"
        elif any(protocol in pred_label for protocol in ["dns", "ntp", "mssql"]):
            action = f"Simulated Action: Monitor {src_ip} for possible Amplification Attack"
        elif any(protocol in pred_label for protocol in ["portmap", "snmp", "ldap"]):
            action = f"Simulated Action: Flag suspicious connection from {src_ip}"
        elif "tftp" in pred_label:
            action = f"Simulated Action: Terminate suspicious TFTP session from {src_ip}"
        else:
            action = f"No critical action required for {pred_label}."

        response_entry = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "alert": alert,
            "action": action
        }

        if os.path.exists(RESPONSE_LOG):
            with open(RESPONSE_LOG, "r") as f:
                responses = json.load(f)
        else:
            responses = []

        responses.append(response_entry)
        with open(RESPONSE_LOG, "w") as f:
            json.dump(responses, f, indent=2)

        print(f"[RESPONSE ENGINE] {action}")

        return {
            "timestamp": response_entry["timestamp"],
            "type": "Action",
            "message": action
        }

    except Exception as e:
        print(f"[ERROR] simulate_response: {e}")
        return None
