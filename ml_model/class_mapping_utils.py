# ml_model/class_mapping_utils.py

import json
import os

# Recovered class-to-label mapping
class_to_label_mapping = {
    0: "BENIGN",
    1: "DNS",
    2: "LDAP",
    3: "MSSQL",
    4: "NetBIOS",
    5: "NTP",
    6: "Portmap",
    7: "SNMP",
    8: "SSDP",
    9: "Syn",
    10: "TFTP",
    11: "UDP",
    12: "UDPLag",
    13: "WebDDoS"
}

def get_class_label(pred_class: int) -> str:
    """
    Given a predicted class number, return the corresponding label.
    """
    return class_to_label_mapping.get(pred_class, "Unknown")

def recover_labels(pred_list):
    """
    Given a list of predicted class numbers, return a list of labels.
    """
    return [get_class_label(pred) for pred in pred_list]

def save_class_mapping_json(filepath="models/class_mapping.json"):
    """
    Save the class mapping dictionary to a JSON file.
    """
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, "w") as f:
        json.dump(class_to_label_mapping, f, indent=4)
    print(f"[INFO] Class mapping saved to {filepath}")

def load_class_mapping_json(filepath="models/class_mapping.json"):
    """
    Load the class mapping dictionary from a JSON file.
    """
    with open(filepath, "r") as f:
        mapping = json.load(f)
    return {int(k): v for k, v in mapping.items()}