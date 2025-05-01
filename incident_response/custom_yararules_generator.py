# incident_response/custom_yararules_generator.py

import os
from datetime import datetime

def generate_yara_rule(alert):

    #Generates a simple YARA rule based on alert information.

    label = alert.get('log', {}).get('label', '').lower()

    if label != 'ddos':
        return None

    try:
        rule_name = f"ddos_alert_{alert['timestamp'].replace(' ', '_').replace(':', '_')}"
        rule_content = f"""
rule {rule_name}
{{
    meta:
        description = "Auto-generated DDoS detection rule"
        confidence = "{alert.get('confidence', 0)}"
    strings:
        $ddos = "ddos"
    condition:
        $ddos
}}
"""
        output_dir = "generated_yara_rules"
        os.makedirs(output_dir, exist_ok=True)

        rule_path = os.path.join(output_dir, f"{rule_name}.yara")
        with open(rule_path, "w") as f:
            f.write(rule_content)

        print(f"[YARA GENERATOR] Rule generated: {rule_path}")

        return {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "type": "YARA Rule",
            "message": f"Generated YARA rule: {rule_name}.yara"
        }

    except Exception as e:
        print(f"[ERROR] generate_yara_rule: {e}")
        return None