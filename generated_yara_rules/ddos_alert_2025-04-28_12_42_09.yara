
rule ddos_alert_2025-04-28_12_42_09
{
    meta:
        description = "Auto-generated DDoS detection rule"
        confidence = "0.2564"
    strings:
        $ddos = "ddos"
    condition:
        $ddos
}
