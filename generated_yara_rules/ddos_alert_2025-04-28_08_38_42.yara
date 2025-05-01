
rule ddos_alert_2025-04-28_08_38_42
{
    meta:
        description = "Auto-generated DDoS detection rule"
        confidence = "0.2892"
    strings:
        $ddos = "ddos"
    condition:
        $ddos
}
