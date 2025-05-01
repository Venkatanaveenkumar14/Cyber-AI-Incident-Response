
rule ddos_alert_2025-04-28_09_05_54
{
    meta:
        description = "Auto-generated DDoS detection rule"
        confidence = "0.2435"
    strings:
        $ddos = "ddos"
    condition:
        $ddos
}
