
rule ddos_alert_2025-04-28_09_25_14
{
    meta:
        description = "Auto-generated DDoS detection rule"
        confidence = "0.2435"
    strings:
        $ddos = "ddos"
    condition:
        $ddos
}
