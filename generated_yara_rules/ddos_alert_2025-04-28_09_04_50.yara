
rule ddos_alert_2025-04-28_09_04_50
{
    meta:
        description = "Auto-generated DDoS detection rule"
        confidence = "0.3366"
    strings:
        $ddos = "ddos"
    condition:
        $ddos
}
