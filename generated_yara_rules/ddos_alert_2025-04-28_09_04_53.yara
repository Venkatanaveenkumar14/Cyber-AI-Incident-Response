
rule ddos_alert_2025-04-28_09_04_53
{
    meta:
        description = "Auto-generated DDoS detection rule"
        confidence = "0.2892"
    strings:
        $ddos = "ddos"
    condition:
        $ddos
}
