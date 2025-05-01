
rule ddos_alert_2025-04-28_09_26_29
{
    meta:
        description = "Auto-generated DDoS detection rule"
        confidence = "0.2056"
    strings:
        $ddos = "ddos"
    condition:
        $ddos
}
