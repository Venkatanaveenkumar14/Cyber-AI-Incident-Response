
rule ddos_alert_2025-04-28_09_04_44
{
    meta:
        description = "Auto-generated DDoS detection rule"
        confidence = "0.3356"
    strings:
        $ddos = "ddos"
    condition:
        $ddos
}
