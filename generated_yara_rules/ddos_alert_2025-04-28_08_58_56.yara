
rule ddos_alert_2025-04-28_08_58_56
{
    meta:
        description = "Auto-generated DDoS detection rule"
        confidence = "0.3269"
    strings:
        $ddos = "ddos"
    condition:
        $ddos
}
