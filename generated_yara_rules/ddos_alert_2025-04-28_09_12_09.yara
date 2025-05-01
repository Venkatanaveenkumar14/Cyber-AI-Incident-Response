
rule ddos_alert_2025-04-28_09_12_09
{
    meta:
        description = "Auto-generated DDoS detection rule"
        confidence = "0.3269"
    strings:
        $ddos = "ddos"
    condition:
        $ddos
}
