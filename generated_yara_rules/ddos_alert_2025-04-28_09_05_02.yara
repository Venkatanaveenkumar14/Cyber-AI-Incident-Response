
rule ddos_alert_2025-04-28_09_05_02
{
    meta:
        description = "Auto-generated DDoS detection rule"
        confidence = "0.3269"
    strings:
        $ddos = "ddos"
    condition:
        $ddos
}
