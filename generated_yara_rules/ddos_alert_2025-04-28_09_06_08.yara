
rule ddos_alert_2025-04-28_09_06_08
{
    meta:
        description = "Auto-generated DDoS detection rule"
        confidence = "0.2391"
    strings:
        $ddos = "ddos"
    condition:
        $ddos
}
