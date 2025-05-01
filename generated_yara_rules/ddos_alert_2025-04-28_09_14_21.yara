
rule ddos_alert_2025-04-28_09_14_21
{
    meta:
        description = "Auto-generated DDoS detection rule"
        confidence = "0.2391"
    strings:
        $ddos = "ddos"
    condition:
        $ddos
}
