
rule ddos_alert_2025-04-28_09_26_06
{
    meta:
        description = "Auto-generated DDoS detection rule"
        confidence = "0.21"
    strings:
        $ddos = "ddos"
    condition:
        $ddos
}
