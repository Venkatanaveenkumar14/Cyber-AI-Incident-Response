
rule ddos_alert_2025-04-28_09_24_27
{
    meta:
        description = "Auto-generated DDoS detection rule"
        confidence = "0.3366"
    strings:
        $ddos = "ddos"
    condition:
        $ddos
}
