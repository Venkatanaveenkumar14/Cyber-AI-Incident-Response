
rule ddos_alert_2025-04-28_08_38_51
{
    meta:
        description = "Auto-generated DDoS detection rule"
        confidence = "0.2525"
    strings:
        $ddos = "ddos"
    condition:
        $ddos
}
