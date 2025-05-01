
rule ddos_alert_2025-04-28_08_38_37
{
    meta:
        description = "Auto-generated DDoS detection rule"
        confidence = "0.3356"
    strings:
        $ddos = "ddos"
    condition:
        $ddos
}
