
rule ddos_alert_2025-04-28_08_30_15
{
    meta:
        description = "Auto-generated DDoS detection rule"
        confidence = "0.3485"
    strings:
        $ddos = "ddos"
    condition:
        $ddos
}
