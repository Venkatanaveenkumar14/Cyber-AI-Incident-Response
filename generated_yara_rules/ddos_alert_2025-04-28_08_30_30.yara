
rule ddos_alert_2025-04-28_08_30_30
{
    meta:
        description = "Auto-generated DDoS detection rule"
        confidence = "0.2098"
    strings:
        $ddos = "ddos"
    condition:
        $ddos
}
