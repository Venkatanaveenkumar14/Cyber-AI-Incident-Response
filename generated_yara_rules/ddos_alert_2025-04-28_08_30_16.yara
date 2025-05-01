
rule ddos_alert_2025-04-28_08_30_16
{
    meta:
        description = "Auto-generated DDoS detection rule"
        confidence = "0.329"
    strings:
        $ddos = "ddos"
    condition:
        $ddos
}
