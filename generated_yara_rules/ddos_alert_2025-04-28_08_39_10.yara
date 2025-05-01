
rule ddos_alert_2025-04-28_08_39_10
{
    meta:
        description = "Auto-generated DDoS detection rule"
        confidence = "0.1994"
    strings:
        $ddos = "ddos"
    condition:
        $ddos
}
