
rule ddos_alert_2025-04-28_12_41_10
{
    meta:
        description = "Auto-generated DDoS detection rule"
        confidence = "0.2435"
    strings:
        $ddos = "ddos"
    condition:
        $ddos
}
