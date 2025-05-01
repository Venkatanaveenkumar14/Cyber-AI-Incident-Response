
rule ddos_alert_2025-04-28_12_41_57
{
    meta:
        description = "Auto-generated DDoS detection rule"
        confidence = "0.2453"
    strings:
        $ddos = "ddos"
    condition:
        $ddos
}
