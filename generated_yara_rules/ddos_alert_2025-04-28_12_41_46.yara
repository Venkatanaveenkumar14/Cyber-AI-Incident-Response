
rule ddos_alert_2025-04-28_12_41_46
{
    meta:
        description = "Auto-generated DDoS detection rule"
        confidence = "0.3485"
    strings:
        $ddos = "ddos"
    condition:
        $ddos
}
