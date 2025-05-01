
rule ddos_alert_2025-04-28_12_41_55
{
    meta:
        description = "Auto-generated DDoS detection rule"
        confidence = "0.2304"
    strings:
        $ddos = "ddos"
    condition:
        $ddos
}
