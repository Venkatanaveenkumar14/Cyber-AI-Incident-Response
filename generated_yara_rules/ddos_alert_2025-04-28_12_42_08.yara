
rule ddos_alert_2025-04-28_12_42_08
{
    meta:
        description = "Auto-generated DDoS detection rule"
        confidence = "0.2124"
    strings:
        $ddos = "ddos"
    condition:
        $ddos
}
