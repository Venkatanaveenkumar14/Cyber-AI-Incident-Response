
rule ddos_alert_2025-04-28_08_30_03
{
    meta:
        description = "Auto-generated DDoS detection rule"
        confidence = "0.2544"
    strings:
        $ddos = "ddos"
    condition:
        $ddos
}
