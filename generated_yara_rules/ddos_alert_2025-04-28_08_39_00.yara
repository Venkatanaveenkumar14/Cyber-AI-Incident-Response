
rule ddos_alert_2025-04-28_08_39_00
{
    meta:
        description = "Auto-generated DDoS detection rule"
        confidence = "0.2544"
    strings:
        $ddos = "ddos"
    condition:
        $ddos
}
