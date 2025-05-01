
rule ddos_alert_2025-04-28_08_39_05
{
    meta:
        description = "Auto-generated DDoS detection rule"
        confidence = "0.2304"
    strings:
        $ddos = "ddos"
    condition:
        $ddos
}
