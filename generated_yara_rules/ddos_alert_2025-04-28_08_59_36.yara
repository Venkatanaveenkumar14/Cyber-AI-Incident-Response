
rule ddos_alert_2025-04-28_08_59_36
{
    meta:
        description = "Auto-generated DDoS detection rule"
        confidence = "0.2414"
    strings:
        $ddos = "ddos"
    condition:
        $ddos
}
