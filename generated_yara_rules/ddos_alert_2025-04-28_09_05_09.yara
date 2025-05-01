
rule ddos_alert_2025-04-28_09_05_09
{
    meta:
        description = "Auto-generated DDoS detection rule"
        confidence = "0.2414"
    strings:
        $ddos = "ddos"
    condition:
        $ddos
}
