
rule ddos_alert_2025-04-28_08_59_02
{
    meta:
        description = "Auto-generated DDoS detection rule"
        confidence = "0.2915"
    strings:
        $ddos = "ddos"
    condition:
        $ddos
}
