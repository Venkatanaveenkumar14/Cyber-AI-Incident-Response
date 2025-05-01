
rule ddos_alert_2025-04-28_09_23_39
{
    meta:
        description = "Auto-generated DDoS detection rule"
        confidence = "0.2915"
    strings:
        $ddos = "ddos"
    condition:
        $ddos
}
