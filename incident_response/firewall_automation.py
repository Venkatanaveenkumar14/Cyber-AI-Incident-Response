#Future code for firewall automation
# import subprocess
# import logging
# import os

# def block_ip(ip_address: str):
#     firewall_mode = os.environ.get('FIREWALL_MODE', 'simulate')
#     if firewall_mode == "simulate":
#         logging.info(f"[SIMULATION] Would block IP: {ip_address}")
#         return

#     try:
#         cmd = ["sudo", "iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"]
#         subprocess.run(cmd, check=True)
#         logging.info(f"[ENFORCE] Blocked IP using IPTables: {ip_address}")
#     except subprocess.CalledProcessError as e:
#         logging.error(f"[ERROR] Failed to block IP {ip_address}: {e}")