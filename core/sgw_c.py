#!/usr/bin/env python3
# core/sgw_c.py — M2M vSGW-C : Serving Gateway Control Plane Function (CPF over Sxa).
#
#   python3 sgw_c.py 4            # 4 worker/heartbeat threads not required; kept for parity
import sys, os, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.cpf import CPF

# ---------------------------------------------------------------- config -----
g_sgwc_ip_addr = "127.0.0.4"
g_sgwc_port    = 8805          # standard PFCP destination port
g_sgw_u_ip     = "127.0.0.2"   # the SGW-U this CPF controls (Sxa)
g_sxa_peers    = ["127.0.0.2"] # sxa-pfcp-peer-list
# -----------------------------------------------------------------------------


def main(argv):
    cpf = CPF("SGW-C", g_sgwc_ip_addr, g_sgwc_port, base_seid=0x1000)
    for ip in g_sxa_peers:
        cpf.add_peer(ip)
    cpf.start()
    if os.environ.get("CPF_CTL_PORT"):
        cpf.enable_control(int(os.environ["CPF_CTL_PORT"]))
    for peer in list(cpf.peers.values()):
        cpf.association_setup(peer)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        cpf.stop()


if __name__ == "__main__":
    main(sys.argv[1:])
