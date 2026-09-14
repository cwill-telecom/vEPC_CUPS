#!/usr/bin/env python3
# core/pgw_c.py — M2M vPGW-C : PDN Gateway Control Plane Function (CPF over Sxb).
#
#   python3 pgw_c.py 4
import sys, os, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.cpf import CPF

# ---------------------------------------------------------------- config -----
g_pgwc_ip_addr = "127.0.0.5"
g_pgwc_port    = 8805
g_pgw_u_ip     = "127.0.0.3"   # the PGW-U this CPF controls (Sxb)
g_sxb_peers    = ["127.0.0.3"] # sxb-pfcp-peer-list
# -----------------------------------------------------------------------------


def main(argv):
    cpf = CPF("PGW-C", g_pgwc_ip_addr, g_pgwc_port, base_seid=0x2000)
    for ip in g_sxb_peers:
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
