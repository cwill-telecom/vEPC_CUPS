#!/usr/bin/env python3
# core/pgw_u.py — M2M vPGW-U : PDN Gateway User Plane Function (UPF over Sxb).
#
# The traffic detection function (TDF) is embedded here (PGW-U/P), not a standalone node.
#
#   python3 pgw_u.py 4
import sys, os, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.upf import UPF

# ---------------------------------------------------------------- config -----
g_pgwu_ip_addr = "127.0.0.3"
g_pgwu_port    = 8805
g_pgwc_ip      = "127.0.0.5"
g_pfcp_peers   = ["127.0.0.5"]       # user-plane-service pfcp-peer-list
g_up_features  = ["TRST", "FTUP", "TREU", "EMPU"]
g_embedded_tdf = True                 # traffic detection function in PGW-U/P
# -----------------------------------------------------------------------------


def main(argv):
    upf = UPF("PGW-U", g_pgwu_ip_addr, g_pgwu_port, features=g_up_features)
    for ip in g_pfcp_peers:
        upf.add_peer(ip)
    upf.start()
    if os.environ.get("UPF_CTL_PORT"):
        upf.enable_control(int(os.environ["UPF_CTL_PORT"]))
    if os.environ.get("UPF_GTPU_PORT"):
        upf.enable_gtpu(int(os.environ["UPF_GTPU_PORT"]),
                        int(os.environ.get("UPF_SGI_PORT", "0")))
    if g_embedded_tdf:
        print("PGW-U: embedded traffic detection function (TDF) active")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        upf.stop()


if __name__ == "__main__":
    main(sys.argv[1:])
