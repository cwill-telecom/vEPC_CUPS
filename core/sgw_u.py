#!/usr/bin/env python3
# core/sgw_u.py — M2M vSGW-U : Serving Gateway User Plane Function (UPF over Sxa).
#
#   python3 sgw_u.py 4
import sys, os, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.upf import UPF

# ---------------------------------------------------------------- config -----
g_sgwu_ip_addr = "127.0.0.2"
g_sgwu_port    = 8805
g_sgwc_ip      = "127.0.0.4"        # CPF that controls us
g_pfcp_peers   = ["127.0.0.4"]      # user-plane-service pfcp-peer-list
g_up_features  = ["TRST", "FTUP", "TREU", "EMPU"]
# -----------------------------------------------------------------------------


def main(argv):
    upf = UPF("SGW-U", g_sgwu_ip_addr, g_sgwu_port, features=g_up_features)
    for ip in g_pfcp_peers:
        upf.add_peer(ip)
    upf.start()
    if os.environ.get("UPF_CTL_PORT"):
        upf.enable_control(int(os.environ["UPF_CTL_PORT"]))
    if os.environ.get("UPF_GTPU_PORT"):
        upf.enable_gtpu(int(os.environ["UPF_GTPU_PORT"]),
                        int(os.environ.get("UPF_SGI_PORT", "0")))
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        upf.stop()


if __name__ == "__main__":
    main(sys.argv[1:])
