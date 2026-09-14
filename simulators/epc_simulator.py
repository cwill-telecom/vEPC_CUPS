#!/usr/bin/env python3
# simulators/epc_simulator.py — end-to-end EPC scenario in a single process.
#
# Brings up every node in-process (still over real UDP loopback sockets) and walks the
# full EPS procedure: UE attach -> authentication (S6a) -> security mode -> S11/S5-C
# session establishment (+ Gx policy + PFCP to the UPFs) -> S1-U setup -> user-plane
# uplink/downlink over GTP-U -> detach.
#
#   python3 simulators/epc_simulator.py
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.pdn import PDN
from core.upf import UPF
from core.hss import HSS
from core.pcrf import PCRF
from core.epc_sgw_c import SGW_C
from core.epc_pgw_c import PGW_C
from core.mme import MME
from core.enb import ENB
from core.ue import UE
from utils.utils import log


def banner(t):
    log("=" * 70)
    log(t)
    log("=" * 70)


def main(argv):
    banner("Bringing up the full EPC (in-process, real UDP loopback sockets)")
    pdn = PDN()
    sgw_u = UPF("SGW-U", "127.0.0.2", 8805); sgw_u.add_peer("127.0.0.4")
    pgw_u = UPF("PGW-U", "127.0.0.3", 8805); pgw_u.add_peer("127.0.0.5")
    hss = HSS()
    pcrf = PCRF()
    sgw_c = SGW_C()
    pgw_c = PGW_C()
    mme = MME()
    enb = ENB()
    ue = UE()
    for n in (pdn, hss, pcrf):
        n.start()
    sgw_u.enable_control(8907); sgw_u.enable_gtpu(2152); sgw_u.start()
    pgw_u.enable_control(8908); pgw_u.enable_gtpu(2152, 2153); pgw_u.start()
    sgw_c.start(); pgw_c.start(); mme.start(); enb.start(); ue.start()
    time.sleep(0.5)

    banner("1. UE attach (UE -> eNB -> MME <-> HSS)")
    ue.attach()
    if not ue.done.wait(10):
        banner("attach did not complete in time")
    else:
        log("UE attached: IP=%s EBI=%s" % (ue.assigned_ip, ue.ebi))

    banner("2. User plane over GTP-U (UE -> eNB -> SGW-U -> PGW-U -> PDN and back)")
    ue.send_ul("UL-DATA-1"); time.sleep(0.4)
    ue.send_ul("UL-DATA-2"); time.sleep(0.4)
    log("UE received %d downlink packet(s); SGW-U GTP-U stats: %s"
        % (len(ue.rx_data), sgw_u.gtpu.stats))

    banner("3. Detach (S11 Delete Session + S1 UE Context Release)")
    ue.detach(); time.sleep(0.5)

    banner("Scenario complete")
    for n in (sgw_c, pgw_c, mme, enb, ue, sgw_u, pgw_u, hss, pcrf, pdn):
        try:
            n.stop()
        except Exception:  # noqa
            pass
    log("All nodes stopped.")


if __name__ == "__main__":
    main(sys.argv[1:])
