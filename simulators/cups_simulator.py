#!/usr/bin/env python3
# simulators/cups_simulator.py — end-to-end CUPS/PFCP scenario driver.
#
# Spins up the split gateways (CPF + UPF) in-process on distinct loopback IPs and walks
# the CUPS flows described in the design document:
#
#   1. Sx Association Setup (CPF <-> UPF)                    [node procedure]
#   2. Sx Session Establishment for a PDN connection         [attach]
#   3. User-plane traffic through the PDR/FAR/QER/URR rules
#   4. Sx Session Report (periodic usage + 1st DL data)      [reporting]
#   5. Sx Session Modification (add a detection rule)
#   6. Sx Session Deletion                                    [detach]
#   7. PFD Management (SDCI) for an Application ID            [node procedure]
#   8. Sx Association Update/Release (user-plane admin-down)
#
#   python3 simulators/cups_simulator.py [run_seconds]
import sys, os, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.upf import UPF
from core.cpf import CPF
from sxcups.rules import PDR
from sxcups import reporting
from utils.utils import log

# ---- loopback addressing (distinct 127.0.0.0/8 hosts) ------------------------
SGWC_IP, PGWC_IP = "127.0.0.4", "127.0.0.5"
SGWU_IP, PGWU_IP = "127.0.0.2", "127.0.0.3"
PFCP = 8805


def banner(t):
    log("=" * 68)
    log(t)
    log("=" * 68)


def main(argv):
    banner("Bringing up CUPS split gateways")
    sgw_u = UPF("SGW-U", SGWU_IP, PFCP); sgw_u.add_peer(SGWC_IP); sgw_u.start()
    pgw_u = UPF("PGW-U", PGWU_IP, PFCP); pgw_u.add_peer(PGWC_IP); pgw_u.start()
    sgw_c = CPF("SGW-C", SGWC_IP, PFCP, base_seid=0x1000); sgw_c.add_peer(SGWU_IP); sgw_c.start()
    pgw_c = CPF("PGW-C", PGWC_IP, PFCP, base_seid=0x2000); pgw_c.add_peer(PGWU_IP); pgw_c.start()
    time.sleep(0.3)

    # 1) Sx Association Setup --------------------------------------------------
    banner("1. Sx Association Setup (Sxa: SGW-C<->SGW-U, Sxb: PGW-C<->PGW-U)")
    sgw_c.association_setup(sgw_c.peers[SGWU_IP])
    pgw_c.association_setup(pgw_c.peers[PGWU_IP])

    # 2) Session establishment (PDN connection) --------------------------------
    banner("2. Sx Session Establishment (PDN connection)")
    s_sgw = sgw_c.session_establish(sgw_c.peers[SGWU_IP], kind="PDN", ue_ip="10.10.0.2")
    s_pgw = pgw_c.session_establish(pgw_c.peers[PGWU_IP], kind="PDN", ue_ip="10.10.0.2")

    # 3) User-plane traffic ----------------------------------------------------
    banner("3. User-plane traffic through PDR/FAR/QER/URR")
    for i in range(5):
        a_ul, n_ul = sgw_u.forward(s_sgw.seid, b"UL-DATA-%02d" % i, "Access")
        a_dl, n_dl = pgw_u.forward(s_pgw.seid, b"DL-DATA-%02d" % i, "Core")
    log("SGW-U uplink  : %d pkts %dB -> %s" %
        (5, sgw_u.store.get(s_sgw.seid).usage["uplink"], "/".join(a_ul)))
    log("PGW-U downlink: %d pkts %dB -> %s" %
        (5, pgw_u.store.get(s_pgw.seid).usage["downlink"], "/".join(a_dl)))

    # 4) Reports ---------------------------------------------------------------
    banner("4. Sx Session Report (periodic usage + 1st DL data for idle UE)")
    sgw_u.report(s_sgw.seid, reporting.TRIG_PERIODIC, urr_id=1,
                 volume=(s_sgw.usage["uplink"] + s_sgw.usage["downlink"],
                         s_sgw.usage["uplink"], s_sgw.usage["downlink"]))
    sgw_u.report(s_sgw.seid, reporting.TRIG_FIRST_DL_DATA, pdr_id=2)

    # 5) Modification ----------------------------------------------------------
    banner("5. Sx Session Modification (add a new detection rule)")
    new_pdr = PDR(9, precedence=50, source_interface="Access", far_id=1, urr_ids=[1])
    sgw_c.session_modify(s_sgw.seid, add_pdrs=[new_pdr])

    # 6) Deletion --------------------------------------------------------------
    banner("6. Sx Session Deletion")
    sgw_c.session_delete(s_sgw.seid)
    pgw_c.session_delete(s_pgw.seid)

    # 7) PFD management (SDCI) -------------------------------------------------
    banner("7. Sx PFD Management for Application ID 'com.example.app'")
    pgw_c.pfd_management(pgw_c.peers[PGWU_IP], "com.example.app",
                         [("example.com", "tcp", "80-443")])

    # 8) Admin-down -> Association Update -> Release ---------------------------
    banner("8. User-plane-service admin-down (Association Update + Release)")
    sgw_u.set_admin_state("DOWN")
    time.sleep(1.0)

    banner("Scenario complete — current Sx sessions")
    for name, cpf in (("SGW-C", sgw_c), ("PGW-C", pgw_c)):
        log("%s: %d Sx connections" % (name, len(cpf.store.sessions)))

    for node in (sgw_c, pgw_c, sgw_u, pgw_u):
        node.stop()
    log("All nodes stopped.")


if __name__ == "__main__":
    main(sys.argv[1:])
