#!/usr/bin/env python3
# run_epc.py — bring up the FULL EPC (CUPS gateways + access/core network) as separate
# OS processes and drive an end-to-end EPS attach / data / detach.
#
# Processes (all loopback, real UDP):
#    UE  127.0.0.10 ──Uu── eNB 127.0.0.11 ──S1-MME── MME 127.0.0.12
#                                            │  S6a        │ S11
#                                            ▼             ▼
#                                          HSS 127.0.0.13  SGW-C 127.0.0.4 ──Sxa── SGW-U 127.0.0.2
#                                                          PGW-C 127.0.0.5 ──Sxb── PGW-U 127.0.0.3
#                                            PGW-C ──Gx── PCRF 127.0.0.14
#                                          SGW-U ──S1-U── eNB,  SGW-U ──S5-U── PGW-U ──SGi── PDN 127.0.0.15
#
#   python3 run_epc.py              # up -> attach -> data -> detach -> down
#   python3 run_epc.py --keep       # stay up (Ctrl-C to stop)
#   python3 run_epc.py --seconds 30
import argparse
import os
import subprocess
import sys
import threading
import time

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE)
from network.udp_client import UDPClient

PY = sys.executable

# name, script, env
NODES = [
    ("PDN",   "core/pdn.py",        {"PDN_CTL_PORT": "8914"}),
    ("SGW-U", "core/sgw_u.py",      {"UPF_CTL_PORT": "8907", "UPF_GTPU_PORT": "2152"}),
    ("PGW-U", "core/pgw_u.py",      {"UPF_CTL_PORT": "8908", "UPF_GTPU_PORT": "2152",
                                     "UPF_SGI_PORT": "2153"}),
    ("HSS",   "core/hss.py",        {"HSS_CTL_PORT": "8912"}),
    ("PCRF",  "core/pcrf.py",       {"PCRF_CTL_PORT": "8913"}),
    ("SGW-C", "core/epc_sgw_c.py",  {"CPF_CTL_PORT": "8905"}),
    ("PGW-C", "core/epc_pgw_c.py",  {"CPF_CTL_PORT": "8906"}),
    ("MME",   "core/mme.py",        {"MME_CTL_PORT": "8910"}),
    ("eNB",   "core/enb.py",        {"ENB_CTL_PORT": "8911"}),
    ("UE",    "core/ue.py",         {"UE_CTL_PORT": "8909"}),
]
UE_CTL = ("127.0.0.10", 8909)
SGWU_CTL = ("127.0.0.2", 8907)
PGWU_CTL = ("127.0.0.3", 8908)

_PRINT_LOCK = threading.Lock()


def emit(node, line):
    with _PRINT_LOCK:
        print("[%-5s] %s" % (node, line.rstrip()), flush=True)


def reader(node, pipe):
    try:
        for line in iter(pipe.readline, ""):
            emit(node, line)
    finally:
        pipe.close()


def banner(t):
    print("\n" + "=" * 78 + "\n" + t + "\n" + "=" * 78, flush=True)


def ctl(target, cmd, timeout=5.0):
    ip, port = target
    c = UDPClient()
    try:
        rep, _ = c.request(cmd.encode(), ip, port, timeout)
    finally:
        c.close()
    return rep.decode().strip() if rep else "<no response>"


def start_nodes(procs):
    for name, script, env in NODES:
        e = dict(os.environ)
        e.update(env)
        e["PYTHONUNBUFFERED"] = "1"
        p = subprocess.Popen([PY, script], cwd=BASE, env=e, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, text=True, bufsize=1)
        procs[name] = p
        threading.Thread(target=reader, args=(name, p.stdout), daemon=True).start()
        time.sleep(0.25)


def wait_ue_state(state, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        s = ctl(UE_CTL, "STATUS", 2.0)
        if ("state=%s" % state) in s:
            return s
        time.sleep(0.3)
    return ctl(UE_CTL, "STATUS", 2.0)


def run_demo():
    banner("EPS attach  (UE -> eNB -> MME <-> HSS ; MME <-> SGW-C <-> PGW-C <-> PCRF ; PFCP -> UPFs)")
    print("  UE:", ctl(UE_CTL, "ATTACH"), flush=True)
    s = wait_ue_state("ATTACHED", 12.0)
    print("  UE:", s, flush=True)
    banner("User plane  (UE -> eNB -> SGW-U -> PGW-U -> PDN, echoed back)")
    print("  UE:", ctl(UE_CTL, "UL UL-DATA-1"), flush=True)
    time.sleep(0.6)
    print("  SGW-U GTP-U:", ctl(SGWU_CTL, "GTPSTAT"), flush=True)
    print("  PGW-U GTP-U:", ctl(PGWU_CTL, "GTPSTAT"), flush=True)
    print("  UE:", ctl(UE_CTL, "STATUS"), flush=True)
    banner("EPS detach  (S11 Delete Session + S1 UE Context Release)")
    print("  UE:", ctl(UE_CTL, "DETACH"), flush=True)
    time.sleep(0.8)
    print("  UE:", ctl(UE_CTL, "STATUS"), flush=True)


def main(argv):
    ap = argparse.ArgumentParser(description="Full EPC stack bring-up")
    ap.add_argument("--keep", action="store_true")
    ap.add_argument("--seconds", type=float, default=0.0)
    ap.add_argument("--no-demo", action="store_true")
    ap.add_argument("--web", type=int, default=8080,
                    help="serve the live state dashboard on this port (0 = off)")
    a = ap.parse_args(argv)

    procs = {}
    banner("Bringing up the FULL EPC  (UE, eNB, MME, HSS, PCRF, SGW-C, PGW-C, SGW-U, PGW-U, PDN)")
    start_nodes(procs)
    time.sleep(2.0)

    dash = None
    if a.web:
        from core.webdash import Dashboard
        dash = Dashboard(host="127.0.0.1", port=a.web).start()
        banner("Live state dashboard: http://127.0.0.1:%d  (JSON: /state.json)" % a.web)

    if not a.no_demo:
        run_demo()

    try:
        if a.keep:
            banner("EPC is UP — Ctrl-C to shut down")
            while True:
                time.sleep(0.5)
        elif a.seconds:
            banner("EPC is UP for %.0fs" % a.seconds)
            deadline = time.time() + a.seconds
            while time.time() < deadline:
                time.sleep(0.5)
        else:
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        banner("Shutting down EPC")
        if dash is not None:
            dash.stop()
        for p in procs.values():
            p.terminate()
        for p in procs.values():
            try:
                p.wait(timeout=5)
            except Exception:  # noqa
                p.kill()
        print("  all nodes stopped.", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
