#!/usr/bin/env python3
# run_stack.py — bring up the FULL CUPS stack as separate OS processes and drive it.
#
# Starts the four Sx entities as real processes talking PFCP over UDP/8805 on the
# loopback Sxa/Sxb reference points:
#
#     SGW-C 127.0.0.4  <--Sxa-->  SGW-U 127.0.0.2
#     PGW-C 127.0.0.5  <--Sxb-->  PGW-U 127.0.0.3
#
# Each engine also exposes a text control socket (CPF_CTL_PORT / UPF_CTL_PORT) so the
# supervisor can drive Sx node + session procedures end-to-end without touching the
# PFCP server's single receive loop.
#
#   python3 run_stack.py                 # up -> demo -> down
#   python3 run_stack.py --keep          # up, stay up (Ctrl-C to stop)
#   python3 run_stack.py --seconds 20    # up, demo, run 20s, down
#   python3 run_stack.py --no-demo       # up, verify associations, down
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

# name, relative script, PFCP ip, extra env
NODES = [
    ("SGW-U", "core/sgw_u.py", "127.0.0.2", {"UPF_CTL_PORT": "8907"}),
    ("PGW-U", "core/pgw_u.py", "127.0.0.3", {"UPF_CTL_PORT": "8908"}),
    ("SGW-C", "core/sgw_c.py", "127.0.0.4", {"CPF_CTL_PORT": "8905"}),
    ("PGW-C", "core/pgw_c.py", "127.0.0.5", {"CPF_CTL_PORT": "8906"}),
]
CTL = {"SGW-U": ("127.0.0.2", 8907), "PGW-U": ("127.0.0.3", 8908),
       "SGW-C": ("127.0.0.4", 8905), "PGW-C": ("127.0.0.5", 8906)}

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


def ctl(node, cmd, timeout=6.0):
    ip, port = CTL[node]
    c = UDPClient()
    try:
        rep, _ = c.request(cmd.encode(), ip, port, timeout)
    finally:
        c.close()
    return rep.decode().strip() if rep else "<no response>"


def _seids(reply):
    """Parse 'OK NAME 0xA,0xB' -> ['0xA','0xB']."""
    parts = reply.split()
    if reply.startswith("OK") and len(parts) >= 3 and parts[2] != "-":
        return parts[2].split(",")
    return []


def start_nodes(procs):
    for name, script, ip, env in NODES:
        e = dict(os.environ)
        e.update(env)
        e["PYTHONUNBUFFERED"] = "1"
        p = subprocess.Popen([PY, script], cwd=BASE, env=e, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, text=True, bufsize=1)
        procs[name] = p
        threading.Thread(target=reader, args=(name, p.stdout), daemon=True).start()
        time.sleep(0.3)  # UPFs (listed first) listen before CPFs run association_setup


def wait_ready(timeout=8.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        ok = 0
        for n in ("SGW-C", "PGW-C"):
            r = ctl(n, "STATUS", 2.0)
            if "associated=1" in r:
                ok += 1
        if ok == 2:
            return True
        time.sleep(0.3)
    return False


def show_state(title):
    banner(title)
    for n in ("SGW-U", "PGW-U", "SGW-C", "PGW-C"):
        print("  %-6s %s" % (n, ctl(n, "STATUS", 3)), flush=True)


def run_demo():
    banner("PDN session lifecycle driven across the live stack")

    print("  SGW-C ESTABLISH :", ctl("SGW-C", "ESTABLISH 10.10.0.2"), flush=True)
    print("  PGW-C ESTABLISH :", ctl("PGW-C", "ESTABLISH 10.10.0.2"), flush=True)

    s_seid = (_seids(ctl("SGW-C", "SESSIONS")) or ["-"])[0]
    p_seid = (_seids(ctl("PGW-C", "SESSIONS")) or ["-"])[0]

    # user-plane traffic through the PDR/FAR/QER/URR pipeline
    print("  SGW-U FORWARD   :", ctl("SGW-U", "FORWARD %s 5 Access" % s_seid), flush=True)
    print("  PGW-U FORWARD   :", ctl("PGW-U", "FORWARD %s 5 Core" % p_seid), flush=True)

    # usage report (periodic + 1st DL data for idle UE) -> CPF
    print("  SGW-U REPORT    :", ctl("SGW-U", "REPORT %s 0x1" % s_seid), flush=True)
    print("  SGW-U REPORT    :", ctl("SGW-U", "REPORT %s 0x40" % s_seid), flush=True)

    # session modification (add a detection rule)
    print("  SGW-C MODIFY    :", ctl("SGW-C", "MODIFY %s" % s_seid), flush=True)

    # teardown
    print("  SGW-C DELETE    :", ctl("SGW-C", "DELETE %s" % s_seid), flush=True)
    print("  PGW-C DELETE    :", ctl("PGW-C", "DELETE %s" % p_seid), flush=True)


def main(argv):
    ap = argparse.ArgumentParser(description="Full CUPS stack bring-up")
    ap.add_argument("--keep", action="store_true", help="stay up until Ctrl-C")
    ap.add_argument("--seconds", type=float, default=0.0, help="run N seconds then exit")
    ap.add_argument("--no-demo", action="store_true", help="skip the session demo")
    a = ap.parse_args(argv)

    procs = {}
    banner("Bringing up the FULL CUPS stack  (SGW-C/PGW-C/SGW-U/PGW-U, PFCP/UDP 8805)")
    start_nodes(procs)
    time.sleep(1.2)

    if wait_ready():
        banner("Sx associations UP (Sxa: SGW-C<->SGW-U,  Sxb: PGW-C<->PGW-U)")
    else:
        banner("WARNING: associations not confirmed within timeout")
    show_state("Stack state")

    if not a.no_demo:
        run_demo()
        time.sleep(0.5)
        show_state("Stack state after demo")

    try:
        if a.keep:
            banner("Stack is UP — Ctrl-C to shut down")
            while True:
                time.sleep(0.5)
        elif a.seconds:
            banner("Stack is UP for %.0fs" % a.seconds)
            deadline = time.time() + a.seconds
            while time.time() < deadline:
                time.sleep(0.5)
        else:
            time.sleep(1.0)
    except KeyboardInterrupt:
        pass
    finally:
        banner("Shutting down stack")
        for p in procs.values():
            p.terminate()
        for name, p in procs.items():
            try:
                p.wait(timeout=5)
            except Exception:  # noqa
                p.kill()
        print("  all nodes stopped.", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
