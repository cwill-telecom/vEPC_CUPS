#!/usr/bin/env python3
# core/pdn.py — external Packet Data Network behind the PGW-U SGi interface.
#
# Receives raw IP payloads from the PGW-U and (for the demo) echoes them back so the
# downlink path (SGi -> PGW-U -> SGW-U -> eNB -> UE) is exercised.
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from network.udp_server import UDPServer
from utils.utils import log

# ---------------------------------------------------------------- config -----
PDN_IP   = "127.0.0.15"
PDN_PORT = 9999
# -----------------------------------------------------------------------------


class PDN:
    def __init__(self, ip=PDN_IP, port=PDN_PORT, echo=True):
        self.ip = ip
        self.port = port
        self.echo = echo
        self.server = UDPServer(ip, port, self.handle, name="PDN")
        self.rx = 0

    def start(self):
        self.server.start()
        log("PDN (external packet network) listening on %s:%d%s"
            % (self.ip, self.port, " [echo]" if self.echo else ""))

    def stop(self):
        self.server.stop()
        if getattr(self, "ctl", None):
            self.ctl.stop()

    def handle(self, data, addr):
        self.rx += 1
        log("PDN: received %dB from %s: %r" % (len(data), addr[0], data[:32]))
        if self.echo and data.startswith(b"UL"):
            return b"DL-ACK:" + data
        return None

    # ------------------------------------------------------------ control ---
    def enable_control(self, port):
        self.ctl = UDPServer(self.ip, port, self._ctl_handle, name="PDN-ctl")
        self.ctl.start()
        log("PDN: control socket on %s:%d" % (self.ip, port))

    def _ctl_handle(self, data, addr):
        parts = data.decode(errors="ignore").split()
        cmd = parts[0].upper() if parts else ""
        if cmd == "STATUS":
            reply = "OK PDN rx=%d" % self.rx
        else:
            reply = "ERR unknown %r" % cmd
        return (reply + "\n").encode()


def main(argv):
    pdn = PDN()
    pdn.start()
    if os.environ.get("PDN_CTL_PORT"):
        pdn.enable_control(int(os.environ["PDN_CTL_PORT"]))
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pdn.stop()


if __name__ == "__main__":
    main(sys.argv[1:])
