# core/gtpu.py — a small GTP-U relay used by the EPC nodes (S1-U / S5-U / SGi).
#
# This is the *user-plane forwarding* companion to the control plane. Each node owns a
# TEID->next-hop table; the CPF-programmed sessions (reused from the CUPS layer) decide
# the rules, while this relay performs the actual encapsulation/decapsulation:
#
#   eNB        --(GTP-U, SGW S1-U TEID)--> SGW-U
#   SGW-U      --(GTP-U, PGW S5-U TEID)--> PGW-U
#   PGW-U      --(raw IP,        SGi)   --> PDN
#
# A node with an SGi socket (PGW-U) also encapsulates raw downlink from the PDN back
# toward the SGW-U using the downlink TEID.
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from network.udp_server import UDPServer
from protocols import gtp
from utils.utils import log, dbg


class GTPUNode:
    def __init__(self, ip, port=2152, name="GTP-U", sgi_port=0):
        self.ip = ip
        self.port = port
        self.name = name
        self.routes = {}                 # in_teid -> {"kind","ip","port","teid"}
        self.stats = {}                  # in_teid -> [pkts, bytes]
        self.sgi_uplink = None           # (next_ip, next_port, dl_teid) for raw SGi -> GTP
        self.server = UDPServer(ip, port, self.handle, name=name)
        self.sgi = UDPServer(ip, sgi_port, self.handle_sgi, name=name + "-sgi") if sgi_port else None

    def start(self):
        self.server.start()
        if self.sgi:
            self.sgi.start()
        log("%s: GTP-U relay on %s:%d%s" % (
            self.name, self.ip, self.port, " (SGi:%d)" % self.sgi.port if self.sgi else ""))

    def stop(self):
        self.server.stop()
        if self.sgi:
            self.sgi.stop()

    # ------------------------------------------------------------- config ----
    def add_route(self, in_teid, next_ip, next_port, out_teid=None, egress=False):
        self.routes[in_teid] = {"kind": "egress" if egress else "fwd",
                                "ip": next_ip, "port": next_port, "teid": out_teid}

    def set_sgi_uplink(self, next_ip, next_port, dl_teid):
        """Raw SGi downlink (from the PDN) gets encapsulated toward `next` with `dl_teid`."""
        self.sgi_uplink = (next_ip, next_port, dl_teid)

    def send_gtpu(self, teid, dst_ip, dst_port, payload):
        self.server.send(gtp.encode_gpdu(teid, payload), (dst_ip, dst_port))

    # ------------------------------------------------------------ rx paths ---
    def handle(self, data, addr):
        try:
            g = gtp.decode(data)
        except Exception:  # noqa
            dbg("%s: bad GTP-U from %s" % (self.name, addr))
            return None
        if g["type"] != gtp.G_PDU:
            return None
        teid, payload = g["teid"], g["payload"]
        st = self.stats.setdefault(teid, [0, 0])
        st[0] += 1
        st[1] += len(payload)
        r = self.routes.get(teid)
        if r is None:
            dbg("%s: no route for TEID 0x%X (from %s)" % (self.name, teid, addr[0]))
            return None
        if r["kind"] == "egress":
            sock = self.sgi or self.server      # raw egress: SGi socket if present, else direct
            sock.send(payload, (r["ip"], r["port"]))
        else:
            self.server.send(gtp.encode_gpdu(r["teid"], payload), (r["ip"], r["port"]))
        return None

    def handle_sgi(self, data, addr):
        """Raw downlink from the PDN; encapsulate toward the SGW with the DL TEID."""
        if self.sgi_uplink is None:
            return None
        ip, port, teid = self.sgi_uplink
        self.server.send(gtp.encode_gpdu(teid, data), (ip, port))
        return None
