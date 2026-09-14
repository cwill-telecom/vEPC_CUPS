# cups/session.py — Sx session context store (per PDN connection / IP-CAN session).
#
# A "Sx session" may correspond to an individual PDN connection or be a standalone
# session not tied to any PDN connection (e.g. forwarding DHCP/RADIUS/DIAMETER
# signalling between the PGW-C and the PDN over SGi).
import itertools
from sxcups.rules import PDR, FAR, QER, URR

_session_seq = itertools.count(1)


class Session:
    def __init__(self, seid, cp_ip, up_ip, kind="PDN"):
        self.seid = seid
        self.cp_fseid = (seid, cp_ip)
        self.up_fseid = (seid, up_ip)
        self.kind = kind                    # "PDN" | "IP-CAN" | "standalone"
        self.pdrs = {}                      # pdr_id -> PDR
        self.fars = {}
        self.qers = {}
        self.urrs = {}
        self.buffered = []                  # DL packets buffered in the UPF
        self.usage = {"uplink": 0, "downlink": 0}
        self.state = "ESTABLISHED"

    # ------------------------------------------------------------ rules ----
    def add_rules(self, pdrs=(), fars=(), qers=(), urrs=()):
        for r in fars: self.fars[r.far_id] = r
        for r in qers: self.qers[r.qer_id] = r
        for r in urrs: self.urrs[r.urr_id] = r
        for r in pdrs: self.pdrs[r.pdr_id] = r

    def remove(self, pdr_ids=(), far_ids=(), qer_ids=(), urr_ids=()):
        for i in pdr_ids: self.pdrs.pop(i, None)
        for i in far_ids: self.fars.pop(i, None)
        for i in qer_ids: self.qers.pop(i, None)
        for i in urr_ids: self.urrs.pop(i, None)

    # ------------------------------------------------- packet pipeline ----
    def classify(self, direction):
        """Return the matching PDR for a packet direction (Access/Core)."""
        best = None
        for pdr in self.pdrs.values():
            if pdr.source_interface == direction:
                if best is None or pdr.precedence < best.precedence:
                    best = pdr
        return best

    def apply(self, payload, direction):
        """Run inspect -> FAR action -> URR accounting. Returns (action, bytes)."""
        pdr = self.classify(direction)
        if pdr is None:
            return ["DROP"], 0
        far = self.fars.get(pdr.far_id)
        action = far.apply_action if far else ["DROP"]
        n = len(payload)
        if direction == "Access":
            self.usage["uplink"] += n
        else:
            self.usage["downlink"] += n
        if "BUFFER" in action and direction == "Core":
            self.buffered.append(payload)
        return action, n

    def summary(self):
        return {
            "seid": self.seid, "kind": self.kind, "state": self.state,
            "pdrs": list(self.pdrs), "fars": list(self.fars),
            "qers": list(self.qers), "urrs": list(self.urrs),
            "usage": dict(self.usage), "buffered": len(self.buffered),
        }


class SessionStore:
    def __init__(self):
        self.sessions = {}                  # seid -> Session

    def new_seid(self, base):
        return (base << 20) | (next(_session_seq) & 0xFFFFF)

    def create(self, seid, cp_ip, up_ip, kind="PDN"):
        s = Session(seid, cp_ip, up_ip, kind)
        self.sessions[seid] = s
        return s

    def get(self, seid):
        return self.sessions.get(seid)

    def delete(self, seid):
        return self.sessions.pop(seid, None)
