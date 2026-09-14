# core/cpf.py — shared Control Plane Function engine (CPF).
#
# Terminates the control-plane protocols (GTP-C, Diameter Gx/Gy/Gz) and drives the
# user plane over Sxa/Sxb using PFCP. One CPF interfaces multiple UPF nodes; a UPF may
# be shared by multiple CPFs. Subclassed by sgw_c.py (Sxa) and pgw_c.py (Sxb).
import threading
import time
from network.udp_server import UDPServer
from protocols import pfcp
from sxcups.session import SessionStore
from sxcups.rules import PDR, FAR, QER, URR
from sxcups import reporting
from utils.utils import log, dbg, trace, PeriodicTimer, DEFAULT_RECOVERY_TS


def _created_pdr_info(value):
    """Return (pdr_id, (teid, ip)) from a Created PDR grouped IE."""
    pid = fteid = None
    for t, v, kids in pfcp.decode_ies_recursive(value):
        if pfcp._IE_NAME.get(t) == "PDR ID":
            pid = pfcp.pdr_id_of(v)
        for ct, cv, _ in kids:
            if pfcp._IE_NAME.get(ct) == "F-TEID":
                fteid = pfcp.decode_ft_eid(cv)
    return pid, fteid


class Peer:
    """State for one remote PFCP peer (a UPF)."""
    def __init__(self, ip, port=pfcp.__dict__.get("PFCP_PORT", 8805)):
        self.ip = ip
        self.port = 8805
        self.node_id = None
        self.associated = False
        self.last_seen = 0.0
        self.guard_interval = 0
        self.up_features = []


class CPF:
    def __init__(self, name, ip, port=8805, heartbeat=5, guard_interval=10,
                 base_seid=0x1000):
        self.name = name
        self.ip = ip
        self.port = port
        self.recovery_ts = DEFAULT_RECOVERY_TS
        self.heartbeat = heartbeat                 # pfcp-heartbeat-periodic-interval
        self.guard_interval = guard_interval       # pfcp-guard-time-interval
        self.base_seid = base_seid
        self.peers = {}
        self.store = SessionStore()
        self.seq = 0
        self.pending = {}                          # seq -> [Event, Message]
        self.lock = threading.Lock()
        self.server = UDPServer(ip, port, self.handle, name=name)
        self.timers = []

    # ------------------------------------------------------------ plumbing --
    def _next_seq(self):
        with self.lock:
            self.seq = (self.seq + 1) & 0xFFFFFF
            return self.seq

    def start(self):
        self.server.start()
        t = PeriodicTimer(self.heartbeat, self._heartbeat_loop, name=self.name + "-hb")
        t.start(); self.timers.append(t)
        log("%s (CPF) listening on %s:%d" % (self.name, self.ip, self.port))

    def stop(self):
        for t in self.timers: t.stop()
        self.server.stop()
        if getattr(self, "ctl", None):
            self.ctl.stop()

    def add_peer(self, ip, port=8805):
        """Configure a pfcp-peer (zone default gateway pfcp-peer)."""
        self.peers[ip] = Peer(ip, port)
        dbg("%s: configured pfcp-peer %s:%d" % (self.name, ip, port))
        return self.peers[ip]

    def _send(self, msg, peer):
        m = pfcp.Message(msg.msg_type, seid=msg.seid, seq=self._next_seq(),
                         ies=msg.ies, has_seid=msg.has_seid)
        # Wait for the response for BOTH session- and node-level requests: PFCP node
        # messages (Association Setup/Update/Release, Heartbeat, PFD Management) are
        # answered too, and callers rely on the reply to mark the peer associated.
        ev = threading.Event()
        self.pending[m.seq] = [ev, None]
        self.server.send(m.to_bytes(), (peer.ip, peer.port))
        ev.wait(3.0)
        _, resp = self.pending.pop(m.seq, [None, None])
        return resp

    def _request(self, msg, peer, expect):
        resp = self._send(msg, peer)
        if resp is None:
            dbg("%s: no response from %s" % (self.name, peer.ip))
            return None
        if resp.msg_type != expect:
            dbg("%s: unexpected response %s" % (self.name, resp.name()))
        return resp

    # ------------------------------------------------------- Rx dispatch ----
    def handle(self, data, addr):
        try:
            msg = pfcp.Message.from_bytes(data)
        except Exception as e:  # noqa
            dbg("%s: bad PFCP packet from %s (%r)" % (self.name, addr, e))
            return None
        peer = self.peers.get(addr[0])
        if peer:
            peer.last_seen = time.time()
        trace("%s <- %s" % (self.name, msg.name()))

        if msg.msg_type in (pfcp.HEARTBEAT_RESPONSE, pfcp.ASSOCIATION_SETUP_RESPONSE,
                            pfcp.ASSOCIATION_UPDATE_RESPONSE,
                            pfcp.ASSOCIATION_RELEASE_RESPONSE,
                            pfcp.SESSION_ESTABLISHMENT_RESPONSE,
                            pfcp.SESSION_MODIFICATION_RESPONSE,
                            pfcp.SESSION_DELETION_RESPONSE,
                            pfcp.PFD_MANAGEMENT_RESPONSE,
                            pfcp.SESSION_REPORT_RESPONSE):
            slot = self.pending.get(msg.seq)
            if slot:
                slot[1] = msg
                slot[0].set()
            return None
        if msg.msg_type == pfcp.HEARTBEAT_REQUEST:
            return pfcp.Message(pfcp.HEARTBEAT_RESPONSE, seq=msg.seq,
                                ies=[pfcp.ie_recovery_ts(self.recovery_ts)]).to_bytes()
        if msg.msg_type == pfcp.SESSION_REPORT_REQUEST:
            self._on_report(msg, addr)
            return pfcp.Message(pfcp.SESSION_REPORT_RESPONSE, seid=msg.seid,
                                seq=msg.seq, ies=[pfcp.ie_cause()]).to_bytes()
        if msg.msg_type == pfcp.ASSOCIATION_UPDATE_REQUEST:
            self._on_association_update(msg, peer)
            return pfcp.Message(pfcp.ASSOCIATION_UPDATE_RESPONSE, seq=msg.seq,
                                ies=[pfcp.ie_cause(), pfcp.ie_recovery_ts(self.recovery_ts)]).to_bytes()
        return None

    # ------------------------------------------------- node procedures ------
    def association_setup(self, peer):
        m = pfcp.Message(pfcp.ASSOCIATION_SETUP_REQUEST, has_seid=False,
                         ies=[pfcp.ie_node_id(self.ip), pfcp.ie_recovery_ts(self.recovery_ts)])
        resp = self._request(m, peer, pfcp.ASSOCIATION_SETUP_RESPONSE)
        if resp and resp.get(pfcp.IE["Cause"]) and resp.get(pfcp.IE["Cause"])[0] == 1:
            peer.associated = True
            peer.node_id = pfcp.decode_node_id(resp.get(pfcp.IE["Node ID"]))
            peer.last_seen = time.time()
            log("%s: Sx association established with UPF %s (%s)"
                % (self.name, peer.ip, peer.node_id))
            return True
        return False

    def association_release(self, peer):
        m = pfcp.Message(pfcp.ASSOCIATION_RELEASE_REQUEST, has_seid=False,
                         ies=[pfcp.ie_node_id(self.ip)])
        resp = self._request(m, peer, pfcp.ASSOCIATION_RELEASE_RESPONSE)
        peer.associated = False
        # remove sessions belonging to this peer
        for seid, s in list(self.store.sessions.items()):
            if s.up_fseid[1] == peer.ip:
                self.store.delete(seid)
        return resp is not None

    def _on_association_update(self, msg, peer):
        if peer is None:
            return
        gi = msg.get(pfcp.IE["Recovery Time Stamp"])
        log("%s: Association Update from UPF %s (user-plane down)" % (self.name, peer.ip))
        # CPF starts deleting sessions, then (after guard timer) sends Release
        for seid in [s for s, v in self.store.sessions.items() if v.up_fseid[1] == peer.ip]:
            self.store.delete(seid)
        if peer and peer.associated:
            threading.Timer(self.guard_interval,
                            lambda: self.association_release(peer)).start()

    def _heartbeat_loop(self):
        for peer in self.peers.values():
            if not peer.associated:
                continue
            m = pfcp.Message(pfcp.HEARTBEAT_REQUEST, has_seid=False,
                             ies=[pfcp.ie_recovery_ts(self.recovery_ts)])
            self.server.send(
                pfcp.Message(m.msg_type, seq=self._next_seq(), ies=m.ies,
                             has_seid=False).to_bytes(), (peer.ip, peer.port))

    def pfd_management(self, peer, app_id, pfd_entries):
        """Provision/remove PFDs for an Application ID (Sx node-level procedure)."""
        ctx = [pfcp.encode_ie(pfcp.IE["Application ID"], app_id.encode())]
        m = pfcp.Message(pfcp.PFD_MANAGEMENT_REQUEST, has_seid=False, ies=[
            pfcp.encode_grouped(pfcp.IE["PFD Context"], ctx)])
        resp = self._request(m, peer, pfcp.PFD_MANAGEMENT_RESPONSE)
        return resp is not None

    # ------------------------------------------------- session procedures ---
    def session_establish(self, peer, kind="PDN", ue_ip="10.10.0.2", teid=None):
        seid = self.store.new_seid(self.base_seid)
        s = self.store.create(seid, self.ip, peer.ip, kind)
        # UL PDR/FAR (Access->Core) and DL PDR/FAR (Core->Access)
        ul_far = FAR(1, ["FORWARD"], "Core")
        dl_far = FAR(2, ["FORWARD"], "Access")
        ul_pdr = PDR(1, source_interface="Access", urr_ids=[1], qer_ids=[1], far_id=1)
        dl_pdr = PDR(2, source_interface="Core", urr_ids=[1], qer_ids=[1], far_id=2)
        s.add_rules([ul_pdr, dl_pdr], [ul_far, dl_far], [QER(1)], [URR(1)])
        m = pfcp.Message(pfcp.SESSION_ESTABLISHMENT_REQUEST, seid=0, ies=[
            pfcp.ie_node_id(self.ip), pfcp.ie_fseid(seid, self.ip),
            pfcp.encode_ie(pfcp.IE["UE IP Address"], pfcp._u32(0) + __import__("socket").inet_aton(ue_ip)),
            ul_pdr.to_pfcp(), ul_far.to_pfcp(), dl_pdr.to_pfcp(), dl_far.to_pfcp(),
            QER(1).to_pfcp(), URR(1).to_pfcp()])
        resp = self._request(m, peer, pfcp.SESSION_ESTABLISHMENT_RESPONSE)
        if resp and resp.get(pfcp.IE["Cause"]) and resp.get(pfcp.IE["Cause"])[0] == 1:
            up_fseid, up_ip = pfcp.decode_fseid(resp.get(pfcp.IE["F-SEID"]))
            s.up_fseid = (up_fseid, up_ip or peer.ip)
            # learn the UP-assigned UL F-TEIDu from each Created PDR
            for t, v in resp.ies:
                if t != pfcp.IE["Created PDR"]:
                    continue
                pid, fteid = _created_pdr_info(v)
                if pid == 1 and fteid:
                    ul_pdr.fteid = fteid
            log("%s: Sx session 0x%X established (UP F-SEID=0x%X, UL F-TEIDu=%s)"
                % (self.name, seid, s.up_fseid[0],
                   ("0x%X@%s" % ul_pdr.fteid) if ul_pdr.fteid else "n/a"))
            return s
        log("%s: session establishment failed" % self.name)
        self.store.delete(seid)
        return None

    def session_modify(self, seid, add_pdrs=(), remove_pdr_ids=()):
        s = self.store.get(seid)
        if not s:
            return None
        peer = self.peers.get(s.up_fseid[1])
        ies = [pfcp.ie_fseid(seid, self.ip)]
        for p in add_pdrs:
            s.pdrs[p.pdr_id] = p
            ies.append(p.to_pfcp())
        for pid in remove_pdr_ids:
            s.pdrs.pop(pid, None)
            ies.append(pfcp.encode_ie(pfcp.IE["Remove PDR"], pfcp._u16(pid)))
        m = pfcp.Message(pfcp.SESSION_MODIFICATION_REQUEST, seid=s.up_fseid[0], ies=ies)
        resp = self._request(m, peer, pfcp.SESSION_MODIFICATION_RESPONSE)
        ok = bool(resp and resp.get(pfcp.IE["Cause"]) and resp.get(pfcp.IE["Cause"])[0] == 1)
        if ok:
            log("%s: Sx session 0x%X modified" % (self.name, seid))
        return s if ok else None

    def session_delete(self, seid):
        s = self.store.get(seid)
        if not s:
            return False
        peer = self.peers.get(s.up_fseid[1])
        m = pfcp.Message(pfcp.SESSION_DELETION_REQUEST, seid=s.up_fseid[0],
                         ies=[pfcp.ie_fseid(seid, self.ip)])
        resp = self._request(m, peer, pfcp.SESSION_DELETION_RESPONSE)
        self.store.delete(seid)
        log("%s: Sx session 0x%X deleted" % (self.name, seid))
        return resp is not None

    def _on_report(self, msg, addr):
        rt = msg.get(pfcp.IE["Report Type"])
        bits = rt[0] if rt else 0
        log("%s: Sx Report from %s: triggers=%s" %
            (self.name, addr[0], ",".join(reporting.describe(bits)) or "?"))
        # In a real CPF this feeds charging (OFCS/OCS) / PCRF.

    # ------------------------------------------------- control interface ---
    def enable_control(self, port):
        """Start a small text-based control listener on a SECOND socket/thread.

        Kept off the PFCP server so a control-driven session procedure (which
        blocks waiting for a PFCP response) cannot deadlock the single PFCP
        receive loop. Intended for test/demo drivers, e.g. run_stack.py.
        """
        self.ctl = UDPServer(self.ip, port, self._ctl_handle, name=self.name + "-ctl")
        self.ctl.start()
        log("%s: control socket listening on %s:%d" % (self.name, self.ip, port))

    def _ctl_handle(self, data, addr):
        try:
            parts = data.decode(errors="ignore").split()
        except Exception:  # noqa
            return b"ERR decode\n"
        cmd = parts[0].upper() if parts else ""
        try:
            if cmd == "PING":
                reply = "OK %s" % self.name
            elif cmd == "STATUS":
                assoc = sum(1 for p in self.peers.values() if p.associated)
                reply = "OK %s peers=%d associated=%d sessions=%d" % (
                    self.name, len(self.peers), assoc, len(self.store.sessions))
            elif cmd == "SESSIONS":
                reply = "OK %s %s" % (
                    self.name, ",".join("0x%X" % s for s in self.store.sessions) or "-")
            elif cmd == "ASSOC":
                out = []
                for peer in self.peers.values():
                    if not peer.associated:
                        out.append("%s=%s" % (peer.ip, self.association_setup(peer)))
                reply = "OK %s assoc[%s]" % (self.name, ",".join(out) or "already")
            elif cmd == "ESTABLISH":
                ue = parts[1] if len(parts) > 1 else "10.10.0.2"
                seids = []
                for peer in self.peers.values():
                    s = self.session_establish(peer, ue_ip=ue)
                    if s is not None:
                        seids.append("0x%X" % s.seid)
                reply = "OK %s sessions=%s" % (self.name, ",".join(seids) or "none")
            elif cmd == "MODIFY":
                seid = int(parts[1], 16)
                pdr = PDR(9, precedence=50, source_interface="Access", far_id=1, urr_ids=[1])
                s = self.session_modify(seid, add_pdrs=[pdr])
                reply = "OK %s modify=0x%X %s" % (self.name, seid, "ok" if s else "fail")
            elif cmd == "DELETE":
                seid = int(parts[1], 16)
                ok = self.session_delete(seid)
                reply = "OK %s delete=0x%X %s" % (self.name, seid, "ok" if ok else "fail")
            elif cmd == "RELEASE":
                out = []
                for peer in self.peers.values():
                    if peer.associated:
                        out.append("%s=%s" % (peer.ip, self.association_release(peer)))
                reply = "OK %s release[%s]" % (self.name, ",".join(out) or "none")
            else:
                reply = "ERR unknown command %r" % cmd
        except Exception as e:  # noqa
            reply = "ERR %r" % e
        return (reply + "\n").encode()
