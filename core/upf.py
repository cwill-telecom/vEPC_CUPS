# core/upf.py — shared User Plane Function engine (UPF).
#
# Applies PDR/FAR/QER/URR rules, own the GTP-U F-TEIDu allocation, performs traffic
# detection (TDF embedded in the PGW-U, not a standalone node), buffers DL packets,
# and reports usage/events to the CPF. Designed to be as 3GPP-agnostic as possible
# (no bearer concept). Subclassed by sgw_u.py (Sxa) and pgw_u.py (Sxb).
import threading
import time
import socket
from network.udp_server import UDPServer
from protocols import pfcp
from sxcups.session import SessionStore
from sxcups.rules import PDR, FAR, QER, URR
from sxcups import reporting
from utils.utils import log, dbg, trace, PeriodicTimer, DEFAULT_RECOVERY_TS, teid_pool


class Peer:
    def __init__(self, ip, port=8805):
        self.ip = ip
        self.port = port
        self.node_id = None
        self.associated = False
        self.last_seen = 0.0


class UPF:
    def __init__(self, name, ip, port=8805, heartbeat=5, guard_interval=10,
                 features=("TRST", "FTUP", "TREU", "EMPU")):
        self.name = name
        self.ip = ip
        self.port = port
        self.recovery_ts = DEFAULT_RECOVERY_TS
        self.features = list(features)          # UP Function Features
        self.guard_interval = guard_interval    # pfcp-guard-time-interval
        self.heartbeat = heartbeat
        self.peers = {}                         # CPF ip -> Peer
        self.user_plane_service = "UP"          # admin-state: "UP" | "DOWN"
        self.store = SessionStore()
        self.seq = 0
        self._teid = teid_pool()
        self.lock = threading.Lock()
        self.server = UDPServer(ip, port, self.handle, name=name)
        self.timers = []

    # ------------------------------------------------------------ plumbing --
    def _next_seq(self):
        with self.lock:
            self.seq = (self.seq + 1) & 0xFFFFFF
            return self.seq

    def _alloc_fteid(self):
        return next(self._teid)

    def start(self):
        self.server.start()
        log("%s (UPF) listening on %s:%d  features=%s"
            % (self.name, self.ip, self.port, ",".join(self.features)))

    def stop(self):
        for t in self.timers: t.stop()
        self.server.stop()
        if getattr(self, "ctl", None):
            self.ctl.stop()
        if getattr(self, "gtpu", None):
            self.gtpu.stop()

    # ------------------------------------------------------ user-plane relay -
    def enable_gtpu(self, port=2152, sgi_port=0):
        """Start the GTP-U forwarding relay (S1-U / S5-U / SGi)."""
        from core.gtpu import GTPUNode
        self.gtpu = GTPUNode(self.ip, port, name=self.name, sgi_port=sgi_port)
        self.gtpu.start()

    def add_peer(self, ip, port=8805):
        self.peers[ip] = Peer(ip, port)
        dbg("%s: configured pfcp-peer %s (user-plane-service pfcp-peer-list)"
            % (self.name, ip))
        return self.peers[ip]

    def _send(self, msg, peer):
        self.server.send(msg.to_bytes(), (peer.ip, peer.port))

    # ------------------------------------------------------- Rx dispatch ----
    def handle(self, data, addr):
        try:
            msg = pfcp.Message.from_bytes(data)
        except Exception as e:  # noqa
            dbg("%s: bad PFCP packet from %s (%r)" % (self.name, addr, e))
            return None
        peer = self.peers.get(addr[0])
        if peer is None:
            peer = self.add_peer(addr[0])
        peer.last_seen = time.time()
        trace("%s <- %s" % (self.name, msg.name()))

        t = msg.msg_type
        if t == pfcp.HEARTBEAT_REQUEST:
            return self._reply(pfcp.HEARTBEAT_RESPONSE, msg, self._hb_ies())
        if t == pfcp.ASSOCIATION_SETUP_REQUEST:
            return self._on_association_setup(msg, peer)
        if t == pfcp.ASSOCIATION_UPDATE_REQUEST:
            return self._reply(pfcp.ASSOCIATION_UPDATE_RESPONSE, msg, self._hb_ies())
        if t == pfcp.ASSOCIATION_RELEASE_REQUEST:
            return self._on_association_release(msg, peer)
        if t == pfcp.SESSION_ESTABLISHMENT_REQUEST:
            return self._on_session_establish(msg, peer)
        if t == pfcp.SESSION_MODIFICATION_REQUEST:
            return self._on_session_modify(msg, peer)
        if t == pfcp.SESSION_DELETION_REQUEST:
            return self._on_session_delete(msg, peer)
        if t == pfcp.PFD_MANAGEMENT_REQUEST:
            return self._on_pfd_management(msg, peer)
        if t in (pfcp.HEARTBEAT_RESPONSE, pfcp.ASSOCIATION_SETUP_RESPONSE,
                 pfcp.ASSOCIATION_UPDATE_RESPONSE, pfcp.ASSOCIATION_RELEASE_RESPONSE,
                 pfcp.SESSION_ESTABLISHMENT_RESPONSE, pfcp.SESSION_MODIFICATION_RESPONSE,
                 pfcp.SESSION_DELETION_RESPONSE, pfcp.PFD_MANAGEMENT_RESPONSE,
                 pfcp.SESSION_REPORT_RESPONSE):
            return None                # responses are correlated by the CPF, ignore here
        dbg("%s: unhandled message %s" % (self.name, msg.name()))
        return None

    def _reply(self, mtype, req, ies):
        return pfcp.Message(mtype, seid=req.seid, seq=req.seq, ies=ies).to_bytes()

    def _hb_ies(self):
        return [pfcp.ie_cause(), pfcp.ie_node_id(self.ip),
                pfcp.ie_recovery_ts(self.recovery_ts)]

    # ------------------------------------------------- node procedures ------
    def _on_association_setup(self, msg, peer):
        peer.associated = True
        if peer.node_id is None:
            peer.node_id = pfcp.decode_node_id(msg.get(pfcp.IE["Node ID"]))
        log("%s: Sx association established with CPF %s (%s)"
            % (self.name, peer.ip, peer.node_id))
        ies = [pfcp.ie_node_id(self.ip), pfcp.ie_cause(),
               pfcp.ie_recovery_ts(self.recovery_ts)]
        # Load / Overload Control Information (simple advertisement)
        ies.append(pfcp.encode_ie(pfcp.IE["Load Control Information"],
                                  pfcp._u8(20)))          # 20% load
        ies.append(pfcp.encode_ie(pfcp.IE["Recovery Time Stamp"],
                                  pfcp._u32(self.recovery_ts)))
        return self._reply(pfcp.ASSOCIATION_SETUP_RESPONSE, msg, ies)

    def _on_association_release(self, msg, peer):
        peer.associated = False
        for seid in list(self.store.sessions):
            self.store.delete(seid)
        log("%s: Sx association released by CPF %s; all sessions removed"
            % (self.name, peer.ip))
        return self._reply(pfcp.ASSOCIATION_RELEASE_RESPONSE, msg,
                           [pfcp.ie_cause(), pfcp.ie_node_id(self.ip)])

    def set_admin_state(self, state):
        """Admin down/up the user-plane-service -> notify CPF via Association Update."""
        self.user_plane_service = state
        for peer in self.peers.values():
            if not peer.associated:
                continue
            ies = [pfcp.ie_node_id(self.ip)]
            if state == "DOWN":
                ies.append(pfcp.ie_recovery_ts(self.recovery_ts))
            m = pfcp.Message(pfcp.ASSOCIATION_UPDATE_REQUEST, has_seid=False,
                             seq=self._next_seq(), ies=ies)
            self._send(m, peer)
            log("%s: sent Association Update to %s (user-plane-service=%s)"
                % (self.name, peer.ip, state))

    # ------------------------------------------------- session procedures ---
    def _on_session_establish(self, msg, peer):
        cp_fseid, cp_ip = pfcp.decode_fseid(msg.get(pfcp.IE["F-SEID"]))
        s = self.store.create(cp_fseid, cp_ip or peer.ip, self.ip, "PDN")
        s.up_fseid = (cp_fseid, self.ip)
        pdrs, fars, qers, urrs = [], [], [], []
        for t, v in msg.ies:
            name = pfcp._IE_NAME.get(t, "")
            if name == "Create PDR":   pdrs.append(PDR.from_pfcp(v))
            elif name == "Create FAR": fars.append(FAR.from_pfcp(v))
            elif name == "Create QER": qers.append(QER.from_pfcp(v))
            elif name == "Create URR": urrs.append(URR.from_pfcp(v))
        s.add_rules(pdrs, fars, qers, urrs)
        # Allocate F-TEIDu for UL PDRs (the UPF is responsible for it).
        created = []
        for pdr in pdrs:
            if pdr.source_interface == "Access":
                pdr.fteid = (self._alloc_fteid(), self.ip)
                created.append(pfcp.encode_grouped(pfcp.IE["Created PDR"], [
                    pfcp.ie_pdr_id(pdr.pdr_id),
                    pfcp.encode_grouped(pfcp.IE["PDI"], [
                        pfcp.ie_ft_eid(pdr.fteid[0], pdr.fteid[1])])]))
        ies = [pfcp.ie_node_id(self.ip), pfcp.ie_cause(),
               pfcp.ie_fseid(cp_fseid, self.ip)] + created
        log("%s: Sx session 0x%X established (%d PDR, %d FAR, %d QER, %d URR)"
            % (self.name, cp_fseid, len(pdrs), len(fars), len(qers), len(urrs)))
        return self._reply(pfcp.SESSION_ESTABLISHMENT_RESPONSE, msg, ies)

    def _on_session_modify(self, msg, peer):
        s = self.store.get(msg.seid) or self.store.get(
            pfcp.decode_fseid(msg.get(pfcp.IE["F-SEID"]))[0])
        if s is None:
            return self._reply(pfcp.SESSION_MODIFICATION_RESPONSE, msg,
                               [pfcp.ie_cause(pfcp.CAUSE_SESSION_CONTEXT_NF)])
        for t, v in msg.ies:
            name = pfcp._IE_NAME.get(t, "")
            if name == "Create PDR":   s.add_rules([PDR.from_pfcp(v)])
            elif name == "Create FAR": s.add_rules(fars=[FAR.from_pfcp(v)])
            elif name == "Remove PDR": s.remove(pdr_ids=[pfcp.pdr_id_of(v)])
            elif name == "Remove FAR": s.remove(far_ids=[pfcp.u32_of(v)])
        log("%s: Sx session 0x%X modified" % (self.name, s.seid))
        return self._reply(pfcp.SESSION_MODIFICATION_RESPONSE, msg,
                           [pfcp.ie_cause(), pfcp.ie_node_id(self.ip)])

    def _on_session_delete(self, msg, peer):
        seid = msg.seid
        s = self.store.delete(seid)
        if s is not None:
            log("%s: Sx session 0x%X deleted (%d DL buffered)"
                % (self.name, seid, len(s.buffered)))
        return self._reply(pfcp.SESSION_DELETION_RESPONSE, msg,
                           [pfcp.ie_cause(), pfcp.ie_node_id(self.ip)])

    def _on_pfd_management(self, msg, peer):
        # The PGW-U stores PFD sets per Application ID (SDCI). MCC may not support it.
        for t, v, kids in msg.children(pfcp.IE["PFD Context"]):
            for ct, cv, _ in [(t, v, kids)] + kids:
                if pfcp._IE_NAME.get(ct) == "Application ID":
                    log("%s: PFD provisioning for Application ID %r"
                        % (self.name, cv.decode(errors="ignore")))
        return self._reply(pfcp.PFD_MANAGEMENT_RESPONSE, msg, [pfcp.ie_cause()])

    # ------------------------------------------------------ data & reports -
    def forward(self, seid, payload, direction):
        """Run the packet pipeline and log the applied action."""
        s = self.store.get(seid)
        if s is None:
            return ["DROP"], 0
        action, n = s.apply(payload, direction)
        trace("%s: session 0x%X %s packet %dB -> %s"
              % (self.name, seid, direction, n, "/".join(action)))
        return action, n

    def report(self, seid, triggers, urr_id=1, volume=None, pdr_id=None):
        s = self.store.get(seid)
        peer = self.peers.get(s.up_fseid[1] if s else None)
        if peer is None and self.peers:
            peer = next(iter(self.peers.values()))
        m = reporting.build_report_request(seid, self._next_seq(), triggers,
                                           urr_id=urr_id, volume=volume, pdr_id=pdr_id)
        self._send(m, peer)
        log("%s: sent Sx Report (session 0x%X, %s)"
            % (self.name, seid, ",".join(reporting.describe(triggers))))

    # ------------------------------------------------- control interface ---
    def enable_control(self, port):
        """Text-based control listener on its own socket/thread (run_stack.py driver)."""
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
                reply = "OK %s admin=%s peers=%d sessions=%d" % (
                    self.name, self.user_plane_service, len(self.peers), len(self.store.sessions))
            elif cmd == "SESSIONS":
                reply = "OK %s %s" % (
                    self.name, ",".join("0x%X" % s for s in self.store.sessions) or "-")
            elif cmd == "FORWARD":
                seid = int(parts[1], 16)
                n = int(parts[2]) if len(parts) > 2 else 1
                direction = parts[3] if len(parts) > 3 else "Access"
                acts = set()
                for i in range(n):
                    a, _ = self.forward(seid, b"PKT-%02d" % i, direction)
                    acts.update(a)
                reply = "OK %s forward=0x%X n=%d dir=%s action=%s" % (
                    self.name, seid, n, direction, "/".join(sorted(acts)))
            elif cmd == "REPORT":
                seid = int(parts[1], 16)
                trig = int(parts[2], 0) if len(parts) > 2 else 1
                s = self.store.get(seid)
                vol = None
                if s and (trig & reporting.TRIG_PERIODIC):
                    vol = (s.usage["uplink"] + s.usage["downlink"],
                           s.usage["uplink"], s.usage["downlink"])
                self.report(seid, trig, urr_id=1, volume=vol,
                            pdr_id=2 if trig & reporting.TRIG_FIRST_DL_DATA else None)
                reply = "OK %s report=0x%X triggers=%s" % (
                    self.name, seid, ",".join(reporting.describe(trig)))
            elif cmd == "ADMIN":
                self.set_admin_state(parts[1].upper())
                reply = "OK %s admin=%s" % (self.name, self.user_plane_service)
            elif cmd == "ROUTE":
                teid = int(parts[1], 16)
                next_ip = parts[2]
                next_port = int(parts[3])
                out = parts[4] if len(parts) > 4 else "-"
                if out in ("-", "EGRESS", "egress"):
                    self.gtpu.add_route(teid, next_ip, next_port, egress=True)
                else:
                    self.gtpu.add_route(teid, next_ip, next_port, out_teid=int(out, 16))
                reply = "OK %s route TEID=0x%X -> %s:%d %s" % (
                    self.name, teid, next_ip, next_port, out)
            elif cmd == "SGI":
                self.gtpu.set_sgi_uplink(parts[1], int(parts[2]), int(parts[3], 16))
                reply = "OK %s sgi uplink -> %s:%s teid=0x%X" % (
                    self.name, parts[1], parts[2], int(parts[3], 16))
            elif cmd == "GTPSTAT":
                reply = "OK %s %s" % (self.name, self.gtpu.stats)
            else:
                reply = "ERR unknown command %r" % cmd
        except Exception as e:  # noqa
            reply = "ERR %r" % e
        return (reply + "\n").encode()
