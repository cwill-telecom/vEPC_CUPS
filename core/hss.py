#!/usr/bin/env python3
# core/hss.py — Home Subscriber Server (S6a over Diameter, TS 29.272).
#
# Stores subscriber profiles and serves the MME over S6a:
#   AIR/AIA  Authentication-Information  -> E-UTRAN authentication vectors
#   ULR/ULA  Update-Location             -> Subscription-Data (APN config, AMBR, QoS)
#
# Authentication vectors are derived deterministically from a per-subscriber secret K
# (a simulated Milenage) so the MME and HSS agree without a real AuC.
import hashlib
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from network.udp_server import UDPServer
from protocols import diameter as D
from utils.utils import log, dbg, DEFAULT_RECOVERY_TS

# ---------------------------------------------------------------- config -----
HSS_IP   = "127.0.0.13"
HSS_PORT = 3868
HSS_ORIGIN_HOST  = "hss.epc.mnc001.mcc001.3gppnetwork.org"
HSS_ORIGIN_REALM = "epc.mnc001.mcc001.3gppnetwork.org"
# default subscription (overridable per subscriber)
DEFAULT_AMBR_UL = 100000      # kbps
DEFAULT_AMBR_DL = 200000      # kbps
DEFAULT_QCI     = 9           # non-GBR
DEFAULT_APN     = "internet"
# -----------------------------------------------------------------------------


def _k(imsi):
    return hashlib.sha256(("K|" + imsi).encode()).digest()[:16]


def _vector(imsi, n):
    """Return one simulated E-UTRAN vector (rand, xres, autn, kasme)."""
    k = _k(imsi)
    rand = hashlib.sha256(("RAND|%s|%d" % (imsi, n)).encode()).digest()[:16]
    xres = hashlib.sha256(k + rand + b"XRES").digest()[:8]
    autn = hashlib.sha256(k + rand + b"AUTN").digest()[:16]
    kasme = hashlib.sha256(k + rand + b"KASME").digest()[:32]
    return rand, xres, autn, kasme


class HSS:
    def __init__(self, ip=HSS_IP, port=HSS_PORT):
        self.ip = ip
        self.port = port
        self.subscribers = {}     # imsi -> dict(apn, ambR_ul, ambR_dl, qci, status)
        self.server = UDPServer(ip, port, self.handle, name="HSS")
        self.vec_counter = {}     # imsi -> vectors handed out
        self._seed_default_subscriber()

    def _seed_default_subscriber(self):
        self.add_subscriber("001010000000001", apn=DEFAULT_APN,
                            ambr_ul=DEFAULT_AMBR_UL, ambr_dl=DEFAULT_AMBR_DL,
                            qci=DEFAULT_QCI)

    def add_subscriber(self, imsi, apn=DEFAULT_APN, ambr_ul=DEFAULT_AMBR_UL,
                       ambr_dl=DEFAULT_AMBR_DL, qci=DEFAULT_QCI, status=0):
        self.subscribers[imsi] = {"apn": apn, "ambr_ul": ambr_ul, "ambr_dl": ambr_dl,
                                  "qci": qci, "status": status}

    def start(self):
        self.server.start()
        log("HSS listening on %s:%d (S6a) — %d subscriber(s)"
            % (self.ip, self.port, len(self.subscribers)))

    def stop(self):
        self.server.stop()
        if getattr(self, "ctl", None):
            self.ctl.stop()

    # ------------------------------------------------------------ S6a rx ----
    def handle(self, data, addr):
        try:
            msg = D.Message.from_bytes(data)
        except Exception as e:  # noqa
            dbg("HSS: bad Diameter from %s (%r)" % (addr, e))
            return None
        dbg("HSS <- %s from %s" % (msg.name(), addr[0]))
        if msg.cmd_code == D.CMD_AUTH_INFO and msg.request:
            return self._ai(msg)
        if msg.cmd_code == D.CMD_UPDATE_LOCATION and msg.request:
            return self._ul(msg)
        return None

    @staticmethod
    def _subs_id(msg):
        subs = msg.get(D.AVP_SUBSCRIPTION_ID)
        if subs is None:
            return None
        for a in D.children(subs):
            if a.code == D.AVP_SUBSCRIPTION_ID_DATA:
                return a.text()
        return None

    def _base_ans(self, req, cmd, result=D.DIAMETER_SUCCESS):
        m = D.Message(cmd, D.S6A_APP, request=False, hop_id=req.hop_id, end_id=req.end_id)
        sid = req.get(D.AVP_SESSION_ID)
        m.add(D.avp(D.AVP_SESSION_ID, sid.text() if sid else "hss;1"))
        m.add(D.avp(D.AVP_ORIGIN_HOST, HSS_ORIGIN_HOST))
        m.add(D.avp(D.AVP_ORIGIN_REALM, HSS_ORIGIN_REALM))
        m.add(D.avp(D.AVP_AUTH_SESSION_STATE, bytes([D.NO_STATE_MAINTAINED])))
        m.add(D.avp_u32(D.AVP_RESULT_CODE, result))
        return m

    def _ai(self, req):
        imsi = self._subs_id(req)
        ans = self._base_ans(req, D.CMD_AUTH_INFO)
        if imsi not in self.subscribers:
            ans.avps[-1] = D.avp_u32(D.AVP_RESULT_CODE, D.DIAMETER_USER_UNKNOWN)
            log("HSS: AIR for unknown IMSI %s -> DIAMETER_USER_UNKNOWN" % imsi)
            return ans.to_bytes()
        want = req.get(D.AVP_REQUESTED_EUTRAN_AUTH_INFO, D.VENDOR_3GPP)
        n = want.u32() if want else 1
        self.vec_counter[imsi] = self.vec_counter.get(imsi, 0) + 1
        vectors = [D.group(D.AVP_E_UTRAN_VECTOR, [
            D.avp(D.AVP_RAND, r, D.VENDOR_3GPP),
            D.avp(D.AVP_XRES, x, D.VENDOR_3GPP),
            D.avp(D.AVP_AUTN, a, D.VENDOR_3GPP),
            D.avp(D.AVP_KASME, k, D.VENDOR_3GPP),
        ], D.VENDOR_3GPP) for r, x, a, k in
            (_vector(imsi, i) for i in range(n))]
        auth_info = D.group(D.AVP_AUTHENTICATION_INFO, [
            D.avp_u32(D.AVP_NUMBER_OF_REQUESTED_VECTORS, n, D.VENDOR_3GPP)] + vectors,
            D.VENDOR_3GPP)
        ans.add(auth_info)
        log("HSS: AIR -> AIA for IMSI %s (%d vector(s))" % (imsi, n))
        return ans.to_bytes()

    def _ul(self, req):
        imsi = self._subs_id(req)
        ans = self._base_ans(req, D.CMD_UPDATE_LOCATION)
        sub = self.subscribers.get(imsi)
        if sub is None:
            ans.avps[-1] = D.avp_u32(D.AVP_RESULT_CODE, D.DIAMETER_USER_UNKNOWN)
            log("HSS: ULR for unknown IMSI %s -> DIAMETER_USER_UNKNOWN" % imsi)
            return ans.to_bytes()
        apn_cfg = D.group(D.AVP_APN_CONFIGURATION, [
            D.avp(D.AVP_SERVICE_SELECTION, sub["apn"], D.VENDOR_3GPP),
            D.avp_u32(D.AVP_PDN_TYPE_3GPP, 1, D.VENDOR_3GPP),           # IPv4
            D.group(D.AVP_EPS_SUBSCRIBED_QOS_PROFILE, [
                D.avp_u32(D.AVP_QOS_CLASS_IDENTIFIER, sub["qci"], D.VENDOR_3GPP),
                D.avp_u32(D.AVP_ALLOCATION_RETENTION_PRIORITY, 8, D.VENDOR_3GPP),
            ], D.VENDOR_3GPP),
            D.group(D.AVP_AMBR, [
                D.avp_u32(D.AVP_MAX_REQ_BANDWIDTH_UL, sub["ambr_ul"], D.VENDOR_3GPP),
                D.avp_u32(D.AVP_MAX_REQ_BANDWIDTH_DL, sub["ambr_dl"], D.VENDOR_3GPP),
            ], D.VENDOR_3GPP),
        ], D.VENDOR_3GPP)
        sub_data = D.group(D.AVP_SUBSCRIPTION_DATA, [
            D.avp_u32(D.AVP_SUBSCRIBER_STATUS, sub["status"], D.VENDOR_3GPP),
            D.group(D.AVP_APN_CONFIGURATION_PROFILE, [apn_cfg], D.VENDOR_3GPP),
        ], D.VENDOR_3GPP)
        ans.add(sub_data)
        log("HSS: ULR -> ULA for IMSI %s (APN=%s AMBR=%d/%d QCI=%d)"
            % (imsi, sub["apn"], sub["ambr_ul"], sub["ambr_dl"], sub["qci"]))
        return ans.to_bytes()

    # ------------------------------------------------------------ control ---
    def enable_control(self, port):
        self.ctl = UDPServer(self.ip, port, self._ctl_handle, name="HSS-ctl")
        self.ctl.start()
        log("HSS: control socket on %s:%d" % (self.ip, port))

    def _ctl_handle(self, data, addr):
        cmd = data.decode(errors="ignore").split()
        cmd = cmd[0].upper() if cmd else ""
        if cmd == "STATUS":
            reply = "OK HSS subscribers=%d vectors=%d" % (
                len(self.subscribers), sum(self.vec_counter.values()))
        elif cmd == "SUBS":
            reply = "OK HSS %s" % ",".join("%s/%s" % (i, s["apn"])
                                           for i, s in self.subscribers.items())
        else:
            reply = "ERR unknown %r" % cmd
        return (reply + "\n").encode()


# ---------------------------------------------------------------- helpers ----
def parse_auth_info(avp):
    """Extract the first E-UTRAN vector from an Authentication-Info AVP."""
    vec = {"rand": None, "xres": None, "autn": None, "kasme": None, "n": 0}
    for a in D.children(avp):
        if a.code == D.AVP_NUMBER_OF_REQUESTED_VECTORS:
            vec["n"] = a.u32()
        elif a.code == D.AVP_E_UTRAN_VECTOR and vec["rand"] is None:
            for v in D.children(a):
                if v.code == D.AVP_RAND:  vec["rand"] = v.data
                if v.code == D.AVP_XRES:  vec["xres"] = v.data
                if v.code == D.AVP_AUTN:  vec["autn"] = v.data
                if v.code == D.AVP_KASME: vec["kasme"] = v.data
    return vec


def parse_subscription_data(avp):
    """Extract (apn, ambr_ul, ambr_dl, qci) from Subscription-Data."""
    out = {"apn": None, "ambr_ul": 0, "ambr_dl": 0, "qci": 9}
    for a in D.children(avp):
        if a.code == D.AVP_APN_CONFIGURATION_PROFILE:
            for p in D.children(a):
                if p.code == D.AVP_APN_CONFIGURATION:
                    for k in D.children(p):
                        if k.code == D.AVP_SERVICE_SELECTION:
                            out["apn"] = k.text()
                        elif k.code == D.AVP_EPS_SUBSCRIBED_QOS_PROFILE:
                            for q in D.children(k):
                                if q.code == D.AVP_QOS_CLASS_IDENTIFIER:
                                    out["qci"] = q.u32()
                        elif k.code == D.AVP_AMBR:
                            for b in D.children(k):
                                if b.code == D.AVP_MAX_REQ_BANDWIDTH_UL:
                                    out["ambr_ul"] = b.u32()
                                if b.code == D.AVP_MAX_REQ_BANDWIDTH_DL:
                                    out["ambr_dl"] = b.u32()
    return out


def main(argv):
    hss = HSS()
    hss.start()
    if os.environ.get("HSS_CTL_PORT"):
        hss.enable_control(int(os.environ["HSS_CTL_PORT"]))
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        hss.stop()


if __name__ == "__main__":
    main(sys.argv[1:])
