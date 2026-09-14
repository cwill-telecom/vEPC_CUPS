#!/usr/bin/env python3
# core/pcrf.py — Policy and Charging Rules Function (Gx over Diameter, TS 29.212).
#
# The PGW-C queries the PCRF with a Credit-Control-Request (CCR); the PCRF answers with
# a CCA carrying the authorized QoS (QCI + MBR UL/DL) and the charging method. Policy is
# held per subscriber (IMSI) with a default profile.
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from network.udp_server import UDPServer
from protocols import diameter as D
from utils.utils import log, dbg

# ---------------------------------------------------------------- config -----
PCRF_IP   = "127.0.0.14"
PCRF_PORT = 3868
PCRF_ORIGIN_HOST  = "pcrf.epc.mnc001.mcc001.3gppnetwork.org"
PCRF_ORIGIN_REALM = "epc.mnc001.mcc001.3gppnetwork.org"
DEFAULT_POLICY = {"qci": 9, "mbr_ul": 100000, "mbr_dl": 200000, "charging": "ONLINE"}
# -----------------------------------------------------------------------------


class PCRF:
    def __init__(self, ip=PCRF_IP, port=PCRF_PORT):
        self.ip = ip
        self.port = port
        self.policies = {}                 # imsi -> policy dict
        self.server = UDPServer(ip, port, self.handle, name="PCRF")

    def set_policy(self, imsi, **kw):
        pol = dict(DEFAULT_POLICY)
        pol.update(kw)
        self.policies[imsi] = pol

    def start(self):
        self.server.start()
        log("PCRF listening on %s:%d (Gx)" % (self.ip, self.port))

    def stop(self):
        self.server.stop()
        if getattr(self, "ctl", None):
            self.ctl.stop()

    # ------------------------------------------------------------- Gx rx ----
    def handle(self, data, addr):
        try:
            msg = D.Message.from_bytes(data)
        except Exception as e:  # noqa
            dbg("PCRF: bad Diameter from %s (%r)" % (addr, e))
            return None
        if msg.cmd_code != D.CMD_CREDIT_CONTROL:
            return None
        ccr_type = msg.get(D.AVP_CC_REQUEST_TYPE)
        ctype = ccr_type.u32() if ccr_type else D.CC_EVENT
        imsi = self._imsi(msg)
        pol = self.policies.get(imsi, DEFAULT_POLICY)
        dbg("PCRF <- %s from %s (type=%d imsi=%s)" % (msg.name(), addr[0], ctype, imsi))

        ans = D.Message(D.CMD_CREDIT_CONTROL, D.GX_APP,
                        request=False, hop_id=msg.hop_id, end_id=msg.end_id)
        sid = msg.get(D.AVP_SESSION_ID)
        ans.add(D.avp(D.AVP_SESSION_ID, sid.text() if sid else "gx;1"))
        ans.add(D.avp(D.AVP_ORIGIN_HOST, PCRF_ORIGIN_HOST))
        ans.add(D.avp(D.AVP_ORIGIN_REALM, PCRF_ORIGIN_REALM))
        ans.add(D.avp(D.AVP_AUTH_SESSION_STATE, bytes([D.NO_STATE_MAINTAINED])))
        num = msg.get(D.AVP_CC_REQUEST_NUMBER)
        if num is not None:
            ans.add(D.avp_u32(D.AVP_CC_REQUEST_NUMBER, num.u32()))
        ans.add(D.avp_u32(D.AVP_CC_REQUEST_TYPE, ctype))
        ans.add(D.avp_u32(D.AVP_RESULT_CODE, D.DIAMETER_SUCCESS))

        if ctype in (D.CC_INITIAL, D.CC_UPDATE):
            ans.add(D.group(D.AVP_QOS_INFORMATION, [
                D.avp_u32(D.AVP_QOS_CLASS_IDENTIFIER, pol["qci"], D.VENDOR_3GPP),
                D.avp_u32(D.AVP_MAX_REQ_BANDWIDTH_UL, pol["mbr_ul"], D.VENDOR_3GPP),
                D.avp_u32(D.AVP_MAX_REQ_BANDWIDTH_DL, pol["mbr_dl"], D.VENDOR_3GPP),
            ], D.VENDOR_3GPP))
            log("PCRF: CCA authorized QoS QCI=%d MBR=%d/%d kbps (IMSI %s, %s)"
                % (pol["qci"], pol["mbr_ul"], pol["mbr_dl"], imsi, pol["charging"]))
        else:
            log("PCRF: CCA for termination (IMSI %s)" % imsi)
        return ans.to_bytes()

    # ------------------------------------------------------------ control ---
    def enable_control(self, port):
        self.ctl = UDPServer(self.ip, port, self._ctl_handle, name="PCRF-ctl")
        self.ctl.start()
        log("PCRF: control socket on %s:%d" % (self.ip, port))

    def _ctl_handle(self, data, addr):
        parts = data.decode(errors="ignore").split()
        cmd = parts[0].upper() if parts else ""
        if cmd == "STATUS":
            reply = "OK PCRF policies=%d default_qci=%d" % (
                len(self.policies), DEFAULT_POLICY["qci"])
        elif cmd == "POLICIES":
            reply = "OK PCRF %s" % ",".join("%s/qci%d" % (i, p["qci"])
                                            for i, p in self.policies.items())
        else:
            reply = "ERR unknown %r" % cmd
        return (reply + "\n").encode()

    @staticmethod
    def _imsi(msg):
        subs = msg.get(D.AVP_SUBSCRIPTION_ID)
        if subs is None:
            return "-"
        for a in D.children(subs):
            if a.code == D.AVP_SUBSCRIPTION_ID_DATA:
                return a.text()
        return "-"


def parse_qos(cca):
    """Extract (qci, mbr_ul, mbr_dl) from a CCA's QoS-Information."""
    out = {"qci": 9, "mbr_ul": 0, "mbr_dl": 0}
    qi = cca.get(D.AVP_QOS_INFORMATION, D.VENDOR_3GPP)
    if qi is None:
        return out
    for a in D.children(qi):
        if a.code == D.AVP_QOS_CLASS_IDENTIFIER:
            out["qci"] = a.u32()
        elif a.code == D.AVP_MAX_REQ_BANDWIDTH_UL:
            out["mbr_ul"] = a.u32()
        elif a.code == D.AVP_MAX_REQ_BANDWIDTH_DL:
            out["mbr_dl"] = a.u32()
    return out


def main(argv):
    pcrf = PCRF()
    pcrf.start()
    if os.environ.get("PCRF_CTL_PORT"):
        pcrf.enable_control(int(os.environ["PCRF_CTL_PORT"]))
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pcrf.stop()


if __name__ == "__main__":
    main(sys.argv[1:])
