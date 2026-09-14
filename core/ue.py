#!/usr/bin/env python3
# core/ue.py — User Equipment (NAS/EMM+ESM over the Uu radio link).
#
# The Uu interface is modelled as UDP to the eNB: NAS signalling on UU_NAS and user data
# on UU_DATA. The UE runs the attach state machine (Attach Request -> Authentication ->
# Security Mode -> Attach Accept/Complete) and can send/receive user-plane payloads.
import hashlib
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from network.udp_server import UDPServer
from protocols import nas
from utils.utils import log, dbg

# ---------------------------------------------------------------- config -----
UE_IP    = "127.0.0.10"
ENB_IP   = "127.0.0.11"
UU_NAS   = 36422
UU_DATA  = 36423
UE_CTL_PORT = 8909
DEFAULT_IMSI = "001010000000001"
DEFAULT_APN  = "internet"
# -----------------------------------------------------------------------------


def _res(imsi, rand):
    k = hashlib.sha256(("K|" + imsi).encode()).digest()[:16]
    return hashlib.sha256(k + rand + b"XRES").digest()[:8]


class UE:
    def __init__(self, imsi=DEFAULT_IMSI, apn=DEFAULT_APN, ip=UE_IP, enb_ip=ENB_IP):
        self.imsi = imsi
        self.apn = apn
        self.ip = ip
        self.enb_ip = enb_ip
        self.state = "IDLE"
        self.assigned_ip = None
        self.ebi = None
        self.kasme = None
        self.enb_addr = None             # learned from downlink
        self.rx_data = []
        self.done = threading.Event()
        self.uu_nas = UDPServer(ip, UU_NAS, self.on_nas, name="UE-Uu-NAS")
        self.uu_data = UDPServer(ip, UU_DATA, self.on_data, name="UE-Uu-data")

    def start(self):
        self.uu_nas.start()
        self.uu_data.start()
        log("UE %s up on %s (Uu NAS:%d data:%d)" % (self.imsi, self.ip, UU_NAS, UU_DATA))

    def stop(self):
        self.uu_nas.stop()
        self.uu_data.stop()

    # --------------------------------------------------------------- attach --
    def attach(self):
        self.state = "ATTACH_SENT"
        m = nas.Message(nas.ATTACH_REQUEST, [
            nas.ie_imsi(self.imsi), nas.ie_apn(self.apn),
            nas.ie_pdn_type(1), nas.ie_attach_type(1)])
        self._send_nas(m, (self.enb_ip, UU_NAS))
        log("UE: -> Attach Request (IMSI %s, APN %s)" % (self.imsi, self.apn))

    def detach(self):
        m = nas.Message(nas.DETACH_REQUEST, [nas.ie_imsi(self.imsi)])
        self._send_nas(m, (self.enb_ip, UU_NAS))
        self.state = "DETACH_SENT"
        log("UE: -> Detach Request")

    def send_ul(self, payload):
        if isinstance(payload, str):
            payload = payload.encode()
        self.uu_data.send(payload, (self.enb_ip, UU_DATA))
        dbg("UE: -> UL data %dB" % len(payload))

    # ------------------------------------------------------------- rx paths --
    def _send_nas(self, msg, addr):
        self.uu_nas.send(msg.to_bytes(), addr)

    def on_nas(self, data, addr):
        self.enb_addr = addr
        try:
            m = nas.Message.from_bytes(data)
        except Exception as e:  # noqa
            dbg("UE: bad NAS (%r)" % e)
            return None
        dbg("UE <- %s" % m.name())
        t = m.msg_type
        if t == nas.AUTH_REQUEST:
            rand, autn = m.get(nas.IE_RAND), m.get(nas.IE_AUTN)
            res = _res(self.imsi, rand)
            log("UE: <- Authentication Request; sending Response (RES=%s)" % res.hex())
            self._send_nas(nas.Message(nas.AUTH_RESPONSE, [nas.ie_res(res)]), addr)
        elif t == nas.SECURITY_MODE_COMMAND:
            log("UE: <- Security Mode Command; sending Complete")
            self._send_nas(nas.Message(nas.SECURITY_MODE_COMPLETE, []), addr)
        elif t == nas.ATTACH_ACCEPT:
            ip = m.get(nas.IE_UE_IP)
            self.assigned_ip = nas.decode_ue_ip(ip) if ip else None
            ebi = m.get(nas.IE_EBI)
            self.ebi = ebi[0] if ebi else 5
            self.state = "ATTACHED"
            log("UE: <- Attach Accept  (IP=%s EBI=%d)  *** ATTACHED ***"
                % (self.assigned_ip, self.ebi))
            self._send_nas(nas.Message(nas.ATTACH_COMPLETE, []), addr)
            self.done.set()
        elif t == nas.ATTACH_REJECT:
            self.state = "REJECTED"
            log("UE: <- Attach Reject")
            self.done.set()
        elif t == nas.DETACH_ACCEPT:
            self.state = "DETACHED"
            log("UE: <- Detach Accept")
        return None

    def on_data(self, data, addr):
        self.rx_data.append(data)
        log("UE: <- DL data %dB: %r" % (len(data), data[:32]))
        return None

    # ------------------------------------------------------------ control ----
    def enable_control(self, port=UE_CTL_PORT):
        self.ctl = UDPServer(self.ip, port, self._ctl_handle, name="UE-ctl")
        self.ctl.start()
        log("UE: control socket on %s:%d" % (self.ip, port))

    def _ctl_handle(self, data, addr):
        parts = data.decode(errors="ignore").split()
        cmd = parts[0].upper() if parts else ""
        if cmd == "ATTACH":
            self.attach()
            reply = "OK UE attach started"
        elif cmd == "DETACH":
            self.detach()
            reply = "OK UE detach started"
        elif cmd == "UL":
            payload = " ".join(parts[1:]) or "UL-DATA"
            self.send_ul(payload)
            reply = "OK UE sent UL %r" % payload
        elif cmd == "STATUS":
            reply = "OK UE state=%s ip=%s rx=%d" % (self.state, self.assigned_ip,
                                                    len(self.rx_data))
        else:
            reply = "ERR unknown %r" % cmd
        return (reply + "\n").encode()


def main(argv):
    ue = UE()
    ue.start()
    ue.enable_control()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        ue.stop()


if __name__ == "__main__":
    main(sys.argv[1:])
