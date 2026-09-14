#!/usr/bin/env python3
# core/enb.py — E-UTRAN eNodeB: S1-MME (S1AP) to the MME and S1-U (GTP-U) to the SGW-U.
#
# Bridges the UE's Uu radio link (simplified UDP: NAS on UU_NAS, data on UU_DATA) to the
# S1 interfaces. UL NAS is wrapped in S1AP; DL NAS from the MME is forwarded to the UE.
# On InitialContextSetupRequest it sets up the S1-U bearer: it allocates a downlink
# TEID, programmes the GTP-U relay, and answers with its S1-U F-TEID.
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from network.udp_server import UDPServer
from core.gtpu import GTPUNode
from protocols import s1ap, nas
from utils.utils import log, dbg

# ---------------------------------------------------------------- config -----
ENB_IP   = "127.0.0.11"
UE_IP    = "127.0.0.10"
MME_IP   = "127.0.0.12"
SGWU_IP  = "127.0.0.2"
S1MME    = 36412
UU_NAS   = 36422
UU_DATA  = 36423
GTPU     = 2152
PLMN     = "00101"
TAC      = 1
ECGI     = 0x0001
# -----------------------------------------------------------------------------


class ENB:
    def __init__(self, ip=ENB_IP, mme_ip=MME_IP, sgwu_ip=SGWU_IP, ue_ip=UE_IP, plmn=PLMN):
        self.ip = ip
        self.mme_ip = mme_ip
        self.sgwu_ip = sgwu_ip
        self.ue_ip = ue_ip
        self.plmn = plmn
        self.s1ap = UDPServer(ip, S1MME, self.on_s1ap, name="eNB-S1AP")
        self.uu_nas = UDPServer(ip, UU_NAS, self.on_uu_nas, name="eNB-Uu-NAS")
        self.uu_data = UDPServer(ip, UU_DATA, self.on_uu_data, name="eNB-Uu-data")
        self.gtpu = GTPUNode(ip, GTPU, name="eNB")
        self.ue_addr = None
        self.enb_ue_id = None
        self.mme_ue_id = None
        self.sgw_s1u_teid = None
        self.dl_teid = 0xE0000001
        self.ebi = 5
        self.attached = False

    def start(self):
        self.s1ap.start()
        self.uu_nas.start()
        self.uu_data.start()
        self.gtpu.start()
        log("eNB up on %s (S1-MME->%s, S1-U->%s)" % (self.ip, self.mme_ip, self.sgwu_ip))

    def stop(self):
        self.s1ap.stop()
        self.uu_nas.stop()
        self.uu_data.stop()
        self.gtpu.stop()
        if getattr(self, "ctl", None):
            self.ctl.stop()

    # ------------------------------------------------------------- Uu -> EPC -
    def on_uu_nas(self, data, addr):
        self.ue_addr = addr
        try:
            m = nas.Message.from_bytes(data)
        except Exception:  # noqa
            return None
        dbg("eNB <- UE NAS %s" % m.name())
        if m.msg_type == nas.ATTACH_REQUEST:
            self.enb_ue_id = 7
            msg = s1ap.Message(s1ap.INITIAL_UE_MESSAGE, [
                s1ap.ie_enb_id(self.enb_ue_id), s1ap.ie_nas_pdu(data),
                s1ap.ie_tai(self.plmn, TAC), s1ap.ie_ecgi(self.plmn, ECGI)])
        else:
            msg = s1ap.Message(s1ap.UPLINK_NAS_TRANSPORT, [
                s1ap.ie_enb_id(self.enb_ue_id or 7),
                s1ap.ie_mme_id(self.mme_ue_id or 0), s1ap.ie_nas_pdu(data)])
        self.s1ap.send(msg.to_bytes(), (self.mme_ip, S1MME))
        return None

    def on_uu_data(self, data, addr):
        if self.sgw_s1u_teid is None:
            dbg("eNB: UL data before bearer set up; dropping")
            return None
        self.gtpu.send_gtpu(self.sgw_s1u_teid, self.sgwu_ip, GTPU, data)
        dbg("eNB: UL data %dB -> SGW-U (TEID 0x%X)" % (len(data), self.sgw_s1u_teid))
        return None

    # ------------------------------------------------------------- EPC -> Uu -
    def _to_ue(self, nas_bytes):
        addr = self.ue_addr or (self.ue_ip, UU_NAS)
        self.uu_nas.send(nas_bytes, addr)

    def on_s1ap(self, data, addr):
        try:
            msg = s1ap.Message.from_bytes(data)
        except Exception as e:  # noqa
            dbg("eNB: bad S1AP (%r)" % e)
            return None
        dbg("eNB <- %s" % msg.name())
        mid = msg.get(s1ap.IE_MME_UE_S1AP_ID)
        if mid:
            self.mme_ue_id = int.from_bytes(mid, "big")
        t = msg.msg_id
        if t == s1ap.DOWNLINK_NAS_TRANSPORT:
            self._to_ue(msg.get(s1ap.IE_NAS_PDU))
        elif t == s1ap.INITIAL_CONTEXT_SETUP_REQUEST:
            erabs = s1ap.decode_erab_list(msg.get(s1ap.IE_E_RAB_SETUP_LIST) or b"")
            if erabs:
                self.ebi, self.sgw_s1u_teid, _ = erabs[0]
            # programme DL: SGW-U -> eNB -> UE
            self.gtpu.add_route(self.dl_teid, self.ue_ip, UU_DATA, egress=True)
            nbytes = msg.get(s1ap.IE_NAS_PDU)
            if nbytes:
                self._to_ue(nbytes)
            resp = s1ap.Message(s1ap.INITIAL_CONTEXT_SETUP_RESPONSE, [
                s1ap.ie_enb_id(self.enb_ue_id or 7), s1ap.ie_mme_id(self.mme_ue_id or 0),
                s1ap.ie_erab_list([(self.ebi, self.dl_teid, self.ip)])])
            self.s1ap.send(resp.to_bytes(), (self.mme_ip, S1MME))
            self.attached = True
            log("eNB: UE context set up; S1-U bearer EBI=%d DL-TEID=0x%X (UL->SGW TEID=0x%X)"
                % (self.ebi, self.dl_teid, self.sgw_s1u_teid or 0))
        elif t == s1ap.UE_CONTEXT_RELEASE_COMMAND:
            self.attached = False
            self.sgw_s1u_teid = None
            resp = s1ap.Message(s1ap.UE_CONTEXT_RELEASE_COMPLETE, [
                s1ap.ie_enb_id(self.enb_ue_id or 7), s1ap.ie_mme_id(self.mme_ue_id or 0)])
            self.s1ap.send(resp.to_bytes(), (self.mme_ip, S1MME))
            log("eNB: UE context released")
        return None

    # ------------------------------------------------------------ control ---
    def enable_control(self, port):
        self.ctl = UDPServer(self.ip, port, self._ctl_handle, name="eNB-ctl")
        self.ctl.start()
        log("eNB: control socket on %s:%d" % (self.ip, port))

    def _ctl_handle(self, data, addr):
        parts = data.decode(errors="ignore").split()
        cmd = parts[0].upper() if parts else ""
        if cmd == "STATUS":
            reply = "OK eNB attached=%s ebi=%s sgw_s1u_teid=%s dl_teid=0x%X" % (
                self.attached, self.ebi,
                ("0x%X" % self.sgw_s1u_teid) if self.sgw_s1u_teid else "-", self.dl_teid)
        elif cmd == "GTPSTAT":
            reply = "OK eNB %s" % self.gtpu.stats
        else:
            reply = "ERR unknown %r" % cmd
        return (reply + "\n").encode()


def main(argv):
    enb = ENB()
    enb.start()
    if os.environ.get("ENB_CTL_PORT"):
        enb.enable_control(int(os.environ["ENB_CTL_PORT"]))
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        enb.stop()


if __name__ == "__main__":
    main(sys.argv[1:])
