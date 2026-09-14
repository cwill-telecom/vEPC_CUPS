#!/usr/bin/env python3
# core/mme.py — Mobility Management Entity: S1-MME (S1AP) + S6a (Diameter) + S11 (GTPv2-C).
#
# Orchestrates the EPS attach procedure end-to-end:
#   1. InitialUEMessage(Attach Request)        <- eNB
#   2. AIR/AIA with the HSS (authentication)   <-> HSS
#   3. Authentication Request / Response       -> eNB -> UE
#   4. Security Mode Command / Complete        -> eNB -> UE
#   5. S11 Create Session (SGW-C -> PGW-C -> PCRF + PFCP to the UPFs)
#   6. InitialContextSetupRequest(Attach Accept + S1-U F-TEID) -> eNB
#   7. InitialContextSetupResponse(eNB S1-U F-TEID) -> S11 Modify Bearer
# Detach reverses the session (S11 Delete Session + UE Context Release).
import os
import socket
import struct
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from network.udp_server import UDPServer
from network.udp_client import UDPClient
from protocols import s1ap, nas, gtp_c, diameter as D
from core.hss import parse_auth_info
from utils.utils import log, dbg

# ---------------------------------------------------------------- config -----
MME_IP   = "127.0.0.12"
ENB_IP   = "127.0.0.11"
SGWU_IP  = "127.0.0.2"
SGWC_IP  = "127.0.0.4"
HSS_IP   = "127.0.0.13"
S1MME    = 36412
GTPC     = 2123
DIAM     = 3868
PLMN     = "00101"
TAC      = 1
MME_ORIGIN_HOST = "mme.epc.mnc001.mcc001.3gppnetwork.org"
# -----------------------------------------------------------------------------


class MME:
    def __init__(self, ip=MME_IP, sgwc_ip=SGWC_IP, hss_ip=HSS_IP, plmn=PLMN):
        self.ip = ip
        self.sgwc_ip = sgwc_ip
        self.hss_ip = hss_ip
        self.plmn = plmn
        self.s1ap = UDPServer(ip, S1MME, self.on_s1ap, name="MME-S1AP")
        self.s6a = UDPClient(local_ip=ip)
        self.s11 = UDPClient(local_ip=ip)
        self.ctx = {}                    # enb_ue_id -> context
        self.enb_addr = None
        self._mme_ue = 0x1000
        self._ccn = 0
        self.lock = threading.Lock()

    def start(self):
        self.s1ap.start()
        log("MME up on %s (S11->%s, S6a->%s)" % (self.ip, self.sgwc_ip, self.hss_ip))

    def stop(self):
        self.s1ap.stop()
        if getattr(self, "ctl", None):
            self.ctl.stop()

    # -------------------------------------------------------------- S6a ----
    def _air(self, imsi):
        with self.lock:
            self._ccn += 1
            n = self._ccn
        msg = D.Message(D.CMD_AUTH_INFO, D.S6A_APP, hop_id=n, end_id=n, avps=[
            D.avp(D.AVP_SESSION_ID, "%s;%d" % (self.ip, n)),
            D.avp(D.AVP_ORIGIN_HOST, MME_ORIGIN_HOST),
            D.avp(D.AVP_DESTINATION_REALM, "epc.mnc001.mcc001.3gppnetwork.org"),
            D.avp(D.AVP_AUTH_SESSION_STATE, bytes([D.NO_STATE_MAINTAINED])),
            D.group(D.AVP_SUBSCRIPTION_ID, [D.avp_u32(D.AVP_SUBSCRIPTION_ID_TYPE, 1),
                                            D.avp(D.AVP_SUBSCRIPTION_ID_DATA, imsi)]),
            D.avp_u32(D.AVP_REQUESTED_EUTRAN_AUTH_INFO, 1, D.VENDOR_3GPP),
        ])
        rep, _ = self.s6a.request(msg.to_bytes(), self.hss_ip, DIAM, timeout=3.0)
        if rep is None:
            dbg("MME: no AIA from HSS")
            return None
        aia = D.Message.from_bytes(rep)
        rc = aia.get(D.AVP_RESULT_CODE)
        if rc and rc.u32() != D.DIAMETER_SUCCESS:
            log("MME: HSS returned result-code %d (unknown subscriber?)" % rc.u32())
            return None
        ai = aia.get(D.AVP_AUTHENTICATION_INFO, D.VENDOR_3GPP)
        vec = parse_auth_info(ai) if ai else None
        log("MME: <- AIA from HSS (IMSI %s, %d vector)" % (imsi, vec["n"] if vec else 0))
        return vec

    # -------------------------------------------------------------- S11 ----
    def _s11_create(self, imsi, apn, ebi=5):
        req = gtp_c.Message(gtp_c.CREATE_SESSION_REQUEST, seq=1, ies=[
            gtp_c.ie_imsi(imsi), gtp_c.ie_apn(apn), gtp_c.ie_pdn_type(1),
            gtp_c.ie_f_teid(0x400000, self.ip, gtp_c.IFACE_S1U_SGW),
            gtp_c.ie_rat_type(6), gtp_c.ie_serving_network(self.plmn),
            gtp_c.ie_uli(self.plmn, TAC, 0x0001),
            gtp_c.ie_bearer_context(ebi, fteid=(0x400000, self.ip, gtp_c.IFACE_S1U_SGW))])
        rep, _ = self.s11.request(req.to_bytes(), self.sgwc_ip, GTPC, timeout=5.0)
        if rep is None:
            log("MME: no S11 Create Session Response from SGW-C")
            return None
        r = gtp_c.Message.from_bytes(rep)
        teid = ip = None
        f = r.get(gtp_c.IE_F_TEID)
        if f:
            teid, ip, _ = gtp_c.decode_f_teid(f)
        ue_ip = gtp_c.decode_paa(r.get(gtp_c.IE_PAA)) if r.get(gtp_c.IE_PAA) else None
        ambr = gtp_c.decode_ambr(r.get(gtp_c.IE_AMBR)) if r.get(gtp_c.IE_AMBR) else (0, 0)
        log("MME: <- S11 Create Session Response (SGW S1-U TEID=0x%X @ %s, UE-IP=%s)"
            % (teid or 0, ip, ue_ip))
        return {"sgw_s1u_teid": teid, "sgw_s1u_ip": ip or SGWU_IP, "ue_ip": ue_ip,
                "ambr": ambr, "ebi": ebi}

    def _s11_modify(self, imsi, enb_teid):
        req = gtp_c.Message(gtp_c.MODIFY_BEARER_REQUEST, seq=2, ies=[
            gtp_c.ie_imsi(imsi),
            gtp_c.ie_bearer_context(5, fteid=(enb_teid, ENB_IP, gtp_c.IFACE_S1U_ENB))])
        self.s11.request(req.to_bytes(), self.sgwc_ip, GTPC, timeout=4.0)

    def _s11_delete(self, imsi):
        req = gtp_c.Message(gtp_c.DELETE_SESSION_REQUEST, seq=3,
                            ies=[gtp_c.ie_imsi(imsi)])
        self.s11.request(req.to_bytes(), self.sgwc_ip, GTPC, timeout=4.0)

    # -------------------------------------------------------------- S1AP ----
    def _send(self, msg):
        self.s1ap.send(msg.to_bytes(), self.enb_addr or (ENB_IP, S1MME))

    def _dl(self, enb_id, mme_id, nas_bytes):
        self._send(s1ap.Message(s1ap.DOWNLINK_NAS_TRANSPORT, [
            s1ap.ie_enb_id(enb_id), s1ap.ie_mme_id(mme_id), s1ap.ie_nas_pdu(nas_bytes)]))

    def on_s1ap(self, data, addr):
        self.enb_addr = addr
        try:
            msg = s1ap.Message.from_bytes(data)
        except Exception as e:  # noqa
            dbg("MME: bad S1AP (%r)" % e)
            return None
        eid = msg.get(s1ap.IE_ENB_UE_S1AP_ID)
        enb_id = int.from_bytes(eid, "big") if eid else 0
        dbg("MME <- %s (eNB-UE %s)" % (msg.name(), enb_id))

        if msg.msg_id == s1ap.INITIAL_UE_MESSAGE:
            return self._on_initial_ue(enb_id, msg)
        if msg.msg_id == s1ap.UPLINK_NAS_TRANSPORT:
            return self._on_ul_nas(enb_id, msg)
        if msg.msg_id == s1ap.INITIAL_CONTEXT_SETUP_RESPONSE:
            return self._on_ctx_setup_resp(enb_id, msg)
        return None

    def _on_initial_ue(self, enb_id, msg):
        nas_bytes = msg.get(s1ap.IE_NAS_PDU)
        try:
            nm = nas.Message.from_bytes(nas_bytes)
        except Exception:  # noqa
            return None
        if nm.msg_type != nas.ATTACH_REQUEST:
            return None
        imsi = nas.decode_imsi(nm.get(nas.IE_IMSI))
        apn = nas.decode_apn(nm.get(nas.IE_APN)) if nm.get(nas.IE_APN) else "internet"
        with self.lock:
            self._mme_ue += 1
            mme_id = self._mme_ue
        self.ctx[enb_id] = {"imsi": imsi, "apn": apn, "mme_id": mme_id}
        log("MME: Attach Request (IMSI %s, APN %s) from eNB %s [MME-UE-S1AP-ID=%d]"
            % (imsi, apn, self.enb_addr[0], mme_id))
        vec = self._air(imsi)
        if vec is None:
            self._send(s1ap.Message(s1ap.DOWNLINK_NAS_TRANSPORT, [
                s1ap.ie_enb_id(enb_id), s1ap.ie_mme_id(mme_id),
                s1ap.ie_nas_pdu(nas.Message(nas.ATTACH_REJECT, []).to_bytes())]))
            return None
        self.ctx[enb_id]["rand"] = vec["rand"]
        self.ctx[enb_id]["xres"] = vec["xres"]
        self._dl(enb_id, mme_id, nas.Message(nas.AUTH_REQUEST, [
            nas.ie_rand(vec["rand"]), nas.ie_autn(vec["autn"])]).to_bytes())
        return None

    def _on_ul_nas(self, enb_id, msg):
        ctx = self.ctx.get(enb_id)
        if ctx is None:
            return None
        nm = nas.Message.from_bytes(msg.get(s1ap.IE_NAS_PDU))
        mme_id = ctx["mme_id"]
        if nm.msg_type == nas.AUTH_RESPONSE:
            res = nm.get(nas.IE_RES)
            if res == ctx.get("xres"):
                log("MME: UE authenticated (RES verified)")
                self._dl(enb_id, mme_id, nas.Message(nas.SECURITY_MODE_COMMAND, []).to_bytes())
            else:
                log("MME: authentication FAILED for IMSI %s" % ctx["imsi"])
                self._dl(enb_id, mme_id, nas.Message(nas.ATTACH_REJECT, []).to_bytes())
        elif nm.msg_type == nas.SECURITY_MODE_COMPLETE:
            s = self._s11_create(ctx["imsi"], ctx["apn"])
            if s is None:
                self._dl(enb_id, mme_id, nas.Message(nas.ATTACH_REJECT, []).to_bytes())
                return None
            ctx.update(s)
            accept = nas.Message(nas.ATTACH_ACCEPT, [
                nas.ie_ue_ip(s["ue_ip"]), nas.ie_ebi(s["ebi"]),
                nas.ie_ambr(int(s["ambr"][0] / 1000) if s["ambr"][0] else 100,
                            int(s["ambr"][1] / 1000) if s["ambr"][1] else 200)])
            self._send(s1ap.Message(s1ap.INITIAL_CONTEXT_SETUP_REQUEST, [
                s1ap.ie_enb_id(enb_id), s1ap.ie_mme_id(mme_id),
                s1ap.ie_erab_list([(s["ebi"], s["sgw_s1u_teid"], s["sgw_s1u_ip"])]),
                s1ap.ie_ue_ambr(int(s["ambr"][0] / 1000), int(s["ambr"][1] / 1000)),
                s1ap.ie_nas_pdu(accept.to_bytes())]))
            log("MME: -> InitialContextSetupRequest (Attach Accept, UE-IP=%s)" % s["ue_ip"])
        elif nm.msg_type == nas.ATTACH_COMPLETE:
            log("MME: Attach Complete from UE")
        elif nm.msg_type == nas.DETACH_REQUEST:
            self._s11_delete(ctx["imsi"])
            self._dl(enb_id, mme_id, nas.Message(nas.DETACH_ACCEPT, []).to_bytes())
            self._send(s1ap.Message(s1ap.UE_CONTEXT_RELEASE_COMMAND, [
                s1ap.ie_enb_id(enb_id), s1ap.ie_mme_id(mme_id), s1ap.ie_cause(18)]))
            log("MME: Detach Request -> session deleted, UE context release")
        return None

    def _on_ctx_setup_resp(self, enb_id, msg):
        ctx = self.ctx.get(enb_id)
        if ctx is None:
            return None
        erabs = s1ap.decode_erab_list(msg.get(s1ap.IE_E_RAB_SETUP_LIST) or b"")
        if erabs and ctx.get("imsi"):
            _, enb_teid, _ = erabs[0]
            self._s11_modify(ctx["imsi"], enb_teid)
            log("MME: -> S11 Modify Bearer (eNB S1-U TEID=0x%X)" % enb_teid)
        return None

    # ------------------------------------------------------------ control ---
    def enable_control(self, port):
        self.ctl = UDPServer(self.ip, port, self._ctl_handle, name="MME-ctl")
        self.ctl.start()
        log("MME: control socket on %s:%d" % (self.ip, port))

    def _ctl_handle(self, data, addr):
        parts = data.decode(errors="ignore").split()
        cmd = parts[0].upper() if parts else ""
        if cmd == "STATUS":
            enb = self.enb_addr[0] if self.enb_addr else "-"
            reply = "OK MME contexts=%d enb=%s" % (len(self.ctx), enb)
        elif cmd == "UES":
            reply = "OK MME %s" % ",".join(
                "%s/ueid%d" % (c.get("imsi", "-"), c.get("mme_id", 0))
                for c in self.ctx.values()) or "-"
        else:
            reply = "ERR unknown %r" % cmd
        return (reply + "\n").encode()


def main(argv):
    mme = MME()
    mme.start()
    if os.environ.get("MME_CTL_PORT"):
        mme.enable_control(int(os.environ["MME_CTL_PORT"]))
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        mme.stop()


if __name__ == "__main__":
    main(sys.argv[1:])
