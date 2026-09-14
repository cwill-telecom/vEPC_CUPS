#!/usr/bin/env python3
# core/epc_pgw_c.py — PGW-C for the full EPC: Sxb (PFCP) + S5-C (GTPv2-C) + Gx (Diameter).
#
# Reuses the CUPS CPF for the Sxb PFCP session toward the PGW-U, and adds the EPC
# control-plane legs:
#     SGW-C --S5-C--> PGW-C  (Create/Modify/Delete Session)
#     PGW-C --Gx----> PCRF   (Credit-Control, policy/QoS)
#
# On a Create Session Request it: queries the PCRF for the authorized QoS, establishes
# the Sxb PFCP session on the PGW-U, allocates the UE IP (PAA), programs the PGW-U GTP-U
# relay (S5-U <-> SGi), and answers the SGW-C.
import os
import socket
import struct
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.cpf import CPF
from network.udp_server import UDPServer
from network.udp_client import UDPClient
from protocols import gtp_c, diameter as D
from utils.utils import log, dbg

# ---------------------------------------------------------------- config -----
PGWC_IP      = "127.0.0.5"
PGWU_IP      = "127.0.0.3"
PCRF_IP      = "127.0.0.14"
PDN_IP       = "127.0.0.15"
PDN_PORT     = 9999
PFCP_PORT    = 8805
GTPC_PORT    = 2123
GTPU_PORT    = 2152
PGWU_CTL_PORT = 8908
UE_POOL_START = "10.10.0.2"
# -----------------------------------------------------------------------------


def _next_ip(base_ip, n):
    parts = list(map(int, base_ip.split(".")))
    v = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]
    return socket.inet_ntoa(struct.pack("!I", v + n))


class PGW_C:
    def __init__(self, ip=PGWC_IP, pgw_u_ip=PGWU_IP, pcrf_ip=PCRF_IP,
                 base_seid=0x2000):
        self.ip = ip
        self.pgw_u_ip = pgw_u_ip
        self.base_seid = base_seid
        self.cpf = CPF("PGW-C", ip, PFCP_PORT, base_seid=base_seid)
        self.cpf.add_peer(pgw_u_ip)
        self.s5c = UDPServer(ip, GTPC_PORT, self.handle_s5c, name="PGW-C-S5C")
        self.gx = UDPClient(local_ip=ip)
        self.pcrf = (pcrf_ip, 3868)
        self.ctx = {}                    # imsi -> dict
        self._ue_n = 0
        self._ccn = 0
        self.lock = threading.Lock()

    def start(self):
        self.cpf.start()
        for peer in self.cpf.peers.values():
            self.cpf.association_setup(peer)
        self.s5c.start()
        log("PGW-C (EPC) ready on %s  S5-C:%d  Gx->%s" % (self.ip, GTPC_PORT, self.pcrf[0]))

    def stop(self):
        self.cpf.stop()
        self.s5c.stop()

    # ---------------------------------------------------------- Gx to PCRF ---
    def _gx_ccr(self, imsi, ctype, ue_ip=None):
        with self.lock:
            self._ccn += 1
            ccn = self._ccn
        msg = D.Message(D.CMD_CREDIT_CONTROL, D.GX_APP, hop_id=ccn, end_id=ccn, avps=[
            D.avp(D.AVP_SESSION_ID, "%s;%d" % (self.ip, ccn)),
            D.avp(D.AVP_ORIGIN_HOST, "pgw-c.epc.mnc001.mcc001.3gppnetwork.org"),
            D.avp(D.AVP_DESTINATION_REALM, "epc.mnc001.mcc001.3gppnetwork.org"),
            D.avp(D.AVP_AUTH_SESSION_STATE, bytes([D.NO_STATE_MAINTAINED])),
            D.group(D.AVP_SUBSCRIPTION_ID, [D.avp_u32(D.AVP_SUBSCRIPTION_ID_TYPE, 1),
                                            D.avp(D.AVP_SUBSCRIPTION_ID_DATA, imsi)]),
            D.avp_u32(D.AVP_CC_REQUEST_TYPE, ctype),
            D.avp_u32(D.AVP_CC_REQUEST_NUMBER, ccn),
        ])
        rep, _ = self.gx.request(msg.to_bytes(), self.pcrf[0], self.pcrf[1], timeout=3.0)
        if rep is None:
            dbg("PGW-C: no Gx answer from PCRF")
            return {"qci": 9, "mbr_ul": 100000, "mbr_dl": 200000}
        from core.pcrf import parse_qos
        return parse_qos(D.Message.from_bytes(rep))

    # ------------------------------------------------------------- S5-C rx ---
    def handle_s5c(self, data, addr):
        try:
            msg = gtp_c.Message.from_bytes(data)
        except Exception as e:  # noqa
            dbg("PGW-C: bad S5-C from %s (%r)" % (addr, e))
            return None
        dbg("PGW-C <- %s from %s" % (msg.name(), addr[0]))
        if msg.msg_type == gtp_c.CREATE_SESSION_REQUEST:
            return self._create_session(msg, addr)
        if msg.msg_type == gtp_c.MODIFY_BEARER_REQUEST:
            return self._modify_bearer(msg, addr)
        if msg.msg_type == gtp_c.DELETE_SESSION_REQUEST:
            return self._delete_session(msg, addr)
        return None

    def _create_session(self, msg, addr):
        imsi = gtp_c.decode_imsi(msg.get(gtp_c.IE_IMSI)) if msg.get(gtp_c.IE_IMSI) else "-"
        apn = gtp_c.decode_apn(msg.get(gtp_c.IE_APN)) if msg.get(gtp_c.IE_APN) else "internet"
        sgw_teid, sgw_ip, _ = gtp_c.decode_f_teid(msg.get(gtp_c.IE_F_TEID)) \
            if msg.get(gtp_c.IE_F_TEID) else (0, addr[0], 0)
        bc = msg.get(gtp_c.IE_BEARER_CONTEXT)
        ebi = gtp_c.decode_bearer_context(bc).get("ebi", 5) if bc else 5

        # 1) policy from the PCRF
        qos = self._gx_ccr(imsi, D.CC_INITIAL)
        with self.lock:
            ue_ip = _next_ip(UE_POOL_START, self._ue_n)
            self._ue_n += 1

        # 2) Sxb PFCP session on the PGW-U (allocates the PGW S5-U F-TEIDu)
        peer = self.cpf.peers.get(self.pgw_u_ip)
        s = self.cpf.session_establish(peer, ue_ip=ue_ip)
        if s is None:
            return gtp_c.Message(gtp_c.CREATE_SESSION_RESPONSE, seq=msg.seq,
                                 ies=[gtp_c.ie_cause(2)]).to_bytes()   # rejected
        pgw_teid, pgw_ip = (s.pdrs[1].fteid if s.pdrs.get(1) and s.pdrs[1].fteid
                            else (0, self.pgw_u_ip))

        # 3) program the PGW-U GTP-U relay: S5-U(UL) -> SGi egress; SGi(DL) -> SGW-U
        self._ctl(self.pgw_u_ip, "ROUTE 0x%X %s %d -" % (pgw_teid, PDN_IP, PDN_PORT))
        self._ctl(self.pgw_u_ip, "SGI %s %d 0x%X" % (sgw_ip or addr[0], GTPU_PORT, sgw_teid))

        self.ctx[imsi] = {"pgw_teid": pgw_teid, "sgw_teid": sgw_teid, "sgw_ip": addr[0],
                          "ue_ip": ue_ip, "ebi": ebi, "qos": qos, "seid": s.seid}
        log("PGW-C: PDN session for IMSI %s UE-IP=%s EBI=%d QCI=%d (PGW S5-U TEID=0x%X)"
            % (imsi, ue_ip, ebi, qos["qci"], pgw_teid))

        ies = [gtp_c.ie_cause(16), gtp_c.ie_imsi(imsi),
               gtp_c.ie_f_teid(pgw_teid, self.pgw_u_ip, gtp_c.IFACE_S5_S8_PGW),
               gtp_c.ie_f_teid(s.seid & 0xFFFFFFFF, self.ip, gtp_c.IFACE_S5_S8_PGW),
               gtp_c.ie_paa(ue_ip),
               gtp_c.ie_ambr(qos.get("mbr_ul", 100000), qos.get("mbr_dl", 200000)),
               gtp_c.ie_bearer_context(ebi, fteid=(pgw_teid, self.pgw_u_ip,
                                                   gtp_c.IFACE_S5_S8_PGW), cause=16,
                                       charging_id=0x2000 + self._ue_n)]
        return gtp_c.Message(gtp_c.CREATE_SESSION_RESPONSE, seq=msg.seq, ies=ies).to_bytes()

    def _modify_bearer(self, msg, addr):
        imsi = gtp_c.decode_imsi(msg.get(gtp_c.IE_IMSI)) if msg.get(gtp_c.IE_IMSI) else "-"
        s = self.ctx.get(imsi)
        ies = [gtp_c.ie_cause(16)]
        if s is not None:
            ies.append(gtp_c.ie_f_teid(s["pgw_teid"], self.pgw_u_ip, gtp_c.IFACE_S5_S8_PGW))
            ies.append(gtp_c.ie_bearer_context(s["ebi"], fteid=(s["pgw_teid"], self.pgw_u_ip,
                                                               gtp_c.IFACE_S5_S8_PGW), cause=16))
        log("PGW-C: S5-C Modify Bearer for IMSI %s" % imsi)
        return gtp_c.Message(gtp_c.MODIFY_BEARER_RESPONSE, seq=msg.seq, ies=ies).to_bytes()

    def _delete_session(self, msg, addr):
        imsi = gtp_c.decode_imsi(msg.get(gtp_c.IE_IMSI)) if msg.get(gtp_c.IE_IMSI) else "-"
        s = self.ctx.pop(imsi, None)
        if s:
            self.cpf.session_delete(s["seid"])
            self._gx_ccr(imsi, D.CC_TERMINATION)
            log("PGW-C: PDN session for IMSI %s deleted" % imsi)
        return gtp_c.Message(gtp_c.DELETE_SESSION_RESPONSE, seq=msg.seq,
                             ies=[gtp_c.ie_cause(16)]).to_bytes()

    # ------------------------------------------------------------- helpers ---
    @staticmethod
    def _ctl(upf_ip, cmd):
        try:
            c = UDPClient()
            c.request(cmd.encode(), upf_ip, PGWU_CTL_PORT, 2.0)
            c.close()
        except Exception as e:  # noqa
            dbg("PGW-C: ctl %r -> %r" % (cmd, e))


def main(argv):
    pgw_c = PGW_C()
    pgw_c.start()
    if os.environ.get("CPF_CTL_PORT"):
        pgw_c.cpf.enable_control(int(os.environ["CPF_CTL_PORT"]))
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pgw_c.stop()


if __name__ == "__main__":
    main(sys.argv[1:])
