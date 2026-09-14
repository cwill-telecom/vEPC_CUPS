#!/usr/bin/env python3
# core/epc_sgw_c.py — SGW-C for the full EPC: Sxa (PFCP) + S11 + S5-C (GTPv2-C).
#
# Reuses the CUPS CPF for the Sxa PFCP session toward the SGW-U, and adds:
#     MME   --S11--> SGW-C  (Create/Modify/Delete Session)
#     SGW-C --S5-C-> PGW-C
#
# On a Create Session Request it establishes the Sxa PFCP session (SGW-U allocates the
# S1-U F-TEIDu), allocates an SGW S5-U TEID, runs the S5-C exchange with the PGW-C, and
# programs the SGW-U GTP-U relay. A later Modify Bearer installs the DL route to the eNB.
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
from protocols import gtp_c
from utils.utils import log, dbg

# ---------------------------------------------------------------- config -----
SGWC_IP   = "127.0.0.4"
SGWU_IP   = "127.0.0.2"
PGWC_IP   = "127.0.0.5"
ENB_IP    = "127.0.0.11"
PFCP_PORT = 8805
GTPC_PORT = 2123
GTPU_PORT = 2152
SGWU_CTL_PORT = 8907
# -----------------------------------------------------------------------------


class SGW_C:
    def __init__(self, ip=SGWC_IP, sgw_u_ip=SGWU_IP, pgw_c_ip=PGWC_IP, enb_ip=ENB_IP,
                 base_seid=0x1000):
        self.ip = ip
        self.sgw_u_ip = sgw_u_ip
        self.enb_ip = enb_ip
        self.base_seid = base_seid
        self.cpf = CPF("SGW-C", ip, PFCP_PORT, base_seid=base_seid)
        self.cpf.add_peer(sgw_u_ip)
        self.s11 = UDPServer(ip, GTPC_PORT, self.handle_s11, name="SGW-C-S11")
        self.s5c = UDPClient(local_ip=ip)
        self.pgw_c = (pgw_c_ip, GTPC_PORT)
        self.ctx = {}                    # imsi -> dict
        self._s5u = 0x300000
        self.lock = threading.Lock()

    def start(self):
        self.cpf.start()
        for peer in self.cpf.peers.values():
            self.cpf.association_setup(peer)
        self.s11.start()
        log("SGW-C (EPC) ready on %s  S11:%d  S5-C->%s" % (self.ip, GTPC_PORT, self.pgw_c[0]))

    def stop(self):
        self.cpf.stop()
        self.s11.stop()

    def _next_s5u_teid(self):
        with self.lock:
            self._s5u += 1
            return self._s5u

    # ------------------------------------------------------------- S11 rx ----
    def handle_s11(self, data, addr):
        try:
            msg = gtp_c.Message.from_bytes(data)
        except Exception as e:  # noqa
            dbg("SGW-C: bad S11 from %s (%r)" % (addr, e))
            return None
        dbg("SGW-C <- %s from %s" % (msg.name(), addr[0]))
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
        bc = msg.get(gtp_c.IE_BEARER_CONTEXT)
        ebi = gtp_c.decode_bearer_context(bc).get("ebi", 5) if bc else 5

        # 1) S5-C -> PGW-C (bearer the SGW S5-U F-TEID)
        sgw_s5u = self._next_s5u_teid()
        req = gtp_c.Message(gtp_c.CREATE_SESSION_REQUEST, seq=msg.seq, ies=[
            gtp_c.ie_imsi(imsi), gtp_c.ie_apn(apn), gtp_c.ie_pdn_type(1),
            gtp_c.ie_f_teid(sgw_s5u, self.sgw_u_ip, gtp_c.IFACE_S5_S8_SGW),
            gtp_c.ie_f_teid(0x1000, self.ip, gtp_c.IFACE_S5_S8_SGW),
            gtp_c.ie_rat_type(6), gtp_c.ie_serving_network("00101"),
            gtp_c.ie_bearer_context(ebi)])
        rep, _ = self.s5c.request(req.to_bytes(), self.pgw_c[0], self.pgw_c[1], timeout=4.0)
        if rep is None:
            log("SGW-C: no S5-C answer from PGW-C")
            return gtp_c.Message(gtp_c.CREATE_SESSION_RESPONSE, seq=msg.seq,
                                 ies=[gtp_c.ie_cause(2)]).to_bytes()
        r = gtp_c.Message.from_bytes(rep)
        pgw_teid, pgw_ip, _ = gtp_c.decode_f_teid(r.get(gtp_c.IE_F_TEID)) \
            if r.get(gtp_c.IE_F_TEID) else (0, self.pgw_c[0], 0)
        ue_ip = gtp_c.decode_paa(r.get(gtp_c.IE_PAA)) if r.get(gtp_c.IE_PAA) else "10.10.0.2"
        ambr = gtp_c.decode_ambr(r.get(gtp_c.IE_AMBR)) if r.get(gtp_c.IE_AMBR) else (100000, 200000)

        # 2) Sxa PFCP session on the SGW-U (allocates the S1-U F-TEIDu)
        peer = self.cpf.peers.get(self.sgw_u_ip)
        s = self.cpf.session_establish(peer, ue_ip=ue_ip)
        if s is None:
            return gtp_c.Message(gtp_c.CREATE_SESSION_RESPONSE, seq=msg.seq,
                                 ies=[gtp_c.ie_cause(2)]).to_bytes()
        sgw_s1u_teid = s.pdrs[1].fteid[0] if s.pdrs.get(1) and s.pdrs[1].fteid else 0

        # 3) program the SGW-U relay: UL S1-U -> PGW-U S5-U
        self._ctl("ROUTE 0x%X %s %d 0x%X" % (sgw_s1u_teid, pgw_ip or self.pgw_c[0] or "127.0.0.3",
                                              GTPU_PORT, pgw_teid))
        self.ctx[imsi] = {"seid": s.seid, "s1u": sgw_s1u_teid, "s5u": sgw_s5u,
                          "pgw_teid": pgw_teid, "pgw_ip": pgw_ip, "ue_ip": ue_ip,
                          "ebi": ebi, "ambr": ambr, "enb_dl": None}
        log("SGW-C: Sx session 0x%X for IMSI %s UE-IP=%s (SGW S1-U TEID=0x%X, "
            "SGW S5-U TEID=0x%X, PGW S5-U TEID=0x%X)"
            % (s.seid, imsi, ue_ip, sgw_s1u_teid, sgw_s5u, pgw_teid))

        ies = [gtp_c.ie_cause(16), gtp_c.ie_imsi(imsi),
               gtp_c.ie_f_teid(sgw_s1u_teid, self.sgw_u_ip, gtp_c.IFACE_S1U_SGW),
               gtp_c.ie_f_teid(0x1000, self.ip, gtp_c.IFACE_S1U_SGW),
               gtp_c.ie_paa(ue_ip), gtp_c.ie_ambr(*ambr),
               gtp_c.ie_bearer_context(ebi, fteid=(sgw_s1u_teid, self.sgw_u_ip,
                                                   gtp_c.IFACE_S1U_SGW), cause=16)]
        return gtp_c.Message(gtp_c.CREATE_SESSION_RESPONSE, seq=msg.seq, ies=ies).to_bytes()

    def _modify_bearer(self, msg, addr):
        imsi = gtp_c.decode_imsi(msg.get(gtp_c.IE_IMSI)) if msg.get(gtp_c.IE_IMSI) else "-"
        s = self.ctx.get(imsi)
        ies = [gtp_c.ie_cause(16)]
        if s is not None:
            enb_teid = None
            bc = msg.get(gtp_c.IE_BEARER_CONTEXT)
            if bc:
                enb_teid = gtp_c.decode_bearer_context(bc).get("f_teid")
            if enb_teid is None and msg.get(gtp_c.IE_F_TEID):
                enb_teid = gtp_c.decode_f_teid(msg.get(gtp_c.IE_F_TEID))
            if enb_teid:
                s["enb_dl"] = enb_teid[0]
                # DL route: SGW S5-U -> eNB S1-U
                self._ctl("ROUTE 0x%X %s %d 0x%X" % (s["s5u"], self.enb_ip, GTPU_PORT,
                                                     enb_teid[0]))
                log("SGW-C: installed DL route S5-U TEID 0x%X -> eNB %s (TEID 0x%X)"
                    % (s["s5u"], self.enb_ip, enb_teid[0]))
            ies.append(gtp_c.ie_f_teid(s["s1u"], self.sgw_u_ip, gtp_c.IFACE_S1U_SGW))
        log("SGW-C: S11 Modify Bearer for IMSI %s" % imsi)
        return gtp_c.Message(gtp_c.MODIFY_BEARER_RESPONSE, seq=msg.seq, ies=ies).to_bytes()

    def _delete_session(self, msg, addr):
        imsi = gtp_c.decode_imsi(msg.get(gtp_c.IE_IMSI)) if msg.get(gtp_c.IE_IMSI) else "-"
        s = self.ctx.pop(imsi, None)
        if s:
            self.cpf.session_delete(s["seid"])
            req = gtp_c.Message(gtp_c.DELETE_SESSION_REQUEST, seq=msg.seq,
                                ies=[gtp_c.ie_imsi(imsi)])
            self.s5c.request(req.to_bytes(), self.pgw_c[0], self.pgw_c[1], timeout=3.0)
            log("SGW-C: Sx session 0x%X for IMSI %s deleted" % (s["seid"], imsi))
        return gtp_c.Message(gtp_c.DELETE_SESSION_RESPONSE, seq=msg.seq,
                             ies=[gtp_c.ie_cause(16)]).to_bytes()

    # ------------------------------------------------------------- helpers ---
    @staticmethod
    def _ctl(cmd):
        try:
            c = UDPClient()
            c.request(cmd.encode(), SGWU_IP, SGWU_CTL_PORT, 2.0)
            c.close()
        except Exception as e:  # noqa
            dbg("SGW-C: ctl %r -> %r" % (cmd, e))


def main(argv):
    sgw_c = SGW_C()
    sgw_c.start()
    if os.environ.get("CPF_CTL_PORT"):
        sgw_c.cpf.enable_control(int(os.environ["CPF_CTL_PORT"]))
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        sgw_c.stop()


if __name__ == "__main__":
    main(sys.argv[1:])
