# protocols/s1ap.py — minimal S1 Application Protocol (TS 36.413) for S1-MME.
#
# SIMPLIFIED: a flat TLV encoding ([IEI:1][len:2][value]) is used instead of the real
# ASN.1 APER encoding. It carries the S1 messages required for the attach procedure
# (Initial UE Message, Downlink/Uplink NAS Transport, Initial Context Setup, UE Context
# Release) so the signalling is explicit and debuggable on the wire.
import struct

# S1AP message (procedure) identifiers — subset.
S1_SETUP_REQUEST                 = 17
S1_SETUP_RESPONSE                = 18
INITIAL_UE_MESSAGE               = 12
DOWNLINK_NAS_TRANSPORT           = 13
UPLINK_NAS_TRANSPORT             = 11
INITIAL_CONTEXT_SETUP_REQUEST    = 9
INITIAL_CONTEXT_SETUP_RESPONSE   = 10
UE_CONTEXT_RELEASE_REQUEST       = 18
UE_CONTEXT_RELEASE_COMMAND       = 23
UE_CONTEXT_RELEASE_COMPLETE      = 24
INITIAL_CONTEXT_SETUP_FAILURE    = 19
ERROR_INDICATION                 = 2

MSG_NAMES = {
    S1_SETUP_REQUEST: "S1Setup Request", S1_SETUP_RESPONSE: "S1Setup Response",
    INITIAL_UE_MESSAGE: "InitialUEMessage", DOWNLINK_NAS_TRANSPORT: "DownlinkNASTransport",
    UPLINK_NAS_TRANSPORT: "UplinkNASTransport",
    INITIAL_CONTEXT_SETUP_REQUEST: "InitialContextSetupRequest",
    INITIAL_CONTEXT_SETUP_RESPONSE: "InitialContextSetupResponse",
    UE_CONTEXT_RELEASE_REQUEST: "UEContextReleaseRequest",
    UE_CONTEXT_RELEASE_COMMAND: "UEContextReleaseCommand",
    UE_CONTEXT_RELEASE_COMPLETE: "UEContextReleaseComplete",
    INITIAL_CONTEXT_SETUP_FAILURE: "InitialContextSetupFailure",
    ERROR_INDICATION: "ErrorIndication",
}

# Simplified S1AP IE identifiers.
IE_ENB_UE_S1AP_ID   = 0x01
IE_MME_UE_S1AP_ID   = 0x02
IE_NAS_PDU          = 0x03
IE_TAI              = 0x04    # PLMN(3) + TAC(2)
IE_ECGI             = 0x05    # PLMN(3) + cell id(4)
IE_RRC_EST_CAUSE    = 0x06
IE_E_RAB_SETUP      = 0x07    # EBI(1) + TEID(4) + IPv4(4)  (S1-U transport)
IE_E_RAB_SETUP_LIST = 0x08    # concatenated IE_E_RAB_SETUP records
IE_UE_IP            = 0x09
IE_CAUSE            = 0x0a
IE_UE_AMBR          = 0x0b    # UL(kbps):2 + DL(kbps):2


class Message:
    def __init__(self, msg_id, ies=None):
        self.msg_id = msg_id
        self.ies = [(t, bytes(v)) for t, v in (ies or [])]

    def add_ie(self, ie, value):
        self.ies.append((ie, bytes(value)))

    def get(self, ie):
        for t, v in self.ies:
            if t == ie:
                return v
        return None

    def name(self):
        return MSG_NAMES.get(self.msg_id, "S1AP %d" % self.msg_id)

    def to_bytes(self):
        body = b"".join(struct.pack("!BH", t, len(v)) + v for t, v in self.ies)
        return struct.pack("!BH", self.msg_id, len(body)) + body

    @classmethod
    def from_bytes(cls, data):
        if len(data) < 3:
            raise ValueError("short S1AP PDU")
        mid, ln = struct.unpack("!BH", data[:3])
        ies, i = [], 3
        while i + 3 <= len(data):
            t, l = struct.unpack("!BH", data[i:i + 3])
            i += 3
            ies.append((t, data[i:i + l]))
            i += l
        return cls(mid, ies)

    def dump(self):
        return "\n".join([self.name()] + ["    - ie 0x%02x [%d] %s" % (t, len(v), v.hex())
                                          for t, v in self.ies])


# ------------------------------------------------------------------ helpers ---
def ie_enb_id(v):     return (IE_ENB_UE_S1AP_ID, struct.pack("!I", v))
def ie_mme_id(v):     return (IE_MME_UE_S1AP_ID, struct.pack("!I", v))
def ie_nas_pdu(b):    return (IE_NAS_PDU, b)
def ie_tai(plmn, tac): return (IE_TAI, plmn.encode() + struct.pack("!H", tac))
def ie_ecgi(plmn, cid): return (IE_ECGI, plmn.encode() + struct.pack("!I", cid))
def ie_cause(v):      return (IE_CAUSE, struct.pack("!B", v))
def ie_ue_ambr(ul, dl): return (IE_UE_AMBR, struct.pack("!HH", ul, dl))
def ie_erab_setup(ebi, teid, ip):
    return (IE_E_RAB_SETUP, struct.pack("!B", ebi) + struct.pack("!I", teid) +
            __import__("socket").inet_aton(ip))
def ie_erab_list(entries):
    return (IE_E_RAB_SETUP_LIST, b"".join(ie_erab_setup(*e)[1] for e in entries))


def decode_erab(value):
    ebi = value[0]
    teid = struct.unpack("!I", value[1:5])[0]
    ip = __import__("socket").inet_ntoa(value[5:9])
    return ebi, teid, ip


def decode_erab_list(value):
    out, i = [], 0
    while i + 9 <= len(value):
        out.append(decode_erab(value[i:i + 9]))
        i += 9
    return out


if __name__ == "__main__":
    import os, sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from protocols import nas
    nas_msg = nas.Message(nas.ATTACH_REQUEST, [nas.ie_imsi("001010000000001")])
    m = Message(INITIAL_UE_MESSAGE, [ie_enb_id(7), ie_nas_pdu(nas_msg.to_bytes()),
                                     ie_tai("00101", 1)])
    raw = m.to_bytes()
    back = Message.from_bytes(raw)
    assert back.msg_id == INITIAL_UE_MESSAGE
    assert nas.Message.from_bytes(back.get(IE_NAS_PDU)).msg_type == nas.ATTACH_REQUEST
    print("s1ap.py OK:", raw.hex())
