# protocols/nas.py — minimal EPS NAS (TS 24.301 / 24.008) for the vEPC simulator.
#
# This is a SIMPLIFIED subset: a flat TLV encoding ([IEI:1][len:1][value]) is used
# rather than the real octet-aligned/type-4 encodings. It carries the EMM/ESM messages
# needed for the attach procedure and is intentionally easy to read on the wire.
import struct

# EMM message types (TS 24.007, table 9.8.1)
ATTACH_REQUEST            = 0x41
ATTACH_ACCEPT             = 0x42
ATTACH_COMPLETE           = 0x43
ATTACH_REJECT             = 0x44
DETACH_REQUEST            = 0x45
DETACH_ACCEPT             = 0x46
AUTH_REQUEST              = 0x52
AUTH_RESPONSE             = 0x53
AUTH_FAILURE              = 0x5c
IDENTITY_REQUEST          = 0x55
IDENTITY_RESPONSE         = 0x56
SECURITY_MODE_COMMAND     = 0x5d
SECURITY_MODE_COMPLETE    = 0x5e
# ESM message types
PDN_CONNECTIVITY_REQUEST  = 0xd0
PDN_CONNECTIVITY_REJECT   = 0xd1
PDN_CONNECTIVITY_ACCEPT   = 0xd2

MSG_NAMES = {
    ATTACH_REQUEST: "Attach Request", ATTACH_ACCEPT: "Attach Accept",
    ATTACH_COMPLETE: "Attach Complete", ATTACH_REJECT: "Attach Reject",
    DETACH_REQUEST: "Detach Request", DETACH_ACCEPT: "Detach Accept",
    AUTH_REQUEST: "Authentication Request", AUTH_RESPONSE: "Authentication Response",
    AUTH_FAILURE: "Authentication Failure", IDENTITY_REQUEST: "Identity Request",
    IDENTITY_RESPONSE: "Identity Response",
    SECURITY_MODE_COMMAND: "Security Mode Command",
    SECURITY_MODE_COMPLETE: "Security Mode Complete",
    PDN_CONNECTIVITY_REQUEST: "PDN Connectivity Request",
    PDN_CONNECTIVITY_ACCEPT: "PDN Connectivity Accept",
    PDN_CONNECTIVITY_REJECT: "PDN Connectivity Reject",
}

# Simplified IE identifiers (internal to this simulator).
IE_IMSI          = 0x01
IE_IMEI          = 0x02
IE_APN           = 0x03
IE_PDN_TYPE      = 0x04     # 1 = IPv4, 2 = IPv6, 3 = IPv4v6
IE_EBI           = 0x05
IE_KASME         = 0x06
IE_RAND          = 0x07
IE_AUTN          = 0x08
IE_XRES          = 0x09
IE_RES           = 0x0a
IE_ATTACH_TYPE   = 0x0b     # 1 = EPS attach
IE_TAI           = 0x0c     # PLMN(3) + TAC(2)
IE_UE_IP         = 0x0d
IE_ESM_MSG       = 0x0e     # nested ESM message container
IE_QCI           = 0x0f
IE_AMBR          = 0x10     # UL(kbps):2 + DL(kbps):2
IE_CAUSE         = 0x11
IE_KSI           = 0x12


def bcd_encode(s):
    """Encode a digit string as swapped-nibble BCD (TS 24.008 style)."""
    s = str(s)
    if len(s) % 2:
        s += "F"
    out = bytearray()
    for i in range(0, len(s), 2):
        out.append(int(s[i + 1], 16) << 4 | int(s[i], 16))
    return bytes(out)


def bcd_decode(b):
    out = ""
    for x in b:
        out += "%X%X" % (x & 0x0F, x >> 4)
    return out.rstrip("F")


class Message:
    """A NAS message: a 1-byte message type followed by flat TLV IEs."""

    def __init__(self, msg_type, ies=None):
        self.msg_type = msg_type
        self.ies = [(t, bytes(v)) for t, v in (ies or [])]

    def add_ie(self, ie, value):
        self.ies.append((ie, bytes(value)))

    def get(self, ie):
        for t, v in self.ies:
            if t == ie:
                return v
        return None

    def name(self):
        return MSG_NAMES.get(self.msg_type, "NAS 0x%02x" % self.msg_type)

    def to_bytes(self):
        body = b"".join(struct.pack("!BB", t, len(v)) + v for t, v in self.ies)
        return struct.pack("!B", self.msg_type) + body

    @classmethod
    def from_bytes(cls, data):
        if not data:
            raise ValueError("empty NAS message")
        mt = data[0]
        ies, i = [], 1
        while i + 2 <= len(data):
            t, ln = data[i], data[i + 1]
            i += 2
            ies.append((t, data[i:i + ln]))
            i += ln
        return cls(mt, ies)

    def dump(self):
        parts = [self.name()]
        for t, v in self.ies:
            parts.append("    - ie 0x%02x [%d] %s" % (t, len(v), v.hex()))
        return "\n".join(parts)


# ------------------------------------------------------------------ helpers ---
def ie_imsi(imsi):        return (IE_IMSI, bcd_encode(imsi))
def ie_apn(apn):          return (IE_APN, apn.encode())
def ie_pdn_type(v=1):     return (IE_PDN_TYPE, struct.pack("!B", v))
def ie_ebi(v):            return (IE_EBI, struct.pack("!B", v))
def ie_attach_type(v=1):  return (IE_ATTACH_TYPE, struct.pack("!B", v))
def ie_tai(plmn, tac):    return (IE_TAI, plmn.encode() + struct.pack("!H", tac))
def ie_kasme(b):          return (IE_KASME, b)
def ie_rand(b):           return (IE_RAND, b)
def ie_autn(b):           return (IE_AUTN, b)
def ie_xres(b):           return (IE_XRES, b)
def ie_res(b):            return (IE_RES, b)
def ie_ue_ip(ip):         return (IE_UE_IP, __import__("socket").inet_aton(ip))
def ie_qci(v):            return (IE_QCI, struct.pack("!B", v))
def ie_ambr(ul, dl):      return (IE_AMBR, struct.pack("!HH", ul, dl))
def ie_cause(v):          return (IE_CAUSE, struct.pack("!B", v))
def ie_esm(nas_msg):      return (IE_ESM_MSG, nas_msg.to_bytes())


def decode_imsi(v):       return bcd_decode(v)
def decode_ue_ip(v):      return __import__("socket").inet_ntoa(v[:4]) if len(v) >= 4 else None
def decode_apn(v):        return v.decode(errors="ignore")


if __name__ == "__main__":
    m = Message(ATTACH_REQUEST, [ie_imsi("001010000000001"), ie_apn("internet"),
                                 ie_pdn_type(1), ie_attach_type(1)])
    raw = m.to_bytes()
    back = Message.from_bytes(raw)
    assert back.msg_type == ATTACH_REQUEST
    assert decode_imsi(back.get(IE_IMSI)) == "001010000000001"
    assert decode_apn(back.get(IE_APN)) == "internet"
    print("nas.py OK:", raw.hex())
