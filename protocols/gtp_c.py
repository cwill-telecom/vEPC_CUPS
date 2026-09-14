# protocols/gtp_c.py — minimal GTPv2-C (TS 29.274) for S11 / S5-C.
#
# Header and TLV IE layout follow TS 29.274; the implemented message/IE set is the
# subset needed for EPS session management (Create/Modify/Delete Session + Echo).
import struct

PORT = 2123

ECHO_REQUEST             = 1
ECHO_RESPONSE            = 2
CREATE_SESSION_REQUEST   = 32
CREATE_SESSION_RESPONSE  = 33
MODIFY_BEARER_REQUEST    = 34
MODIFY_BEARER_RESPONSE   = 35
DELETE_SESSION_REQUEST   = 36
DELETE_SESSION_RESPONSE  = 37

MSG_NAMES = {
    ECHO_REQUEST: "Echo Request", ECHO_RESPONSE: "Echo Response",
    CREATE_SESSION_REQUEST: "Create Session Request",
    CREATE_SESSION_RESPONSE: "Create Session Response",
    MODIFY_BEARER_REQUEST: "Modify Bearer Request",
    MODIFY_BEARER_RESPONSE: "Modify Bearer Response",
    DELETE_SESSION_REQUEST: "Delete Session Request",
    DELETE_SESSION_RESPONSE: "Delete Session Response",
}

# IE type numbers (TS 29.274 table 8.1-1)
IE_IMSI                 = 1
IE_CAUSE                = 2
IE_RECOVERY             = 3
IE_APN                  = 71
IE_AMBR                 = 72
IE_EBI                  = 73
IE_MEI                  = 75
IE_MSISDN               = 76
IE_INDICATION           = 77
IE_PAA                  = 79
IE_BEARER_QOS           = 80
IE_RAT_TYPE             = 82
IE_SERVING_NETWORK      = 83
IE_ULI                  = 86
IE_F_TEID               = 87
IE_BEARER_CONTEXT       = 93
IE_PDN_TYPE             = 99
IE_CHARGING_ID          = 94
IE_CHARGING_CHARACTER   = 95

# interface type values (F-TEID flags bits 0-5)
IFACE_S1U_ENB  = 0
IFACE_S1U_SGW  = 1
IFACE_S5_S8_SGW = 4
IFACE_S5_S8_PGW = 5
IFACE_SGI_PGW  = 7


def _u8(v):  return struct.pack("!B", v & 0xFF)
def _u16(v): return struct.pack("!H", v & 0xFFFF)
def _u32(v): return struct.pack("!I", v & 0xFFFFFFFF)


class Message:
    def __init__(self, msg_type, teid=0, seq=0, ies=None, has_teid=True):
        self.msg_type = msg_type
        self.teid = teid
        self.seq = seq
        self.has_teid = has_teid
        self.ies = [(t, bytes(v)) for t, v in (ies or [])]

    def add_ie(self, ie, value):
        self.ies.append((ie, bytes(value)))

    def get(self, ie):
        for t, v in self.ies:
            if t == ie:
                return v
        return None

    def get_all(self, ie):
        return [v for t, v in self.ies if t == ie]

    def name(self):
        return MSG_NAMES.get(self.msg_type, "GTPv2-C %d" % self.msg_type)

    def to_bytes(self):
        flags = 0x40 | (0x08 if self.has_teid else 0x00)   # version 2, T flag
        body = b"".join(struct.pack("!BH", t, len(v)) + v for t, v in self.ies)
        hdr = _u8(flags) + _u8(self.msg_type)
        seq_bytes = struct.pack("!I", (self.seq & 0xFFFFFF) << 8)
        if self.has_teid:
            payload = _u32(self.teid) + seq_bytes + body
        else:
            payload = seq_bytes + body
        return hdr + _u16(len(payload)) + payload

    @classmethod
    def from_bytes(cls, data):
        if len(data) < 8:
            raise ValueError("short GTPv2-C message")
        flags, mtype, length = struct.unpack("!BBH", data[:4])
        has_teid = bool(flags & 0x08)
        i = 4
        teid = 0
        if has_teid:
            teid = struct.unpack("!I", data[i:i + 4])[0]
            i += 4
        seq = struct.unpack("!I", data[i:i + 4])[0] >> 8
        i += 4
        end = 4 + length
        ies, j = [], i
        while j + 3 <= min(end, len(data)):
            t, l = struct.unpack("!BH", data[j:j + 3])
            j += 3
            ies.append((t, data[j:j + l]))
            j += l
        return cls(mtype, teid=teid, seq=seq, ies=ies, has_teid=has_teid)

    def dump(self):
        return "\n".join(["%s (teid=0x%X seq=%d)" % (self.name(), self.teid, self.seq)] +
                         ["    - ie %d [%d] %s" % (t, len(v), v.hex()) for t, v in self.ies])


# ------------------------------------------------------------------ helpers ---
def group(ie_type, children):
    return (ie_type, b"".join(struct.pack("!BH", t, len(v)) + v for t, v in children))


def decode_ies(data):
    out, i = [], 0
    while i + 3 <= len(data):
        t, l = struct.unpack("!BH", data[i:i + 3])
        i += 3
        out.append((t, data[i:i + l]))
        i += l
    return out


def ie_imsi(imsi):     return (IE_IMSI, imsi.encode())
def decode_imsi(v):    return v.decode(errors="ignore")
def ie_cause(v=16):    return (IE_CAUSE, _u8(v))          # 16 = Request accepted
def ie_recovery(v):    return (IE_RECOVERY, _u8(v & 0xFF))
def ie_apn(apn):       return (IE_APN, apn.encode())
def decode_apn(v):     return v.decode(errors="ignore")
def ie_ambr(ul, dl):   return (IE_AMBR, _u8(0) + _u32(ul) + _u32(dl))
def decode_ambr(v):    return struct.unpack("!II", v[1:9]) if len(v) >= 9 else (0, 0)
def ie_ebi(v):         return (IE_EBI, _u8(v))
def ie_pdn_type(v=1):  return (IE_PDN_TYPE, _u8(v))
def ie_rat_type(v=6):  return (IE_RAT_TYPE, _u8(v))       # 6 = EUTRAN
def ie_serving_network(plmn): return (IE_SERVING_NETWORK, plmn.encode())
def ie_paa(ip):        return (IE_PAA, _u8(0x01) + __import__("socket").inet_aton(ip))
def decode_paa(v):     return __import__("socket").inet_ntoa(v[1:5]) if len(v) >= 5 else None
def ie_uli(plmn, tac, ecgi):
    return (IE_ULI, _u8(0x10 | 0x04) + plmn.encode() + _u16(tac) + plmn.encode() + _u32(ecgi))


def ie_f_teid(teid, ip, iface=0):
    flags = 0x80 | (iface & 0x3F)     # V4 flag + interface type
    return (IE_F_TEID, _u8(flags) + _u32(teid) + __import__("socket").inet_aton(ip))


def decode_f_teid(v):
    flags = v[0]
    teid = struct.unpack("!I", v[1:5])[0]
    if flags & 0x80 and len(v) >= 9:
        ip = __import__("socket").inet_ntoa(v[5:9])
    else:
        ip = None
    return teid, ip, flags & 0x3F


def ie_bearer_context(ebi, fteid=None, cause=None, charging_id=None):
    kids = [ie_ebi(ebi)]
    if cause is not None:
        kids.append(ie_cause(cause))
    if fteid is not None:
        kids.append(ie_f_teid(*fteid))
    if charging_id is not None:
        kids.append((IE_CHARGING_ID, _u32(charging_id)))
    return group(IE_BEARER_CONTEXT, kids)


def decode_bearer_context(v):
    out = {}
    for t, val in decode_ies(v):
        if t == IE_EBI:
            out["ebi"] = val[0]
        elif t == IE_F_TEID:
            out["f_teid"] = decode_f_teid(val)
        elif t == IE_CAUSE:
            out["cause"] = val[0]
        elif t == IE_CHARGING_ID:
            out["charging_id"] = struct.unpack("!I", val[:4])[0]
    return out


if __name__ == "__main__":
    m = Message(CREATE_SESSION_REQUEST, teid=0, seq=101, ies=[
        ie_imsi("001010000000001"), ie_apn("internet"), ie_pdn_type(1),
        ie_ambr(100000, 200000), ie_f_teid(0x10000, "127.0.0.2", IFACE_S1U_SGW)])
    raw = m.to_bytes()
    back = Message.from_bytes(raw)
    assert back.msg_type == CREATE_SESSION_REQUEST
    assert decode_imsi(back.get(IE_IMSI)) == "001010000000001"
    assert decode_f_teid(back.get(IE_F_TEID))[0] == 0x10000
    print("gtp_c.py OK:", raw.hex())
