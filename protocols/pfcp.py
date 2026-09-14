# protocols/pfcp.py — Packet Forwarding Control Protocol (TS 29.244), CUPS Sx interface.
#
# Implements the subset of PFCP needed for the vEPC CUPS flows:
#   * TLV Information Elements (incl. grouped IEs)
#   * Node messages   : Heartbeat, Association Setup/Update/Release, PFD Management
#   * Session messages: Establishment, Modification, Deletion, Report
#
# Reference points: Sxa (SGW-C  <-> SGW-U), Sxb (PGW-C <-> PGW-U). Transport: UDP/IP,
# standard destination port 8805.
import struct
import socket

# ------------------------------------------------------------------ messages --
HEARTBEAT_REQUEST            = 1
HEARTBEAT_RESPONSE           = 2
ASSOCIATION_SETUP_REQUEST    = 5
ASSOCIATION_SETUP_RESPONSE   = 6
ASSOCIATION_UPDATE_REQUEST   = 7
ASSOCIATION_UPDATE_RESPONSE  = 8
ASSOCIATION_RELEASE_REQUEST  = 9
ASSOCIATION_RELEASE_RESPONSE = 10
VERSION_NOT_SUPPORTED        = 12
SESSION_ESTABLISHMENT_REQUEST  = 50
SESSION_ESTABLISHMENT_RESPONSE = 51
SESSION_MODIFICATION_REQUEST   = 52
SESSION_MODIFICATION_RESPONSE  = 53
SESSION_DELETION_REQUEST       = 54
SESSION_DELETION_RESPONSE      = 55
SESSION_REPORT_REQUEST         = 56
SESSION_REPORT_RESPONSE        = 57
PFD_MANAGEMENT_REQUEST         = 58
PFD_MANAGEMENT_RESPONSE        = 59

MSG_NAMES = {
    HEARTBEAT_REQUEST: "Heartbeat Request", HEARTBEAT_RESPONSE: "Heartbeat Response",
    ASSOCIATION_SETUP_REQUEST: "Association Setup Request",
    ASSOCIATION_SETUP_RESPONSE: "Association Setup Response",
    ASSOCIATION_UPDATE_REQUEST: "Association Update Request",
    ASSOCIATION_UPDATE_RESPONSE: "Association Update Response",
    ASSOCIATION_RELEASE_REQUEST: "Association Release Request",
    ASSOCIATION_RELEASE_RESPONSE: "Association Release Response",
    SESSION_ESTABLISHMENT_REQUEST: "Session Establishment Request",
    SESSION_ESTABLISHMENT_RESPONSE: "Session Establishment Response",
    SESSION_MODIFICATION_REQUEST: "Session Modification Request",
    SESSION_MODIFICATION_RESPONSE: "Session Modification Response",
    SESSION_DELETION_REQUEST: "Session Deletion Request",
    SESSION_DELETION_RESPONSE: "Session Deletion Response",
    SESSION_REPORT_REQUEST: "Session Report Request",
    SESSION_REPORT_RESPONSE: "Session Report Response",
    PFD_MANAGEMENT_REQUEST: "PFD Management Request",
    PFD_MANAGEMENT_RESPONSE: "PFD Management Response",
}

# ------------------------------------------------------------ Information Elem --
# PFCP IE type numbers used by this subset (TS 29.244, table 8.1.2-1).
IE = {
    "Create PDR": 1, "PDI": 2, "Create FAR": 3, "Forwarding Parameters": 4,
    "Duplicating Parameters": 5, "Create URR": 6, "Create QER": 7, "Created PDR": 8,
    "Update PDR": 9, "Update FAR": 10, "Update URR": 11, "Update QER": 12,
    "Remove PDR": 13, "Remove FAR": 14, "Remove URR": 15, "Remove QER": 16,
    "Load Control Information": 51, "Overload Control Information": 54,
    "Cause": 19, "Source Interface": 20, "F-TEID": 21, "Network Instance": 22,
    "Precedence": 29, "Destination Interface": 42, "Measurement Method": 62,
    "Usage Report Trigger": 63, "Measurement Period": 64, "F-SEID": 57,
    "Outer Header Creation": 84, "BAR ID": 88, "URR ID": 58, "PDR ID": 56,
    "FAR ID": 108, "QER ID": 109, "Reporting Triggers": 37, "Report Type": 39,
    "Node ID": 60, "Recovery Time Stamp": 96, "Apply Action": 44,
    "Volume Measurement": 42, "Duration Measurement": 43, "PFD": 260,
    "Application ID": 24, "UE IP Address": 93, "PFD Context": 261,
    "Reported PDR ID": 120, "URR Sequence Number": 104,
}
_IE_NAME = {v: k for k, v in IE.items()}

# Grouped IEs whose value is a list of child IEs.
GROUPED_IES = {
    IE["PDI"], IE["Create PDR"], IE["Create FAR"], IE["Forwarding Parameters"],
    IE["Duplicating Parameters"], IE["Create URR"], IE["Create QER"],
    IE["Update PDR"], IE["Update FAR"], IE["Update URR"], IE["Update QER"],
    IE["Created PDR"], IE["PFD Context"],
}

# ------------------------------------------------------------------- causes --
CAUSE_REQUEST_ACCEPTED      = 1
CAUSE_REQUEST_REJECTED      = 2
CAUSE_SESSION_CONTEXT_NF    = 3
CAUSE_MANDATORY_IE_MISSING  = 4
CAUSE_MANDATORY_IE_INCORRECT = 5
CAUSE_RULE_CREATION_FAILURE = 11
CAUSE_PFCP_ENTITY_INACTIVE  = 16
CAUSE_NO_ESTABLISHED_PFCP_ASSOCIATION = 17
CAUSE_RULES_MISSING         = 19
CAUSE_CAUSE_NAMES = {
    1: "Request accepted", 2: "Request rejected", 3: "Session context not found",
    4: "Mandatory IE missing", 5: "Mandatory IE incorrect",
    11: "Rule creation/modification failure", 16: "PFCP entity inactive",
    17: "No established PFCP association", 19: "Rule(s) missing",
}

# --------------------------------------------------------------- primitives ---
def _u8(v):  return struct.pack("!B", v & 0xFF)
def _u16(v): return struct.pack("!H", v & 0xFFFF)
def _u32(v): return struct.pack("!I", v & 0xFFFFFFFF)
def _u64(v): return struct.pack("!Q", v & 0xFFFFFFFFFFFFFFFF)

def encode_ie(ie_type, value):
    """TLV-encode one IE. `value` is raw bytes."""
    return _u16(ie_type) + _u16(len(value)) + value

def encode_grouped(ie_type, children):
    """Encode a grouped IE from a list of already-encoded child IEs."""
    return encode_ie(ie_type, b"".join(children))

def decode_ies(data):
    """Decode a byte string into a list of (type, raw_value_bytes)."""
    out, i, n = [], 0, len(data)
    while i + 4 <= n:
        t, l = struct.unpack("!HH", data[i:i + 4])
        i += 4
        v = data[i:i + l]
        i += l
        out.append((t, v))
    return out

def decode_ies_recursive(data):
    """Return list of (type, value, children) where children is [] or recursive list."""
    res = []
    for t, v in decode_ies(data):
        children = decode_ies_recursive(v) if t in GROUPED_IES else []
        res.append((t, v, children))
    return res

# ------------------------------------------------------------- value codecs ---
def ie_cause(value=CAUSE_REQUEST_ACCEPTED):
    return encode_ie(IE["Cause"], _u8(value))

def ie_node_id(ip, v4=True):
    if v4:
        return encode_ie(IE["Node ID"], _u8(0) + socket.inet_aton(ip))
    return encode_ie(IE["Node ID"], _u8(1) + socket.inet_aton(ip) + b"\x00" * 16)

def decode_node_id(v):
    if not v:
        return None
    if v[0] == 0 and len(v) >= 5:
        return socket.inet_ntoa(v[1:5])
    return None

def ie_fseid(seid, ip):
    # flags(1) + SEID(8) + IPv4(4)
    return encode_ie(IE["F-SEID"], _u8(0x02) + _u64(seid) + socket.inet_aton(ip))

def decode_fseid(v):
    if len(v) >= 13:
        return struct.unpack("!Q", v[1:9])[0], socket.inet_ntoa(v[9:13])
    return None, None

def ie_recovery_ts(ts):
    return encode_ie(IE["Recovery Time Stamp"], _u32(ts))

def ie_source_interface(value):
    return encode_ie(IE["Source Interface"], _u8(value))

def ie_ft_eid(teid, ip, iface_type=0):
    # flags(1=IPv4) + TEID(4) + IPv4(4)
    return encode_ie(IE["F-TEID"], _u8(0x02) + _u32(teid) + socket.inet_aton(ip))

def decode_ft_eid(v):
    if len(v) >= 9:
        return struct.unpack("!I", v[1:5])[0], socket.inet_ntoa(v[5:9])
    return None, None

def ie_apply_action(forward=False, drop=False, buffer=False, notify=False, duplicate=False):
    bits = 0
    if drop:      bits |= 0x01
    if forward:   bits |= 0x02
    if buffer:    bits |= 0x04
    if notify:    bits |= 0x08
    if duplicate: bits |= 0x10
    return encode_ie(IE["Apply Action"], _u8(bits))

APPLY_ACTION_NAMES = [(0x01, "DROP"), (0x02, "FORWARD"), (0x04, "BUFFER"),
                      (0x08, "NOTIFY"), (0x10, "DUPLICATE")]

def decode_apply_action(v):
    b = v[0] if v else 0
    return [name for bit, name in APPLY_ACTION_NAMES if b & bit]

def ie_pdr_id(i):   return encode_ie(IE["PDR ID"], _u16(i))
def ie_far_id(i):   return encode_ie(IE["FAR ID"], _u32(i))
def ie_qer_id(i):   return encode_ie(IE["QER ID"], _u32(i))
def ie_urr_id(i):   return encode_ie(IE["URR ID"], _u32(i))
def ie_ur_seqn(i):  return encode_ie(IE["URR Sequence Number"], _u32(i))
def ie_volume(total=0, ul=0, dl=0):
    return encode_ie(IE["Volume Measurement"], _u64(total) + _u64(ul) + _u64(dl))

def decode_volume(v):
    if len(v) >= 24:
        t, ul, dl = struct.unpack("!QQQ", v[:24])
        return {"total": t, "uplink": ul, "downlink": dl}
    return {}

# -------------------------------------------------------------- SD / decoding -
def pdr_id_of(v):
    return struct.unpack("!H", v[:2])[0] if len(v) >= 2 else None

def u32_of(v):
    return struct.unpack("!I", v[:4])[0] if len(v) >= 4 else None

def u8_of(v):
    return v[0] if len(v) >= 1 else None

# ------------------------------------------------------------------ Message ---
class Message:
    """A PFCP message: header + list of (type, value_bytes) IEs."""

    def __init__(self, msg_type, seid=0, seq=0, ies=None, has_seid=True):
        self.msg_type = msg_type
        self.seid = seid
        self.seq = seq
        self.ies = self._normalise(ies or [])
        self.has_seid = has_seid

    @staticmethod
    def _normalise(items):
        """Accept a mix of encoded IE bytes and (type, value[, children]) tuples."""
        out = []
        for it in items:
            if isinstance(it, (bytes, bytearray)):
                out.extend(decode_ies(bytes(it)))
            elif isinstance(it, tuple) and len(it) >= 2:
                out.append((it[0], it[1]))
            else:
                raise TypeError("bad IE item: %r" % (it,))
        return out

    # --- building ---
    def add(self, encoded_ie):
        self.ies.append(decode_ies(encoded_ie)[0])

    def add_ie(self, ie_type, value):
        self.ies.append((ie_type, value))

    def get(self, ie_type):
        for t, v in self.ies:
            if t == ie_type:
                return v
        return None

    def get_all(self, ie_type):
        return [v for t, v in self.ies if t == ie_type]

    def children(self, ie_type):
        v = self.get(ie_type)
        return decode_ies_recursive(v) if v is not None else []

    def contains(self, ie_type):
        return self.get(ie_type) is not None

    # --- wire format ---
    def to_bytes(self):
        flags = 0x20  # version 1 in bits 5-7
        if self.has_seid:
            flags |= 0x01
        payload = b"".join(encode_ie(t, v) for t, v in self.ies)
        body = (_u64(self.seid) if self.has_seid else b"")
        seq_bytes = struct.pack("!I", (self.seq & 0xFFFFFF) << 8)  # 3B seq + 1B spare
        body += seq_bytes + payload
        return _u8(flags) + _u8(self.msg_type) + _u16(len(body)) + body

    @classmethod
    def from_bytes(cls, data):
        if len(data) < 4:
            raise ValueError("short PFCP message")
        flags = data[0]
        version = (flags >> 5) & 0x07
        has_seid = bool(flags & 0x01)
        msg_type = data[1]
        length = struct.unpack("!H", data[2:4])[0]
        i = 4
        seid = 0
        if has_seid:
            seid = struct.unpack("!Q", data[i:i + 8])[0]
            i += 8
        seq = struct.unpack("!I", data[i:i + 4])[0] >> 8
        i += 4
        ies = decode_ies(data[i:i + length - (i - 4)])
        return cls(msg_type, seid=seid, seq=seq, ies=ies, has_seid=has_seid)

    def name(self):
        return MSG_NAMES.get(self.msg_type, "Message %d" % self.msg_type)

    def dump(self):
        parts = ["%s (seq=%d, seid=0x%X, %d IEs)" %
                 (self.name(), self.seq, self.seid, len(self.ies))]
        for t, v in self.ies:
            parts.append("    - %s [%d] %s" %
                         (_IE_NAME.get(t, "IE%d" % t), t, v[:24].hex()))
        return "\n".join(parts)
