# protocols/diameter.py — minimal Diameter base (RFC 6733) + S6a (TS 29.272) and
# Gx (TS 29.212) subset, used for the MME<->HSS (S6a) and PGW-C<->PCRF (Gx) interfaces.
#
# Header + AVP framing follow RFC 6733. The AVP set is a SIMPLIFIED subset: codes use
# the standard base/3GPP(vendor 10415) values where well known, but only the attributes
# needed for AIR/AIA, ULR/ULA and CCR/CCA are implemented.
import struct

BASE_APP = 0
S6A_APP  = 16777251
GX_APP   = 16777238

CMD_CAPABILITIES_EXCHANGE = 257
CMD_AUTH_INFO             = 318
CMD_UPDATE_LOCATION       = 316
CMD_CANCEL_LOCATION       = 317
CMD_PURGE_UE              = 321
CMD_CREDIT_CONTROL        = 272

CMD_NAMES = {
    CMD_CAPABILITIES_EXCHANGE: "Capabilities-Exchange",
    CMD_AUTH_INFO: "Authentication-Information",
    CMD_UPDATE_LOCATION: "Update-Location",
    CMD_CANCEL_LOCATION: "Cancel-Location",
    CMD_PURGE_UE: "Purge-UE",
    CMD_CREDIT_CONTROL: "Credit-Control",
}

VENDOR_3GPP = 10415

# --- base AVPs ---
AVP_SESSION_ID            = 263
AVP_ORIGIN_HOST          = 264
AVP_ORIGIN_REALM         = 296
AVP_DESTINATION_REALM    = 283
AVP_DESTINATION_HOST     = 293
AVP_RESULT_CODE          = 268
AVP_AUTH_SESSION_STATE   = 277
AVP_AUTH_APPLICATION_ID  = 258
AVP_USER_NAME            = 1
AVP_ORIGIN_STATE_ID      = 278
AVP_SUPPORTED_VENDOR_ID  = 265
AVP_PRODUCT_NAME         = 269
AVP_VENDOR_SPECIFIC_APP  = 260
AVP_SUBSCRIPTION_ID      = 443
AVP_SUBSCRIPTION_ID_TYPE = 450
AVP_SUBSCRIPTION_ID_DATA = 444
# --- Gx ---
AVP_CC_REQUEST_TYPE      = 416
AVP_CC_REQUEST_NUMBER    = 415
AVP_REQUESTED_SERVICE_UNIT = 437
# --- 3GPP vendor AVPs (S6a) ---
AVP_IMSI                          = 1      # vendor 10415
AVP_SUBSCRIPTION_DATA             = 1400
AVP_AUTHENTICATION_INFO           = 1413
AVP_E_UTRAN_VECTOR                = 1414
AVP_NUMBER_OF_REQUESTED_VECTORS   = 1410
AVP_REQUESTED_EUTRAN_AUTH_INFO    = 1408
AVP_VISITED_PLMN_ID               = 1407
AVP_RAND                          = 1447
AVP_XRES                          = 1448
AVP_AUTN                          = 1449
AVP_KASME                         = 1450
AVP_APN_CONFIGURATION_PROFILE     = 1429
AVP_APN_CONFIGURATION             = 1430
AVP_SERVICE_SELECTION             = 493
AVP_EPS_SUBSCRIBED_QOS_PROFILE    = 1431
AVP_SUBSCRIBED_QOS_PROFILE        = 1404
AVP_QOS_CLASS_IDENTIFIER          = 1028
AVP_ALLOCATION_RETENTION_PRIORITY = 1034
AVP_AMBR                          = 1435
AVP_MAX_REQ_BANDWIDTH_UL          = 516
AVP_MAX_REQ_BANDWIDTH_DL          = 515
AVP_PDN_TYPE_3GPP                 = 1456
AVP_SUBSCRIBER_STATUS             = 1424
# --- Gx QoS ---
AVP_QOS_INFORMATION               = 1010
AVP_BEARER_IDENTIFIER             = 1029

# result codes
RC_SUCCESS = 2001
DIAMETER_SUCCESS = 2001
DIAMETER_USER_UNKNOWN = 5001

# Auth-Session-State
NO_STATE_MAINTAINED = 1
STATE_MAINTAINED = 0

# CC-Request-Type
CC_INITIAL = 1
CC_UPDATE = 2
CC_TERMINATION = 3
CC_EVENT = 4


class Avp:
    def __init__(self, code, data=b"", vendor=0, mandatory=True, protected=False):
        self.code = code
        self.data = bytes(data)
        self.vendor = vendor
        self.mandatory = mandatory
        self.protected = protected

    def encode(self):
        flags = 0
        if self.vendor:
            flags |= 0x80
        if self.mandatory:
            flags |= 0x40
        if self.protected:
            flags |= 0x20
        if self.vendor:
            payload = struct.pack("!I", self.vendor) + self.data
        else:
            payload = self.data
        length = 8 + len(payload)
        raw = struct.pack("!IB", self.code, flags) + length.to_bytes(3, "big") + payload
        pad = (-len(raw)) % 4
        return raw + b"\x00" * pad

    @staticmethod
    def decode(buf, off=0):
        code = struct.unpack("!I", buf[off:off + 4])[0]
        flags = buf[off + 4]
        length = int.from_bytes(buf[off + 5:off + 8], "big")
        vendor = 0
        p = off + 8
        if flags & 0x80:
            vendor = struct.unpack("!I", buf[p:p + 4])[0]
            p += 4
        data = buf[p:off + length]
        nxt = off + length + ((-length) % 4)
        return Avp(code, data, vendor, bool(flags & 0x40), bool(flags & 0x20)), nxt

    def u32(self):
        return struct.unpack("!I", self.data[:4])[0] if len(self.data) >= 4 else None

    def text(self):
        return self.data.decode(errors="ignore")

    def __repr__(self):
        return "Avp(code=%d,len=%d,vendor=%d)" % (self.code, len(self.data), self.vendor)


class Message:
    def __init__(self, cmd_code, app_id, avps=None, request=True, hop_id=0, end_id=0):
        self.cmd_code = cmd_code
        self.app_id = app_id
        self.request = request
        self.hop_id = hop_id
        self.end_id = end_id
        self.avps = list(avps or [])

    def name(self):
        return "%s-%s" % (CMD_NAMES.get(self.cmd_code, str(self.cmd_code)),
                          "Request" if self.request else "Answer")

    def add(self, avp):
        self.avps.append(avp)

    def get(self, code, vendor=0):
        for a in self.avps:
            if a.code == code and a.vendor == vendor:
                return a
        return None

    def get_all(self, code, vendor=0):
        return [a for a in self.avps if a.code == code and a.vendor == vendor]

    def to_bytes(self):
        body = b"".join(a.encode() for a in self.avps)
        flags = 0x80 if self.request else 0x00   # R bit (P/E/T clear)
        hdr = (struct.pack("!BB", 1, flags) + (20 + len(body)).to_bytes(3, "big") +
               self.cmd_code.to_bytes(3, "big") + struct.pack("!III", self.app_id,
                                                              self.hop_id, self.end_id))
        return hdr + body

    @classmethod
    def from_bytes(cls, data):
        if len(data) < 20:
            raise ValueError("short Diameter message")
        ver, flags = data[0], data[1]
        length = int.from_bytes(data[2:5], "big")
        cmd = int.from_bytes(data[5:8], "big")
        app_id, hop, end = struct.unpack("!III", data[8:20])
        avps, i = [], 20
        while i < min(length, len(data)):
            a, i = Avp.decode(data, i)
            avps.append(a)
        return cls(cmd, app_id, avps, bool(flags & 0x80), hop, end)


# ------------------------------------------------------------------ helpers ---
def avp(code, data, vendor=0, mandatory=True):
    if isinstance(data, str):
        data = data.encode()
    return Avp(code, data, vendor, mandatory)


def avp_u32(code, value, vendor=0):
    return Avp(code, struct.pack("!I", value), vendor)


def group(code, children, vendor=0):
    return Avp(code, b"".join(a.encode() for a in children), vendor)


def children(avp_obj):
    return [Avp.decode(avp_obj.data, i)[0]
            for i in _iter_offsets(avp_obj.data)]


def _iter_offsets(buf):
    off = 0
    while off < len(buf):
        yield off
        _, off = Avp.decode(buf, off)


if __name__ == "__main__":
    air = Message(CMD_AUTH_INFO, S6A_APP, [
        avp(AVP_SESSION_ID, "hss.mme;1"),
        avp(AVP_ORIGIN_HOST, "mme.epc.mnc001.mcc001.3gppnetwork.org"),
        avp(AVP_DESTINATION_REALM, "epc.mnc001.mcc001.3gppnetwork.org"),
        group(AVP_SUBSCRIPTION_ID, [avp_u32(AVP_SUBSCRIPTION_ID_TYPE, 1),
                                    avp(AVP_SUBSCRIPTION_ID_DATA, "001010000000001")]),
        avp_u32(AVP_REQUESTED_EUTRAN_AUTH_INFO, 1, VENDOR_3GPP),
    ], hop_id=7, end_id=7)
    raw = air.to_bytes()
    back = Message.from_bytes(raw)
    assert back.cmd_code == CMD_AUTH_INFO and back.request
    subs = back.get(AVP_SUBSCRIPTION_ID)
    kids = children(subs)
    assert kids[1].text() == "001010000000001"
    assert back.get(AVP_REQUESTED_EUTRAN_AUTH_INFO, VENDOR_3GPP).u32() == 1
    print("diameter.py OK:", raw.hex())
