# protocols/gtp.py — minimal GTP-U (TS 29.281) used for Sx data forwarding.
#
# The CPF and UPF exchange user-plane frames over GTP-U, e.g. RS/RA/DHCP signalling
# between the UE and PGW-C, or DL buffered data when buffering is done in the CPF.
import struct

GTPU_PORT = 2152

# Message types
ECHO_REQUEST = 1
ECHO_RESPONSE = 2
ERROR_INDICATION = 26
END_MARKER = 254
G_PDU = 255

MSG_NAMES = {1: "Echo Request", 2: "Echo Response", 26: "Error Indication",
             254: "End Marker", 255: "G-PDU"}


def encode_gpdu(teid, payload, seq=0):
    """Build a GTP-U G-PDU header + payload. flags: version 1, PT=1, no ext."""
    flags = 0x30                      # version 1 (0x20) | PT (0x10)
    length = 8 + len(payload)         # bytes after the mandatory 8-byte header
    hdr = struct.pack("!BBHI", flags, G_PDU, length, teid & 0xFFFFFFFF)
    return hdr + payload


def encode_echo(teid=0, seq=0):
    return struct.pack("!BBHI", 0x30, ECHO_REQUEST, 4, teid) + struct.pack("!I", seq)


def decode(data):
    """Return dict with flags/type/length/teid and payload (for G-PDU)."""
    if len(data) < 8:
        raise ValueError("short GTP-U packet")
    flags, mtype, length, teid = struct.unpack("!BBHI", data[:8])
    payload = data[8:8 + length - 4] if mtype == G_PDU else data[8:8 + length]
    return {"flags": flags, "type": mtype, "length": length, "teid": teid,
            "payload": payload}


def name(mtype):
    return MSG_NAMES.get(mtype, "GTP-U %d" % mtype)
