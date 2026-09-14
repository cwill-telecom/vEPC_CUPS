#!/usr/bin/env python3
# capture_pfcp.py — in-process PFCP wiretap for the vEPC CUPS simulator.
#
# Loopback capture (tshark/dumpcap) is unavailable to non-root here, so this script
# taps socket.recvfrom in-process to record every PFCP PDU exactly as it crosses the
# UDP socket boundary (the receiver's view => accurate src/dst 4-tuple, one record per
# wire datagram). It then writes:
#
#   captures/pfcp_raw_<ts>.txt    human-readable hexdump + annotated decode
#   captures/pfcp_raw_<ts>.pcap   synthetic Ethernet/IPv4/UDP pcap (open in Wireshark)
#
# PFCP is identified by header (TS 29.244): version==1 (flags & 0xE0 == 0x20) and a
# known message type, which cleanly excludes GTP-U (type 0xFF) on the same loopback.
#
#   python3 capture_pfcp.py [run_seconds]
import os, sys, time, socket, struct, threading, datetime

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE)

from protocols import pfcp
from utils.utils import log

CAP_DIR = os.path.join(BASE, "captures")

_KNOWN_TYPES = set(pfcp.MSG_NAMES.keys())
_records = []
_lock = threading.Lock()


def _looks_like_pfcp(data):
    return (isinstance(data, (bytes, bytearray)) and len(data) >= 8
            and (data[0] & 0xE0) == 0x20 and data[1] in _KNOWN_TYPES)


_orig_recvfrom = socket.socket.recvfrom


def _tap_recvfrom(self, *a, **kw):
    data, addr = _orig_recvfrom(self, *a, **kw)
    if _looks_like_pfcp(data):
        try:
            dst = self.getsockname()
        except OSError:
            dst = ("0.0.0.0", 0)
        with _lock:
            _records.append({"t": time.time(), "src": addr, "dst": dst, "raw": bytes(data)})
    return data, addr


socket.socket.recvfrom = _tap_recvfrom


# ----------------------------------------------------------------- pcap writer --
def _ip_checksum(hdr):
    if len(hdr) % 2:
        hdr += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(hdr) // 2), hdr))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def _synth_frame(src, dst, payload):
    """Build Ethernet + IPv4 + UDP frame carrying `payload` (checksums: IPv4 valid, UDP 0)."""
    sip, sport = src
    dip, dport = dst
    sport, dport = sport & 0xFFFF, dport & 0xFFFF
    udp_len = 8 + len(payload)
    udp = struct.pack("!HHHH", sport, dport, udp_len, 0) + payload
    total_len = 20 + udp_len
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0x00, total_len, 0, 0x4000, 64, 17, 0,
                     socket.inet_aton(sip), socket.inet_aton(dip))
    csum = _ip_checksum(ip)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0x00, total_len, 0, 0x4000, 64, 17, csum,
                     socket.inet_aton(sip), socket.inet_aton(dip))
    dst_mac = bytes.fromhex("020000000002")
    src_mac = bytes.fromhex("020000000001")
    eth = dst_mac + src_mac + struct.pack("!H", 0x0800)
    return eth + ip + udp


def write_pcap(path, records):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))  # Ethernet
        for r in records:
            frame = _synth_frame(r["src"], r["dst"], r["raw"])
            ts = r["t"]
            sec, usec = int(ts), int((ts - int(ts)) * 1_000_000)
            f.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
            f.write(frame)


# ------------------------------------------------------------- decode / hexdump --
def _ie_tree(ies, depth=1, out=None):
    out = out if out is not None else []
    for t, v, kids in ies:
        name = pfcp._IE_NAME.get(t, "IE%d" % t)
        out.append("%s%-28s type=%-4d len=%-3d %s" %
                   ("  " * depth, name, t, len(v), v[:16].hex()))
        if kids:
            _ie_tree(kids, depth + 1, out)
    return out


def _hexdump(data, width=16):
    lines = []
    for off in range(0, len(data), width):
        chunk = data[off:off + width]
        hexpart = " ".join("%02x" % b for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append("  %04x  %-*s  |%s|" % (off, width * 3 - 1, hexpart, asc))
    return "\n".join(lines)


def decode_block(raw):
    try:
        m = pfcp.Message.from_bytes(raw)
    except Exception as e:  # noqa
        return "  <decode failed: %r>" % e
    head = "  %s  seq=%d  seid=0x%X  len=%d  ies=%d" % (
        m.name(), m.seq, m.seid, len(raw), len(m.ies))
    ies = pfcp.decode_ies_recursive(
        b"".join(pfcp.encode_ie(t, v) for t, v in m.ies))
    return head + "\n" + "\n".join(_ie_tree(ies))


def _flow_label(r):
    return "%s:%d -> %s:%d" % (r["src"][0], r["src"][1], r["dst"][0], r["dst"][1])


# ------------------------------------------------------------------------ main --
def main(argv):
    run_seconds = float(argv[0]) if argv else 0.0
    os.makedirs(CAP_DIR, exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    txt_path = os.path.join(CAP_DIR, "pfcp_raw_%s.txt" % stamp)
    pcap_path = os.path.join(CAP_DIR, "pfcp_raw_%s.pcap" % stamp)

    from simulators import cups_simulator
    log("Launching CUPS scenario under PFCP wiretap ...")
    cups_simulator.main([])
    if run_seconds:
        time.sleep(run_seconds)

    recs = _records
    counts = {}
    for r in recs:
        try:
            name = pfcp.MSG_NAMES.get(r["raw"][1], "type%d" % r["raw"][1])
        except Exception:  # noqa
            name = "?"
        counts[name] = counts.get(name, 0) + 1

    with open(txt_path, "w") as f:
        f.write("# Raw PFCP capture — vEPC_cups_python / TS 29.244 (Sxa/Sxb, UDP 8805)\n")
        f.write("# generated: %s\n# PDUs captured: %d\n" %
                (datetime.datetime.now().isoformat(timespec="seconds"), len(recs)))
        f.write("#" + "=" * 78 + "\n")
        t0 = recs[0]["t"] if recs else time.time()
        for i, r in enumerate(recs, 1):
            mtype = r["raw"][1]
            mname = pfcp.MSG_NAMES.get(mtype, "type%d" % mtype)
            f.write("\n[%03d] t=+%.6f  %s\n" % (i, r["t"] - t0, _flow_label(r)))
            f.write("      %s  (%d bytes)\n" % (mname, len(r["raw"])))
            f.write(_hexdump(r["raw"]) + "\n")
            f.write("    ---- decoded ----\n")
            f.write(decode_block(r["raw"]) + "\n")

    write_pcap(pcap_path, recs)

    log("Captured %d PFCP PDUs" % len(recs))
    for k in sorted(counts):
        log("  %-34s %d" % (k, counts[k]))
    log("  text  -> %s" % txt_path)
    log("  pcap  -> %s" % pcap_path)
    return recs


if __name__ == "__main__":
    main(sys.argv[1:])
