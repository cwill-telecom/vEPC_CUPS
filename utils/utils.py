# utils/utils.py — assorted helpers for the CUPS vEPC simulator.
import os
import time
import threading
import socket
import struct

# ---------------------------------------------------------------- logging ----
DEBUG = os.environ.get("DEBUG", "") not in ("", "0")
TRACE = os.environ.get("TRACE", "") not in ("", "0")

_LOCK = threading.Lock()
def _log(tag, msg):
    with _LOCK:
        print("%s [%s] %s" % (time.strftime("%H:%M:%S"), tag, msg), flush=True)

def log(msg):
    _log("INFO", msg)

def dbg(msg):
    if DEBUG:
        _log("DBG ", msg)

def trace(msg):
    if TRACE:
        _log("TRC ", msg)

# --------------------------------------------------------------- addresses ---
def ip_to_int(ip):
    return struct.unpack("!I", socket.inet_aton(ip))[0]

def int_to_ip(v):
    return socket.inet_ntoa(struct.pack("!I", v & 0xFFFFFFFF))

def teid_pool(base=0x00010000, step=1):
    """Monotonic GTP-U TEID allocator (F-TEIDu)."""
    n = base
    while True:
        yield n
        n = (n + step) & 0xFFFFFFFF

# ----------------------------------------------------------------- timers ----
class PeriodicTimer(threading.Thread):
    """Call `fn` every `interval` seconds until stopped."""
    def __init__(self, interval, fn, name="timer"):
        super().__init__(daemon=True, name=name)
        self.interval = interval
        self.fn = fn
        self._stop = threading.Event()

    def run(self):
        while not self._stop.wait(self.interval):
            try:
                self.fn()
            except Exception as e:  # noqa
                dbg("timer %s error: %r" % (self.name, e))

    def stop(self):
        self._stop.set()

# -------------------------------------------------------------- constants ----
PFCP_PORT = 8805                     # standard PFCP destination port
DEFAULT_RECOVERY_TS = int(time.time())
