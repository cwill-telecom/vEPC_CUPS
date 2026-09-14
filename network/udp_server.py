# network/udp_server.py — threaded UDP server (mirrors vEPC_python's udp_server.py).
import socket
import threading
from utils.utils import dbg, trace


class UDPServer(threading.Thread):
    """One recv loop; dispatches each datagram to `handler(data, addr)`.

    The handler may return bytes/text to send straight back to the sender
    (used for the PFCP request/response heartbeats and association setup).
    """

    def __init__(self, ip, port, handler, name="udp"):
        super().__init__(daemon=True, name=name)
        self.ip = ip
        self.port = port
        self.handler = handler
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((ip, port))
        self._stop = threading.Event()
        dbg("UDP server bound to %s:%d" % (ip, port))

    def run(self):
        self.sock.settimeout(0.5)
        while not self._stop.is_set():
            try:
                data, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            trace("recv %d bytes from %s" % (len(data), addr))
            try:
                reply = self.handler(data, addr)
            except Exception as e:  # noqa
                dbg("handler error from %s: %r" % (addr, e))
                reply = None
            if reply:
                self.sock.sendto(reply, addr)

    def send(self, data, addr):
        self.sock.sendto(data, addr)

    def stop(self):
        self._stop.set()
        try:
            self.sock.close()
        except OSError:
            pass
