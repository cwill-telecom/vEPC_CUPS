# network/udp_client.py — simple request/response UDP client (mirrors vEPC_python).
import socket
import threading
from utils.utils import trace


class UDPClient:
    def __init__(self, local_ip="0.0.0.0", local_port=0):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((local_ip, local_port))
        self.lock = threading.Lock()

    def send(self, data, ip, port):
        with self.lock:
            self.sock.sendto(data, (ip, port))
        trace("sent %d bytes to %s:%d" % (len(data), ip, port))

    def request(self, data, ip, port, timeout=2.0):
        """Send and wait for one reply; returns (reply_bytes, addr) or (None, None)."""
        with self.lock:
            self.sock.sendto(data, (ip, port))
            self.sock.settimeout(timeout)
            try:
                reply, addr = self.sock.recvfrom(65535)
                return reply, addr
            except socket.timeout:
                return None, None

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass
