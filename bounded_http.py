"""Small bounded HTTP server with a total request-header deadline."""
import io
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from threading import BoundedSemaphore


class _DeadlineReader(io.RawIOBase):
    def __init__(self, sock, deadline):
        super().__init__()
        self.sock = sock
        self.deadline = deadline

    def readable(self):
        return True

    def fileno(self):
        return self.sock.fileno()

    def readinto(self, buffer):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('request header deadline exceeded')
        self.sock.settimeout(remaining)
        return self.sock.recv_into(buffer)


class DeadlineHTTPRequestHandler(BaseHTTPRequestHandler):
    """Apply one absolute deadline while the request line and headers arrive."""
    header_timeout_seconds = 5
    response_timeout_seconds = 5

    def setup(self):
        self.connection = self.request
        raw = _DeadlineReader(
            self.connection, time.monotonic() + self.header_timeout_seconds)
        self.rfile = io.BufferedReader(raw, buffer_size=8192)
        self.wfile = self.connection.makefile('wb', self.wbufsize)

    def response_ready(self):
        self.connection.settimeout(self.response_timeout_seconds)


class BoundedHTTPServer(ThreadingMixIn, HTTPServer):
    """Serve a small fixed number of requests without unbounded worker threads."""
    daemon_threads = True
    block_on_close = True
    max_workers = 4
    request_queue_size = 8

    def __init__(self, *args, **kwargs):
        self._worker_slots = BoundedSemaphore(self.max_workers)
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        if not self._worker_slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._worker_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._worker_slots.release()
