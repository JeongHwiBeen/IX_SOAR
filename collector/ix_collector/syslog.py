"""UDP and TCP Syslog receivers. No parsing and no local disk writes."""
from __future__ import annotations

import logging
import os
import socket
import socketserver
import threading

from .framing import FrameTooLarge, SyslogFramer
from .kafka_output import KafkaPublisher, RawLog

LOG = logging.getLogger(__name__)


def run_udp(
    publisher: KafkaPublisher,
    stop: threading.Event,
    ready: threading.Event
):
    host = os.getenv("SYSLOG_HOST", "0.0.0.0")
    port = int(os.getenv("SYSLOG_PORT", "1514"))
    limit = int(os.getenv("MAX_MESSAGE_BYTES", "65507"))
    dropped = 0

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:

        sock.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_RCVBUF,
            4 * 1024 * 1024
        )

        sock.bind((host, port))
        sock.settimeout(1)

        ready.set()

        LOG.info(
            "UDP syslog listening at %s:%d",
            host, port
        )

        while not stop.is_set():

            try:
                raw, _anc, flags, peer = sock.recvmsg(limit, 0)

            except socket.timeout:
                continue

            failed = bool(flags & socket.MSG_TRUNC)

            if not failed:
                rec = RawLog.build(
                    raw,
                    "syslog-udp",
                    peer[0]
                )

                failed = not publisher.try_publish(rec)

            if failed:
                dropped += 1

                if dropped == 1 or dropped % 100 == 0:
                    LOG.warning(
                        "UDP messages dropped=%d",
                        dropped
                    )


def run_tcp(
    publisher: KafkaPublisher,
    stop: threading.Event,
    ready: threading.Event
):
    host = os.getenv("SYSLOG_HOST", "0.0.0.0")
    port = int(os.getenv("SYSLOG_PORT", "1514"))
    limit = int(os.getenv("MAX_MESSAGE_BYTES", "65536"))
    mode = os.getenv("TCP_FRAMING", "auto")

    slots = threading.BoundedSemaphore(
        int(os.getenv("TCP_MAX_CONNECTIONS", "100"))
    )

    class Server(socketserver.ThreadingTCPServer):

        allow_reuse_address = True
        daemon_threads = True
        request_queue_size = 128

        def verify_request(self, _request, _address):
            return slots.acquire(blocking=False)

        def process_request_thread(self, request, client_address):
            try:
                super().process_request_thread(
                    request,
                    client_address
                )

            finally:
                slots.release()

    class Handler(socketserver.BaseRequestHandler):

        def handle(self):
            framer = SyslogFramer(mode, limit)
            self.request.settimeout(1)

            while not stop.is_set():

                try:
                    chunk = self.request.recv(65536)

                except socket.timeout:
                    continue

                if not chunk:
                    return

                try:
                    frames = framer.feed(chunk)

                except (FrameTooLarge, ValueError):
                    LOG.warning(
                        "Invalid TCP frame from %s",
                        self.client_address[0]
                    )
                    return

                for frame in frames:

                    rec = RawLog.build(
                        frame,
                        "syslog-tcp",
                        self.client_address[0]
                    )

                    if not publisher.publish_with_backpressure(
                        rec,
                        stop
                    ):
                        return

    with Server((host, port), Handler) as server:

        server.timeout = 1
        ready.set()

        LOG.info(
            "TCP syslog listening at %s:%d",
            host, port
        )

        while not stop.is_set():
            server.handle_request()