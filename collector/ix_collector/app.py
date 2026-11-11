"""Runs exactly one input mode per Kubernetes Pod."""
from __future__ import annotations

import logging
import os
import signal
import threading

from http.server import (
    BaseHTTPRequestHandler,
    ThreadingHTTPServer
)

from .api import APICollector
from .kafka_output import KafkaPublisher
from .syslog import run_tcp, run_udp


def start_health_server(
    ready: threading.Event,
    stop: threading.Event
):

    class Handler(BaseHTTPRequestHandler):

        def do_GET(self):

            if self.path == "/livez":
                status = 200

            elif self.path == "/readyz":
                status = (
                    200
                    if ready.is_set() and not stop.is_set()
                    else 503
                )

            else:
                status = 404

            self.send_response(status)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(
        ("0.0.0.0", 8080),
        Handler
    )

    thread = threading.Thread(
        target=server.serve_forever,
        daemon=True
    )

    thread.start()

    return server


def main():

    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s"
    )

    mode = os.environ["COLLECTOR_MODE"]

    if mode not in {
        "syslog-udp",
        "syslog-tcp",
        "api"
    }:
        raise ValueError(
            "COLLECTOR_MODE must be syslog-udp, syslog-tcp or api"
        )

    if not os.getenv("KAFKA_BROKERS"):
        raise ValueError(
            "KAFKA_BROKERS is required"
        )

    stop = threading.Event()
    ready = threading.Event()

    signal.signal(
        signal.SIGINT,
        lambda *_: stop.set()
    )

    signal.signal(
        signal.SIGTERM,
        lambda *_: stop.set()
    )

    health = start_health_server(
        ready,
        stop
    )

    publisher = KafkaPublisher()

    try:

        if mode == "syslog-udp":

            run_udp(
                publisher,
                stop,
                ready
            )

        elif mode == "syslog-tcp":

            run_tcp(
                publisher,
                stop,
                ready
            )

        else:

            APICollector(
                publisher,
                stop,
                ready
            ).run()

    finally:

        ready.clear()
        stop.set()

        publisher.close()

        health.shutdown()
        health.server_close()


if __name__ == "__main__":
    main()