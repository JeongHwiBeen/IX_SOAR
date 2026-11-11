"""Generic read-only device REST API poller with Kafka-backed cursor checkpoints."""
from __future__ import annotations

import json
import logging
import os
import threading
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from .kafka_output import (
    KafkaCheckpointStore,
    KafkaPublisher,
    RawLog,
    api_message_id,
)

LOG = logging.getLogger(__name__)


def nested(obj, dotted_path: str):

    for part in dotted_path.split("."):

        if not isinstance(obj, dict) or part not in obj:
            raise ValueError(
                f"Missing API response field: {dotted_path}"
            )

        obj = obj[part]

    return obj


class NoRedirect(urllib.request.HTTPRedirectHandler):

    def redirect_request(
        self, req, fp, code, msg, headers, newurl
    ):
        raise urllib.error.HTTPError(
            req.full_url,
            code,
            "redirect denied",
            headers,
            fp
        )


class APICollector:

    def __init__(
        self,
        publisher: KafkaPublisher,
        stop: threading.Event,
        ready: threading.Event
    ):
        self.publisher = publisher
        self.stop = stop
        self.ready = ready

        self.config = json.loads(
            Path(
                os.environ["API_CONFIG_PATH"]
            ).read_text("utf-8")
        )

        cfg = self.config

        for required in (
            "name",
            "url",
            "items_path",
            "next_cursor_path",
            "record_id_path",
            "cursor_param"
        ):
            if not cfg.get(required):
                raise ValueError(
                    f"API config missing: {required}"
                )

        url = urllib.parse.urlsplit(cfg["url"])

        if url.scheme != "https":
            raise ValueError(
                "Device API endpoint must use HTTPS"
            )

        self.source_id = f"api:{cfg['name']}"

        self.interval = float(
            cfg.get("interval_seconds", 30)
        )

        self.timeout = float(
            cfg.get("timeout_seconds", 10)
        )

        self.max_bytes = int(
            cfg.get("max_response_bytes", 4_194_304)
        )

        self.max_items = int(
            cfg.get("max_page_items", 1000)
        )

        if min(
            self.interval,
            self.timeout,
            self.max_bytes,
            self.max_items
        ) <= 0:
            raise ValueError(
                "API limits must be positive"
            )

        self.checkpoints_topic = os.getenv(
            "KAFKA_CHECKPOINT_TOPIC",
            "ix.collector.checkpoints"
        )

        self.checkpoint_store = KafkaCheckpointStore(
            self.checkpoints_topic
        )

        self.http = urllib.request.build_opener(
            NoRedirect()
        )

    def request_page(
        self,
        cursor: str | None
    ) -> tuple[list, str | None]:

        cfg = self.config
        parsed = urllib.parse.urlsplit(cfg["url"])

        query = dict(
            urllib.parse.parse_qsl(parsed.query)
        )

        if cursor is not None:
            query[cfg["cursor_param"]] = cursor

        url = urllib.parse.urlunsplit((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            urllib.parse.urlencode(query),
            ""
        ))

        headers = {
            "Accept": "application/json",
            "User-Agent": "IX-SOAR/0.2"
        }

        if cfg.get("auth_env"):

            headers[
                cfg.get("auth_header", "Authorization")
            ] = (
                cfg.get("auth_prefix", "Bearer ")
                + os.environ[cfg["auth_env"]]
            )

        request = urllib.request.Request(
            url,
            headers=headers,
            method="GET"
        )

        with self.http.open(
            request,
            timeout=self.timeout
        ) as response:

            content = response.read(
                self.max_bytes + 1
            )

        if len(content) > self.max_bytes:
            raise ValueError(
                "API response exceeds max_response_bytes"
            )

        body = json.loads(content)

        items = nested(
            body,
            cfg["items_path"]
        )

        next_cursor = nested(
            body,
            cfg["next_cursor_path"]
        )

        if (
            not isinstance(items, list)
            or len(items) > self.max_items
        ):
            raise ValueError(
                "API page must be an array within max_page_items"
            )

        if (
            next_cursor is not None
            and not isinstance(next_cursor, (str, int))
        ):
            raise ValueError(
                "next_cursor must be a string, integer, or null"
            )

        return (
            items,
            None if next_cursor is None else str(next_cursor)
        )

    def run(self):

        cursor = self.checkpoint_store.load(
            self.source_id
        )

        if cursor is None:
            cursor = self.config.get(
                "initial_cursor"
            )

        LOG.info(
            "API source=%s checkpoint loaded=%s",
            self.source_id,
            cursor is not None
        )

        self.ready.set()

        while not self.stop.is_set():

            try:
                items, next_cursor = self.request_page(
                    cursor
                )

                records = []

                for row in items:

                    if not isinstance(row, dict):
                        raise ValueError(
                            "API items must be JSON objects"
                        )

                    unique = nested(
                        row,
                        self.config["record_id_path"]
                    )

                    if unique is None:
                        raise ValueError(
                            "API record ID must not be null"
                        )

                    raw = json.dumps(
                        row,
                        ensure_ascii=False,
                        separators=(",", ":")
                    ).encode()

                    records.append(
                        RawLog.build(
                            raw,
                            "device-api",
                            self.source_id,
                            api_message_id(
                                self.source_id,
                                str(unique)
                            )
                        )
                    )

                if items and next_cursor is None:
                    raise ValueError(
                        "Non-empty API page is missing next_cursor"
                    )

                if items and next_cursor == cursor:
                    raise ValueError(
                        "API returned records without advancing cursor"
                    )

                if not self.publisher.publish_confirmed(
                    records,
                    self.stop
                ):
                    raise RuntimeError(
                        "Kafka did not ACK complete API page"
                    )

                if (
                    next_cursor is not None
                    and next_cursor != cursor
                ):

                    if not self.publisher.publish_confirmed(
                        [],
                        self.stop,
                        topic=self.checkpoints_topic,
                        key_value=(
                            self.source_id.encode(),
                            next_cursor.encode()
                        )
                    ):
                        raise RuntimeError(
                            "Kafka checkpoint ACK failed"
                        )

                    cursor = next_cursor

                if items:
                    LOG.info(
                        "API source=%s delivered=%d",
                        self.source_id,
                        len(items)
                    )

            except Exception as exc:

                LOG.warning(
                    "API source=%s poll failed (%s)",
                    self.source_id,
                    type(exc).__name__
                )

            self.stop.wait(
                self.interval
            )