"""Local-disk-free Kafka transport for raw bytes. Kafka must provide durability."""
from __future__ import annotations

import hashlib
import logging
import os
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from confluent_kafka import Consumer, Producer, TopicPartition

LOG = logging.getLogger(__name__)


def kafka_common_config() -> dict:
    conf = {"bootstrap.servers": os.environ["KAFKA_BROKERS"]}
    protocol = os.getenv("KAFKA_SECURITY_PROTOCOL", "PLAINTEXT")
    conf["security.protocol"] = protocol

    if protocol.startswith("SASL_"):
        conf.update({
            "sasl.mechanism": os.environ["KAFKA_SASL_MECHANISM"],
            "sasl.username": os.environ["KAFKA_USERNAME"],
            "sasl.password": os.environ["KAFKA_PASSWORD"],
        })

    if os.getenv("KAFKA_SSL_CA_LOCATION"):
        conf["ssl.ca.location"] = os.environ["KAFKA_SSL_CA_LOCATION"]

    return conf


@dataclass(frozen=True)
class RawLog:
    value: bytes
    transport: str
    source: str
    message_id: str
    received_at: str

    @classmethod
    def build(
        cls,
        value: bytes,
        transport: str,
        source: str,
        message_id: str | None = None
    ) -> "RawLog":

        return cls(
            value=value,
            transport=transport,
            source=source,
            message_id=message_id or uuid.uuid4().hex,
            received_at=datetime.now(timezone.utc).isoformat(),
        )

    @property
    def headers(self) -> list[tuple[str, bytes]]:
        return [
            ("message_id", self.message_id.encode()),
            ("transport", self.transport.encode()),
            ("source", self.source.encode()),
            ("received_at", self.received_at.encode()),
        ]


def api_message_id(device: str, record_id: str) -> str:
    return hashlib.sha256(
        f"{device}\0{record_id}".encode()
    ).hexdigest()


class KafkaPublisher:

    def __init__(self):
        conf = kafka_common_config()

        conf.update({
            "acks": "all",
            "enable.idempotence": True,
            "compression.type": "lz4",
            "linger.ms": 15,
            "queue.buffering.max.kbytes": 65536,
            "message.timeout.ms": 120000,
        })

        self.producer = Producer(conf)
        self.topic = os.getenv("KAFKA_TOPIC", "ix.raw.logs")

        self._closed = threading.Event()

        self._poller = threading.Thread(
            target=self._poll_loop,
            daemon=True
        )
        self._poller.start()

    def _poll_loop(self):
        while not self._closed.is_set():
            self.producer.poll(0.1)

    def _send(
        self,
        topic: str,
        key: bytes,
        value: bytes,
        headers: list[tuple[str, bytes]] | None = None,
        callback=None
    ) -> bool:

        try:
            self.producer.produce(
                topic=topic,
                key=key,
                value=value,
                headers=headers,
                on_delivery=callback,
            )
            return True

        except BufferError:
            return False

    @staticmethod
    def _delivery_notice(err, _msg):
        if err is not None:
            LOG.error(
                "Kafka delivery failed; in-memory record may be lost: %s",
                err
            )

    def try_publish(self, record: RawLog) -> bool:
        """UDP path: never wait when the Kafka queue is full."""

        return self._send(
            self.topic,
            record.source.encode(),
            record.value,
            record.headers,
            self._delivery_notice,
        )

    def publish_with_backpressure(
        self,
        record: RawLog,
        stop: threading.Event
    ):
        """TCP path: pause socket reading while Kafka producer is full."""

        while not stop.is_set():
            if self.try_publish(record):
                return True

            stop.wait(0.05)

        return False

    def publish_confirmed(
        self,
        records: list[RawLog],
        stop: threading.Event,
        *,
        topic: str | None = None,
        key_value: tuple[bytes, bytes] | None = None,
        timeout: float = 150.0
    ) -> bool:
        """
        API path: wait for broker delivery ACK before advancing checkpoint.

        Passing key_value publishes one checkpoint message instead of raw records.
        This is at-least-once, not an atomic transaction with the API source.
        """

        if key_value is None and not records:
            return True

        pending = len(records) if key_value is None else 1
        completed = threading.Event()
        lock = threading.Lock()
        failed = False

        def on_delivery(err, _msg):
            nonlocal pending, failed

            with lock:
                if err is not None:
                    failed = True
                    LOG.warning(
                        "Kafka confirmed batch delivery failed: %s",
                        err
                    )

                pending -= 1

                if pending == 0:
                    completed.set()

        items = (
            [
                (r.source.encode(), r.value, r.headers)
                for r in records
            ]
            if key_value is None
            else [(key_value[0], key_value[1], None)]
        )

        target = topic or self.topic
        deadline = time.monotonic() + timeout

        for key, value, headers in items:
            while not stop.is_set() and time.monotonic() < deadline:
                if self._send(
                    target,
                    key,
                    value,
                    headers,
                    on_delivery
                ):
                    break

                stop.wait(0.05)

            else:
                return False

        while not completed.wait(0.1):
            if stop.is_set() or time.monotonic() >= deadline:
                return False

        return not failed

    def close(self):
        remaining = self.producer.flush(10.0)

        self._closed.set()
        self._poller.join(timeout=2)

        if remaining:
            LOG.warning(
                "Kafka shutdown with %d undelivered messages",
                remaining
            )


class KafkaCheckpointStore:
    """Read an API cursor from a one-partition compacted Kafka topic."""

    def __init__(self, topic: str):
        self.topic = topic

    def load(self, source_id: str) -> str | None:
        conf = kafka_common_config()

        conf.update({
            "group.id": f"ix-checkpoint-read-{uuid.uuid4().hex}",
            "enable.auto.commit": False,
            "auto.offset.reset": "earliest",
        })

        consumer = Consumer(conf)

        try:
            partition = TopicPartition(self.topic, 0)

            low, high = consumer.get_watermark_offsets(
                partition,
                timeout=10
            )

            if low == high:
                return None

            consumer.assign([
                TopicPartition(self.topic, 0, low)
            ])

            cursor = None
            deadline = time.monotonic() + 30
            last_offset = low - 1

            while last_offset < high - 1:
                if time.monotonic() >= deadline:
                    raise TimeoutError(
                        "Could not reconstruct API checkpoint"
                    )

                msg = consumer.poll(1.0)

                if msg is None:
                    continue

                if msg.error():
                    raise RuntimeError(
                        f"Kafka checkpoint read error: {msg.error()}"
                    )

                last_offset = msg.offset()

                if msg.key() == source_id.encode():
                    cursor = (
                        msg.value().decode()
                        if msg.value() is not None
                        else None
                    )

            return cursor

        finally:
            consumer.close()