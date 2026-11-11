"""
IX SOAR - Log Format Detector

역할:
    원본 로그의 외부 형식을 자동 판별한다.

지원:
    - JSON
    - Key-Value
    - Syslog
    - Delimited (설정된 경우)
    - Unknown
"""

from __future__ import annotations

import json
import re

from dataclasses import dataclass
from enum import Enum

from .delimiter_parser import (
    DelimiterParseError,
    parse_delimited
)


# --------------------------------------------------
# 1. 지원 형식
# --------------------------------------------------

class LogFormat(str, Enum):

    JSON = "json"
    KEY_VALUE = "key_value"
    SYSLOG = "syslog"
    DELIMITED = "delimited"
    UNKNOWN = "unknown"


# --------------------------------------------------
# 2. 판별 결과
# --------------------------------------------------

@dataclass(frozen=True)
class DetectionResult:

    format: LogFormat
    reason: str


# --------------------------------------------------
# 3. 판별 패턴
# --------------------------------------------------

_SYSLOG_PRI = re.compile(
    r"^<(?P<priority>\d{1,3})>"
)

_RFC3164_NO_PRI = re.compile(
    r"^(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
    r"\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+"
)

_KV_PREFIX = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_.-]*\s*="
)


# --------------------------------------------------
# 4. 형식 판별
# --------------------------------------------------

def detect_format(
    raw: bytes | str,
    *,
    delimiter: str | None = None,
    expected_fields: int | None = None
) -> DetectionResult:

    """
    로그 형식을 판별한다.

    delimiter:
        장비에 설정된 구분자.
        None이면 Delimited 형식을 추정하지 않는다.

    expected_fields:
        Delimited 로그의 예상 필드 개수.
    """

    if (
        expected_fields is not None
        and delimiter is None
    ):
        raise ValueError(
            "expected_fields requires delimiter"
        )

    # 1. 입력 디코딩
    if isinstance(raw, bytes):

        try:
            text = raw.decode("utf-8")

        except UnicodeDecodeError:

            return DetectionResult(
                LogFormat.UNKNOWN,
                "invalid_utf8"
            )

    elif isinstance(raw, str):

        text = raw

    else:

        raise TypeError(
            "raw must be bytes or str"
        )

    text = text.strip().lstrip("\ufeff")

    if not text:

        return DetectionResult(
            LogFormat.UNKNOWN,
            "empty_log"
        )

    # 2. Syslog Priority 확인
    priority = _SYSLOG_PRI.match(text)

    if priority:

        pri = int(
            priority.group("priority")
        )

        if 0 <= pri <= 191:

            return DetectionResult(
                LogFormat.SYSLOG,
                "syslog_priority_header"
            )

    # 3. PRI 없는 RFC3164
    if _RFC3164_NO_PRI.match(text):

        return DetectionResult(
            LogFormat.SYSLOG,
            "rfc3164_timestamp_header"
        )

    # 4. JSON 판별
    if text.startswith(("{", "[")):

        try:
            parsed = json.loads(text)

        except json.JSONDecodeError:

            return DetectionResult(
                LogFormat.UNKNOWN,
                "invalid_json"
            )

        if isinstance(parsed, (dict, list)):

            return DetectionResult(
                LogFormat.JSON,
                "valid_json_structure"
            )

        return DetectionResult(
            LogFormat.UNKNOWN,
            "unsupported_json_value"
        )

    # 5. Key-Value 판별
    if _KV_PREFIX.match(text):

        return DetectionResult(
            LogFormat.KEY_VALUE,
            "key_value_prefix"
        )

    # 6. Delimiter 판별
    if delimiter is not None:

        try:

            records = parse_delimited(
                raw,
                delimiter=delimiter,
                expected_fields=expected_fields
            )

        except DelimiterParseError:

            return DetectionResult(
                LogFormat.UNKNOWN,
                "invalid_delimited"
            )

        if len(records[0].values) >= 2:

            return DetectionResult(
                LogFormat.DELIMITED,
                "configured_delimiter"
            )

    # 7. 알 수 없는 형식
    return DetectionResult(
        LogFormat.UNKNOWN,
        "unrecognized_format"
    )