"""
IX SOAR - Syslog Parser

지원:
    - RFC 3164
    - RFC 5424 Version 1

역할:
    - Syslog 헤더 추출
    - Priority, Facility, Severity 계산
    - Timestamp 추출
    - Structured Data 분리
    - Message Body 추출

주의:
    - 메시지 본문은 별도 Parser에서 처리한다.
    - RFC3164의 연도와 시간대는 임의로 추정하지 않는다.
"""

from __future__ import annotations

import calendar
import re

from dataclasses import dataclass
from datetime import datetime, time, timezone


# --------------------------------------------------
# 1. 파싱 오류
# --------------------------------------------------

class SyslogParseError(ValueError):
    """잘못되었거나 지원하지 않는 Syslog 형식"""


# --------------------------------------------------
# 2. 파싱 결과
# --------------------------------------------------

@dataclass(frozen=True)
class SyslogRecord:

    standard: str

    priority: int | None
    facility: int | None
    severity: int | None

    timestamp_text: str | None
    event_time: datetime | None

    hostname: str | None
    app_name: str | None
    proc_id: str | None
    msg_id: str | None

    structured_data: str | None

    message: str


# --------------------------------------------------
# 3. 헤더 식별 패턴
# --------------------------------------------------

_PRI = re.compile(
    r"^<([0-9]{1,3})>"
)

_VERSION = re.compile(
    r"^([1-9][0-9]{0,2}) "
)

_RFC5424_TIME = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?"
    r"(?:Z|[+-][0-9]{2}:[0-9]{2})$"
)


_MONTHS = {
    month: i
    for i, month in enumerate(
        (
            "Jan", "Feb", "Mar",
            "Apr", "May", "Jun",
            "Jul", "Aug", "Sep",
            "Oct", "Nov", "Dec"
        ),
        start=1
    )
}


_RFC3164 = re.compile(
    r"^(?P<month>"
    r"Jan|Feb|Mar|Apr|May|Jun|"
    r"Jul|Aug|Sep|Oct|Nov|Dec"
    r")"
    r"[ ]{1,2}(?P<day>[0-9]{1,2}) "
    r"(?P<hh>[0-9]{2}):"
    r"(?P<mm>[0-9]{2}):"
    r"(?P<ss>[0-9]{2}) "
    r"(?P<host>[^ ]+) "
    r"(?P<content>.*)$",
    re.DOTALL
)


_TAG = re.compile(
    r"^(?P<app>[A-Za-z0-9_.\-/]+)"
    r"(?:\[(?P<pid>[0-9]+)\])?"
    r": ?(?P<message>.*)$",
    re.DOTALL
)


# --------------------------------------------------
# 4. 공통 함수
# --------------------------------------------------

def _nil(token: str) -> str | None:

    return None if token == "-" else token


def _header_field(
    token: str,
    name: str,
    limit: int
) -> str | None:

    if (
        not 1 <= len(token) <= limit
        or any(
            not (33 <= ord(ch) <= 126)
            for ch in token
        )
    ):
        raise SyslogParseError(
            f"invalid RFC5424 {name}"
        )

    return _nil(token)


# --------------------------------------------------
# 5. RFC5424 Timestamp 처리
# --------------------------------------------------

def _timestamp(
    token: str
) -> datetime | None:

    if token == "-":
        return None

    if not _RFC5424_TIME.fullmatch(token):

        raise SyslogParseError(
            "invalid RFC5424 timestamp"
        )

    try:

        parsed = datetime.fromisoformat(
            token.replace("Z", "+00:00")
        )

        return parsed.astimezone(
            timezone.utc
        )

    except ValueError as exc:

        raise SyslogParseError(
            "invalid RFC5424 timestamp"
        ) from exc


# --------------------------------------------------
# 6. Structured Data 검증
# --------------------------------------------------

def _sd_name(name: str) -> bool:

    return (
        1 <= len(name) <= 32
        and all(
            33 <= ord(char) <= 126
            and char not in '= ]"'
            for char in name
        )
    )


def _structured_data(
    value: str
) -> tuple[str | None, str]:

    """
    RFC5424 Structured Data와 메시지 본문을 분리한다.

    Structured Data 내부의 따옴표, 이스케이프,
    대괄호를 검사한다.

    Structured Data 자체는 원문 문자열로 보존한다.
    """

    # Structured Data가 없는 경우
    if value == "-":
        return None, ""

    if value.startswith("- "):
        return None, value[2:]

    if not value.startswith("["):

        raise SyslogParseError(
            "missing RFC5424 structured data"
        )

    i = 0
    length = len(value)

    seen_ids: set[str] = set()

    # 여러 개의 SD Element 지원
    while i < length and value[i] == "[":

        i += 1
        start = i

        # SD-ID 추출
        while (
            i < length
            and value[i] not in " ]"
        ):
            i += 1

        sd_id = value[start:i]

        if (
            not _sd_name(sd_id)
            or sd_id in seen_ids
        ):
            raise SyslogParseError(
                "invalid or duplicate SD-ID"
            )

        seen_ids.add(sd_id)

        seen_params: set[str] = set()

        # SD Parameter 처리
        while (
            i < length
            and value[i] == " "
        ):

            i += 1
            start = i

            while (
                i < length
                and value[i] not in '= ]'
            ):
                i += 1

            param = value[start:i]

            if (
                not _sd_name(param)
                or param in seen_params
            ):
                raise SyslogParseError(
                    "invalid or duplicate SD param"
                )

            seen_params.add(param)

            if (
                i >= length
                or value[i] != "="
            ):
                raise SyslogParseError(
                    "SD parameter missing '='"
                )

            i += 1

            if (
                i >= length
                or value[i] != '"'
            ):
                raise SyslogParseError(
                    "SD parameter requires quoted value"
                )

            i += 1

            # 따옴표로 감싼 Parameter Value
            while True:

                if i >= length:

                    raise SyslogParseError(
                        "unterminated SD parameter"
                    )

                char = value[i]

                if char == '"':
                    i += 1
                    break

                if char == "\\":

                    i += 1

                    if (
                        i >= length
                        or value[i] not in (
                            '"', "\\", "]"
                        )
                    ):
                        raise SyslogParseError(
                            "invalid SD escape"
                        )

                elif char == "]":

                    raise SyslogParseError(
                        "unescaped ']' in SD value"
                    )

                i += 1

            if (
                i < length
                and value[i] not in " ]"
            ):
                raise SyslogParseError(
                    "invalid character after SD parameter"
                )

        # SD Element 종료 확인
        if (
            i >= length
            or value[i] != "]"
        ):
            raise SyslogParseError(
                "unterminated SD element"
            )

        i += 1

    # Structured Data 이후 메시지가 없는 경우
    if i == length:
        return value, ""

    # Structured Data와 Message 사이 공백
    if value[i] != " ":

        raise SyslogParseError(
            "invalid separator after structured data"
        )

    return value[:i], value[i + 1:]


# --------------------------------------------------
# 7. RFC5424 Parser
# --------------------------------------------------

def _rfc5424(
    rest: str,
    pri: int
) -> SyslogRecord:

    # VERSION 1 뒤부터 헤더 분리
    parts = rest[2:].split(" ", 5)

    if (
        len(parts) != 6
        or any(not part for part in parts)
    ):
        raise SyslogParseError(
            "incomplete RFC5424 header"
        )

    (
        timestamp,
        hostname,
        app,
        proc,
        msgid,
        sd_and_msg
    ) = parts

    # Timestamp 검증 및 UTC 변환
    event_time = _timestamp(timestamp)

    # 헤더 필드 검증
    hostname = _header_field(
        hostname, "hostname", 255
    )

    app = _header_field(
        app, "app_name", 48
    )

    proc = _header_field(
        proc, "proc_id", 128
    )

    msgid = _header_field(
        msgid, "msg_id", 32
    )

    # Structured Data 및 Message 분리
    sd, message = _structured_data(
        sd_and_msg
    )

    return SyslogRecord(
        standard="rfc5424",

        priority=pri,
        facility=pri // 8,
        severity=pri % 8,

        timestamp_text=_nil(timestamp),
        event_time=event_time,

        hostname=hostname,
        app_name=app,
        proc_id=proc,
        msg_id=msgid,

        structured_data=sd,
        message=message.removeprefix("\ufeff")
    )


# --------------------------------------------------
# 8. RFC3164 Parser
# --------------------------------------------------

def _rfc3164(
    rest: str,
    pri: int | None
) -> SyslogRecord:

    match = _RFC3164.fullmatch(rest)

    if match is None:

        raise SyslogParseError(
            "invalid RFC3164 header"
        )

    # 날짜 유효성 검사
    month = _MONTHS[
        match.group("month")
    ]

    day = int(
        match.group("day")
    )

    # 연도가 없으므로 윤년의 2월 29일까지 허용
    if not 1 <= day <= calendar.monthrange(
        2024, month
    )[1]:

        raise SyslogParseError(
            "invalid RFC3164 day"
        )

    # 시각 유효성 검사
    try:

        time(
            int(match.group("hh")),
            int(match.group("mm")),
            int(match.group("ss"))
        )

    except ValueError as exc:

        raise SyslogParseError(
            "invalid RFC3164 clock"
        ) from exc

    # TAG 및 메시지 본문 추출
    content = match.group("content")

    tag = _TAG.fullmatch(content)

    app = (
        tag.group("app")
        if tag else None
    )

    proc = (
        tag.group("pid")
        if tag else None
    )

    message = (
        tag.group("message")
        if tag else content
    )

    return SyslogRecord(
        standard="rfc3164",

        priority=pri,

        facility=(
            pri // 8
            if pri is not None else None
        ),

        severity=(
            pri % 8
            if pri is not None else None
        ),

        timestamp_text=rest[
            :match.start("host") - 1
        ],

        # 연도와 시간대를 알 수 없음
        event_time=None,

        hostname=match.group("host"),
        app_name=app,
        proc_id=proc,
        msg_id=None,

        structured_data=None,
        message=message
    )


# --------------------------------------------------
# 9. Syslog Parser 진입점
# --------------------------------------------------

def parse_syslog(
    raw: bytes | str,
    *,
    max_bytes: int = 65536
) -> SyslogRecord:

    """
    Syslog 원본에서 헤더와 메시지를 분리한다.

    Args:
        raw:
            원본 Syslog 메시지

        max_bytes:
            최대 입력 메시지 크기

    Returns:
        SyslogRecord
    """

    # 1. 설정 검증
    if max_bytes <= 0:

        raise ValueError(
            "max_bytes must be positive"
        )

    # 2. 입력 타입 검증
    if not isinstance(raw, (bytes, str)):

        raise TypeError(
            "raw must be bytes or str"
        )

    # 3. 크기 및 인코딩 검증
    try:

        if isinstance(raw, bytes):

            if len(raw) > max_bytes:

                raise SyslogParseError(
                    "message exceeds max_bytes"
                )

            text = raw.decode("utf-8-sig")

        else:

            if len(raw.encode("utf-8")) > max_bytes:

                raise SyslogParseError(
                    "message exceeds max_bytes"
                )

            text = raw.removeprefix("\ufeff")

    except (
        UnicodeDecodeError,
        UnicodeEncodeError
    ) as exc:

        raise SyslogParseError(
            "Syslog must be valid UTF-8"
        ) from exc

    if not text:

        raise SyslogParseError(
            "empty Syslog message"
        )

    # 4. Priority 추출
    priority: int | None = None

    pri_match = _PRI.match(text)

    if pri_match:

        priority = int(
            pri_match.group(1)
        )

        if priority > 191:

            raise SyslogParseError(
                "Syslog PRI must be 0..191"
            )

        text = text[
            pri_match.end():
        ]

    elif text.startswith("<"):

        raise SyslogParseError(
            "invalid Syslog PRI prefix"
        )

    # 5. RFC5424 버전 확인
    version_match = (
        _VERSION.match(text)
        if priority is not None
        else None
    )

    if version_match:

        version = int(
            version_match.group(1)
        )

        if version != 1:

            raise SyslogParseError(
                "unsupported RFC5424 version"
            )

        return _rfc5424(
            text,
            priority
        )

    # 6. RFC3164 파싱
    return _rfc3164(
        text,
        priority
    )