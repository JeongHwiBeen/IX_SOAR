"""
IX SOAR - Validator

역할:
    Field Mapper가 생성한 표준 필드의
    데이터 타입과 유효성을 검사한다.

지원:
    - IPv4 / IPv6
    - Port
    - Protocol
    - Action
    - Event Time
    - Device ID

설계 원칙:
    1. 원본 데이터를 변경하지 않는다.
    2. 검증 실패 시 오류 정보를 반환한다.
    3. 알 수 없는 값을 임의로 해석하지 않는다.
    4. Timestamp의 시간대를 임의로 추측하지 않는다.
"""

from __future__ import annotations

import ipaddress
import re

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping

from .field_mapper import (
    ALLOWED_TARGETS,
    MappedRecord,
)


# --------------------------------------------------
# 1. 검증 오류 및 경고
# --------------------------------------------------

@dataclass(frozen=True)
class ValidationIssue:

    field: str
    severity: str
    code: str
    message: str


# --------------------------------------------------
# 2. 검증 결과
# --------------------------------------------------

@dataclass(frozen=True)
class ValidationResult:

    fields: dict[str, Any]

    issues: tuple[ValidationIssue, ...]

    @property
    def is_valid(self) -> bool:

        return not any(
            issue.severity == "error"
            for issue in self.issues
        )

    @property
    def status(self) -> str:

        if not self.is_valid:
            return "failed"

        if self.issues:
            return "partial"

        return "success"


# --------------------------------------------------
# 3. 입력 형식 검증 패턴
# --------------------------------------------------

_INT_TEXT = re.compile(
    r"^[0-9]{1,5}$"
)

_PROTOCOL_TOKEN = re.compile(
    r"^[A-Za-z][A-Za-z0-9_.+/-]{0,31}$"
)

_ACTION_TOKEN = re.compile(
    r"^[^\x00-\x1f\x7f]{1,64}$"
)

_TIME_TEXT = re.compile(
    r"^\d{4}-\d{2}-\d{2}[T ]"
    r"\d{2}:\d{2}:\d{2}"
    r"(?:\.\d{1,6})?"
    r"(?:Z|[+-]\d{2}:\d{2})?$"
)


# --------------------------------------------------
# 4. Protocol 표준화 규칙
# --------------------------------------------------

_PROTOCOLS = {

    # IP Protocol Number
    "1": "ICMP",
    "6": "TCP",
    "17": "UDP",
    "47": "GRE",
    "50": "ESP",
    "58": "ICMPV6",
    "132": "SCTP",

    # Protocol Name
    "ICMP": "ICMP",
    "TCP": "TCP",
    "UDP": "UDP",
    "GRE": "GRE",
    "ESP": "ESP",
    "ICMPV6": "ICMPV6",
    "IPV6-ICMP": "ICMPV6",
    "SCTP": "SCTP",
}


# --------------------------------------------------
# 5. Action 표준화 규칙
# --------------------------------------------------

_ACTIONS = {

    # Allow
    "allow": "allow",
    "allowed": "allow",
    "accept": "allow",
    "permit": "allow",
    "pass": "allow",

    # Deny
    "deny": "deny",
    "denied": "deny",
    "block": "deny",
    "blocked": "deny",

    # Drop
    "drop": "drop",
    "dropped": "drop",
    "discard": "drop",

    # Reject
    "reject": "reject",
    "rejected": "reject",

    # Other
    "reset": "reset",
    "alert": "alert",
    "monitor": "monitor",
    "quarantine": "quarantine",
}


# --------------------------------------------------
# 6. IP 주소 검증
# --------------------------------------------------

def _ip(value: Any) -> str:

    if not isinstance(value, str):

        raise ValueError(
            "IP must be a string"
        )

    candidate = value.strip()

    # 인터페이스 범위가 지정된 IPv6 주소는 지원하지 않음
    if "%" in candidate:

        raise ValueError(
            "zone-scoped IPv6 addresses are not supported"
        )

    try:

        return str(
            ipaddress.ip_address(candidate)
        )

    except ValueError as exc:

        raise ValueError(
            "invalid IPv4 or IPv6 address"
        ) from exc


# --------------------------------------------------
# 7. Port 검증
# --------------------------------------------------

def _port(value: Any) -> int:

    # bool은 int의 하위 타입이므로 정확한 타입 비교
    if type(value) is int:

        number = value

    elif (
        isinstance(value, str)
        and _INT_TEXT.fullmatch(value.strip())
    ):

        number = int(
            value.strip()
        )

    else:

        raise ValueError(
            "port must be a decimal integer"
        )

    if not 0 <= number <= 65535:

        raise ValueError(
            "port must be between 0 and 65535"
        )

    return number


# --------------------------------------------------
# 8. Protocol 검증 및 표준화
# --------------------------------------------------

def _protocol(
    value: Any
) -> tuple[str, bool]:

    if type(value) is int:

        if not 0 <= value <= 255:

            raise ValueError(
                "IP protocol number must be between 0 and 255"
            )

        token = str(value)

    elif isinstance(value, str):

        token = value.strip().upper()

        # 숫자로 전달된 IP Protocol Number
        if token.isascii() and token.isdecimal():

            number = int(token)

            if not 0 <= number <= 255:

                raise ValueError(
                    "IP protocol number must be between 0 and 255"
                )

            token = str(number)

        # 문자로 전달된 프로토콜
        elif not _PROTOCOL_TOKEN.fullmatch(token):

            raise ValueError(
                "invalid protocol token"
            )

    else:

        raise ValueError(
            "protocol must be string or integer"
        )

    canonical = _PROTOCOLS.get(token)

    if canonical is not None:

        return canonical, False

    # 알려지지 않은 프로토콜을 TCP 등으로 추측하지 않음
    return token, True


# --------------------------------------------------
# 9. Action 검증 및 표준화
# --------------------------------------------------

def _action(
    value: Any
) -> tuple[str, bool]:

    if not isinstance(value, str):

        raise ValueError(
            "action must be a string"
        )

    token = value.strip()

    if not _ACTION_TOKEN.fullmatch(token):

        raise ValueError(
            "action must be printable and 1..64 characters"
        )

    canonical = _ACTIONS.get(
        token.casefold()
    )

    if canonical is not None:

        return canonical, False

    # 알려지지 않은 Action은 원래 값을 유지
    return token, True


# --------------------------------------------------
# 10. Device ID 검증
# --------------------------------------------------

def _device_id(value: Any) -> str:

    if not isinstance(value, str):

        raise ValueError(
            "device_id must be a string"
        )

    token = value.strip()

    if (
        not 1 <= len(token) <= 128
        or any(
            ord(char) < 32 or ord(char) == 127
            for char in token
        )
    ):

        raise ValueError(
            "device_id must be printable and 1..128 characters"
        )

    return token


# --------------------------------------------------
# 11. Timestamp 검증 및 UTC 변환
# --------------------------------------------------

def _event_time(
    value: Any,
    assume_timezone: timezone | None
) -> datetime:

    # datetime 객체인 경우
    if isinstance(value, datetime):

        dt = value

    # 문자열인 경우
    elif isinstance(value, str):

        token = value.strip()

        if not _TIME_TEXT.fullmatch(token):

            raise ValueError(
                "timestamp must be ISO 8601 with seconds"
            )

        try:

            dt = datetime.fromisoformat(
                token.replace("Z", "+00:00")
            )

        except ValueError as exc:

            raise ValueError(
                "invalid calendar date or UTC offset"
            ) from exc

    else:

        raise ValueError(
            "event_time must be an ISO timestamp or datetime"
        )

    # 시간대 정보가 없는 경우
    if dt.tzinfo is None or dt.utcoffset() is None:

        if assume_timezone is None:

            raise ValueError(
                "naive timestamp requires explicit assume_timezone"
            )

        dt = dt.replace(
            tzinfo=assume_timezone
        )

    # UTC 통일
    return dt.astimezone(
        timezone.utc
    )


# --------------------------------------------------
# 12. Validator 진입점
# --------------------------------------------------

def validate_fields(
    mapped: MappedRecord | Mapping[str, Any],
    *,
    assume_timezone: timezone | None = None,
) -> ValidationResult:

    """
    IX SOAR 표준 필드 검증.

    Args:
        mapped:
            Field Mapper 결과 또는 표준 필드 딕셔너리

        assume_timezone:
            시간대가 없는 Timestamp에 적용할
            명시적인 고정 UTC 오프셋.
            None이면 시간대 없는 Timestamp는 오류 처리.

    Returns:
        ValidationResult
    """

    # 1. 시간대 설정 검증
    if (
        assume_timezone is not None
        and not isinstance(assume_timezone, timezone)
    ):

        raise TypeError(
            "assume_timezone must be datetime.timezone or None"
        )

    # 2. Field Mapper 결과 추출
    data = (
        mapped.fields
        if isinstance(mapped, MappedRecord)
        else mapped
    )

    if not isinstance(data, Mapping):

        raise TypeError(
            "mapped must be MappedRecord or mapping"
        )

    result: dict[str, Any] = {}

    issues: list[ValidationIssue] = []

    # --------------------------------------------------
    # 3. 필드별 유효성 검사
    # --------------------------------------------------

    for field, value in data.items():

        # 지원하지 않는 필드 차단
        if (
            not isinstance(field, str)
            or field not in ALLOWED_TARGETS
        ):

            issues.append(
                ValidationIssue(
                    field=str(field),
                    severity="error",
                    code="unsupported_field",
                    message="field is not in IX SOAR normalized schema",
                )
            )

            continue

        # 선택 필드에 값이 없는 경우
        if value is None:
            continue

        try:

            # ------------------------------------------
            # A. IP 주소
            # ------------------------------------------

            if field in {
                "src_ip",
                "dst_ip"
            }:

                normalized = _ip(value)

            # ------------------------------------------
            # B. Port
            # ------------------------------------------

            elif field in {
                "src_port",
                "dst_port"
            }:

                normalized = _port(value)

            # ------------------------------------------
            # C. Event Time
            # ------------------------------------------

            elif field == "event_time":

                normalized = _event_time(
                    value,
                    assume_timezone
                )

            # ------------------------------------------
            # D. Device ID
            # ------------------------------------------

            elif field == "device_id":

                normalized = _device_id(value)

            # ------------------------------------------
            # E. Protocol
            # ------------------------------------------

            elif field == "protocol":

                normalized, unknown = _protocol(value)

                if unknown:

                    issues.append(
                        ValidationIssue(
                            field=field,
                            severity="warning",
                            code="unknown_protocol",
                            message=(
                                "unrecognized protocol preserved; "
                                "do not infer a transport protocol"
                            ),
                        )
                    )

            # ------------------------------------------
            # F. Action
            # ------------------------------------------

            elif field == "action":

                normalized, unknown = _action(value)

                if unknown:

                    issues.append(
                        ValidationIssue(
                            field=field,
                            severity="warning",
                            code="unknown_action",
                            message=(
                                "unrecognized action preserved; "
                                "do not automate response from this value"
                            ),
                        )
                    )

            else:

                raise ValueError(
                    "unsupported field"
                )

        # ----------------------------------------------
        # 4. 필드 검증 실패
        # ----------------------------------------------

        except ValueError as exc:

            issues.append(
                ValidationIssue(
                    field=field,
                    severity="error",
                    code="invalid_value",
                    message=str(exc),
                )
            )

            continue

        # ----------------------------------------------
        # 5. 정상 필드 저장
        # ----------------------------------------------

        result[field] = normalized

    # --------------------------------------------------
    # 6. 검증 결과 반환
    # --------------------------------------------------

    return ValidationResult(
        fields=result,
        issues=tuple(issues)
    )