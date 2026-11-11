"""
IX SOAR - JSON Parser

역할:
    JSON 형식 로그에서 원본 필드를 추출한다.

지원 기능:
    - JSON Object
    - JSON Array
    - Nested JSON
    - UTF-8 검증
    - 중복 Key 검증
    - 입력 크기 제한
    - 로그 레코드 수 제한

주의:
    필드명 변경 및 데이터 정규화는 수행하지 않는다.
"""

from __future__ import annotations

import json

from dataclasses import dataclass
from typing import Any


# --------------------------------------------------
# 1. JSON 파싱 오류
# --------------------------------------------------

class JSONParseError(ValueError):

    """JSON 파싱 과정에서 발생하는 오류"""


# --------------------------------------------------
# 2. JSON 파싱 결과
# --------------------------------------------------

@dataclass(frozen=True)
class JSONRecord:

    index: int
    fields: dict[str, Any]


# --------------------------------------------------
# 3. 중복 Key 검사
# --------------------------------------------------

def _unique_pairs(
    pairs: list[tuple[str, Any]]
) -> dict[str, Any]:

    result = {}

    for key, value in pairs:

        if key in result:

            raise JSONParseError(
                f"duplicate JSON key: {key}"
            )

        result[key] = value

    return result


# --------------------------------------------------
# 4. 비표준 JSON 값 검사
# --------------------------------------------------

def _reject_constant(value: str) -> None:

    raise JSONParseError(
        f"nonstandard JSON value: {value}"
    )


# --------------------------------------------------
# 5. JSON Parser
# --------------------------------------------------

def parse_json(
    raw: bytes | str,
    *,
    max_bytes: int = 1_048_576,
    max_records: int = 1_000
) -> list[JSONRecord]:

    """
    JSON 로그를 파싱하여 레코드 목록을 반환한다.

    Args:
        raw:
            Collector가 전달한 원본 로그

        max_bytes:
            단일 메시지 최대 크기

        max_records:
            JSON 배열에 포함할 수 있는 최대 레코드 수

    Returns:
        list[JSONRecord]
    """

    # 1. 제한값 검사
    if max_bytes <= 0 or max_records <= 0:

        raise ValueError(
            "max_bytes and max_records must be positive"
        )

    # 2. 입력 타입 검사
    if not isinstance(raw, (bytes, str)):

        raise TypeError(
            "raw must be bytes or str"
        )

    # 3. UTF-8 디코딩 및 크기 검사
    try:

        if isinstance(raw, bytes):

            if len(raw) > max_bytes:

                raise JSONParseError(
                    "JSON message exceeds max_bytes"
                )

            text = raw.decode("utf-8-sig")

        else:

            if len(raw.encode("utf-8")) > max_bytes:

                raise JSONParseError(
                    "JSON message exceeds max_bytes"
                )

            text = raw

    except (UnicodeDecodeError, UnicodeEncodeError) as exc:

        raise JSONParseError(
            "JSON message must be valid UTF-8"
        ) from exc

    # 4. 공백 및 BOM 제거
    text = text.strip().lstrip("\ufeff").strip()

    if not text:

        raise JSONParseError(
            "empty JSON message"
        )

    # 5. JSON 파싱
    try:

        parsed = json.loads(
            text,
            object_pairs_hook=_unique_pairs,
            parse_constant=_reject_constant
        )

    except json.JSONDecodeError as exc:

        raise JSONParseError(
            f"invalid JSON at character {exc.pos}"
        ) from exc

    # 6. JSON Object 처리
    if isinstance(parsed, dict):

        rows = [parsed]

    # 7. JSON Array 처리
    elif isinstance(parsed, list):

        rows = parsed

    else:

        raise JSONParseError(
            "top-level JSON must be an object or array"
        )

    # 8. 빈 배열 검사
    if not rows:

        raise JSONParseError(
            "empty JSON array: no log records"
        )

    # 9. 최대 레코드 수 검사
    if len(rows) > max_records:

        raise JSONParseError(
            "JSON array exceeds max_records"
        )

    # 10. 개별 레코드 타입 검사
    if any(
        not isinstance(item, dict)
        for item in rows
    ):

        raise JSONParseError(
            "every JSON log record must be an object"
        )

    # 11. 파싱 결과 반환
    return [
        JSONRecord(
            index=i,
            fields=item
        )
        for i, item in enumerate(rows)
    ]