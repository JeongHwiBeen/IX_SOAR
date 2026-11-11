"""
IX SOAR — Key-Value Parser

역할:
    Key-Value 형식의 로그를 파싱한다.

지원 기능:
    - key=value 구조
    - 사용자 지정 필드 구분자
    - 큰따옴표 / 작은따옴표
    - 이스케이프 문자
    - 중복 Key 검사
    - 메시지 크기 제한
    - 필드 개수 제한

주의:
    필드명 정규화 및 데이터 타입 변환은 수행하지 않는다.
"""

from __future__ import annotations

import string

from dataclasses import dataclass


# --------------------------------------------------
# 1. 파싱 오류
# --------------------------------------------------

class KVParseError(ValueError):
    """잘못된 Key-Value 로그"""


# --------------------------------------------------
# 2. 파싱 결과
# --------------------------------------------------

@dataclass(frozen=True)
class KVRecord:

    index: int
    fields: dict[str, str]


# --------------------------------------------------
# 3. Key 유효성 검사
# --------------------------------------------------

_KEY_START = frozenset(
    string.ascii_letters + "_"
)

_KEY_CONT = frozenset(
    string.ascii_letters + string.digits + "_.-"
)


def _valid_key(key: str) -> bool:

    return (
        bool(key)
        and key[0] in _KEY_START
        and all(char in _KEY_CONT for char in key[1:])
    )


# --------------------------------------------------
# 4. Key-Value Parser
# --------------------------------------------------

def parse_kv(
    raw: bytes | str,
    *,
    field_separators: str = " \t\r\n",
    assignment: str = "=",
    max_bytes: int = 1_048_576,
    max_fields: int = 256,
) -> list[KVRecord]:

    """
    Key-Value 로그를 파싱한다.

    Args:
        raw:
            원본 로그

        field_separators:
            필드 사이를 구분하는 문자들의 집합

        assignment:
            Key와 Value를 구분하는 문자

        max_bytes:
            최대 메시지 크기

        max_fields:
            최대 필드 개수

    Returns:
        list[KVRecord]
    """

    # 1. 제한값 검사
    if max_bytes <= 0 or max_fields <= 0:
        raise ValueError(
            "max_bytes and max_fields must be positive"
        )

    # 2. 구분자 설정 검사
    if (
        len(assignment) != 1
        or not field_separators
        or assignment in field_separators
        or '"' in field_separators
        or "'" in field_separators
        or "\\" in field_separators
    ):
        raise ValueError(
            "invalid assignment or field_separators"
        )

    # 3. 입력 타입 검사
    if not isinstance(raw, (bytes, str)):
        raise TypeError(
            "raw must be bytes or str"
        )

    # 4. UTF-8 및 메시지 크기 검사
    try:

        if isinstance(raw, bytes):

            if len(raw) > max_bytes:
                raise KVParseError(
                    "message exceeds max_bytes"
                )

            text = raw.decode("utf-8-sig")

        else:

            if len(raw.encode("utf-8")) > max_bytes:
                raise KVParseError(
                    "message exceeds max_bytes"
                )

            text = raw.lstrip("\ufeff")

    except (UnicodeEncodeError, UnicodeDecodeError) as exc:
        raise KVParseError(
            "message must be valid UTF-8"
        ) from exc

    if "\x00" in text:
        raise KVParseError(
            "NUL byte is not allowed"
        )

    # 5. 파싱 준비
    separators = frozenset(field_separators)

    fields: dict[str, str] = {}

    i = 0
    size = len(text)

    # 6. 문자열 순차 탐색
    while i < size:

        # 필드 사이 구분자 건너뛰기
        while i < size and text[i] in separators:
            i += 1

        if i == size:
            break

        # 7. Key 추출
        start = i

        while (
            i < size
            and text[i] not in separators
            and text[i] != assignment
        ):
            i += 1

        key = text[start:i]

        # '=' 앞에 있는 공백 허용
        while (
            i < size
            and text[i] in " \t"
            and text[i] in separators
        ):
            i += 1

        # 8. Key 검증
        if (
            not _valid_key(key)
            or i == size
            or text[i] != assignment
        ):
            raise KVParseError(
                f"invalid key or missing assignment near {start}"
            )

        if key in fields:
            raise KVParseError(
                f"duplicate key: {key}"
            )

        # '=' 다음으로 이동
        i += 1

        value_parts: list[str] = []

        # 9. 따옴표로 감싼 Value
        if i < size and text[i] in ('"', "'"):

            quote = text[i]
            i += 1

            while i < size:

                char = text[i]

                # 이스케이프 처리
                if char == "\\" and i + 1 < size:

                    nxt = text[i + 1]

                    if (
                        nxt in (quote, "\\")
                        or nxt in separators
                    ):
                        value_parts.append(nxt)
                        i += 2
                        continue

                # 닫는 따옴표
                if char == quote:
                    i += 1
                    break

                value_parts.append(char)
                i += 1

            else:
                raise KVParseError(
                    f"unterminated quoted value for key: {key}"
                )

            # 따옴표 뒤에는 필드 구분자만 허용
            if (
                i < size
                and text[i] not in separators
            ):
                raise KVParseError(
                    f"unexpected character after quoted value: {key}"
                )

        # 10. 일반 Value
        else:

            while (
                i < size
                and text[i] not in separators
            ):

                char = text[i]

                # 이스케이프된 구분자 처리
                if char == "\\" and i + 1 < size:

                    nxt = text[i + 1]

                    if (
                        nxt in separators
                        or nxt == "\\"
                    ):
                        value_parts.append(nxt)
                        i += 2
                        continue

                value_parts.append(char)
                i += 1

        # 11. 필드 저장
        fields[key] = "".join(value_parts)

        if len(fields) > max_fields:
            raise KVParseError(
                "message exceeds max_fields"
            )

    # 12. 빈 로그 검사
    if not fields:
        raise KVParseError(
            "empty Key-Value message"
        )

    # 13. 결과 반환
    return [
        KVRecord(
            index=0,
            fields=fields
        )
    ]