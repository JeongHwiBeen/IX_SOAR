"""
IX SOAR - Delimiter Parser

역할:
    구분자로 나열된 로그 필드를 위치별로 추출한다.

지원 기능:
    - 쉼표, 파이프, 세미콜론, 탭 구분자
    - 여러 문자로 구성된 구분자
    - 따옴표 내부의 구분자 보호
    - CSV 방식의 이중 따옴표 처리
    - 빈 필드 및 필드 순서 보존
    - 필드 개수 및 크기 제한

주의:
    - Kafka 메시지 하나에 로그 레코드 하나가 있다고 가정한다.
    - 필드명 매핑과 데이터 타입 변환은 수행하지 않는다.
"""

from __future__ import annotations

from dataclasses import dataclass


# --------------------------------------------------
# 1. Delimiter 파싱 오류
# --------------------------------------------------

class DelimiterParseError(ValueError):
    """잘못된 구분자 기반 로그"""


# --------------------------------------------------
# 2. 파싱 결과
# --------------------------------------------------

@dataclass(frozen=True)
class DelimiterRecord:

    index: int
    values: tuple[str, ...]


# --------------------------------------------------
# 3. Delimiter Parser
# --------------------------------------------------

def parse_delimited(
    raw: bytes | str,
    *,
    delimiter: str = ",",
    quote_char: str | None = '"',
    expected_fields: int | None = None,
    max_bytes: int = 1_048_576,
    max_fields: int = 256,
    max_field_chars: int = 65_536,
) -> list[DelimiterRecord]:

    """
    하나의 구분자 기반 로그를 파싱한다.

    Args:
        raw:
            원본 로그

        delimiter:
            필드 구분자

        quote_char:
            필드를 감싸는 따옴표 문자
            None이면 따옴표 처리를 사용하지 않는다.

        expected_fields:
            예상 필드 개수
            None이면 개수를 강제하지 않는다.

        max_bytes:
            최대 메시지 크기

        max_fields:
            최대 필드 개수

        max_field_chars:
            개별 필드의 최대 문자 수

    Returns:
        list[DelimiterRecord]
    """

    # 1. 구분자 검증
    if (
        not delimiter
        or len(delimiter) > 16
        or "\r" in delimiter
        or "\n" in delimiter
    ):
        raise ValueError(
            "delimiter must be 1..16 chars and contain no newline"
        )

    # 2. 따옴표 설정 검증
    if quote_char is not None:

        if (
            len(quote_char) != 1
            or quote_char in delimiter
            or quote_char in "\r\n"
        ):
            raise ValueError(
                "invalid quote_char"
            )

    # 3. 제한값 검증
    if (
        max_bytes <= 0
        or max_fields <= 0
        or max_field_chars <= 0
    ):
        raise ValueError(
            "limits must be positive"
        )

    if expected_fields is not None:

        if not 1 <= expected_fields <= max_fields:
            raise ValueError(
                "expected_fields must be between 1 and max_fields"
            )

    # 4. 입력 타입 검증
    if not isinstance(raw, (bytes, str)):
        raise TypeError(
            "raw must be bytes or str"
        )

    # 5. 메시지 크기 및 UTF-8 검증
    try:

        if isinstance(raw, bytes):

            if len(raw) > max_bytes:
                raise DelimiterParseError(
                    "message exceeds max_bytes"
                )

            text = raw.decode("utf-8-sig")

        else:

            if len(raw.encode("utf-8")) > max_bytes:
                raise DelimiterParseError(
                    "message exceeds max_bytes"
                )

            text = raw.removeprefix("\ufeff")

    except (
        UnicodeEncodeError,
        UnicodeDecodeError
    ) as exc:

        raise DelimiterParseError(
            "message must be valid UTF-8"
        ) from exc

    if not text:
        raise DelimiterParseError(
            "empty delimited message"
        )

    # 6. 파싱 상태 초기화
    fields: list[str] = []
    chars: list[str] = []

    state = "start"

    i = 0
    size = len(text)

    # --------------------------------------------------
    # 7. 개별 문자 추가
    # --------------------------------------------------

    def add_char(char: str) -> None:

        if len(chars) >= max_field_chars:
            raise DelimiterParseError(
                "field exceeds max_field_chars"
            )

        chars.append(char)

    # --------------------------------------------------
    # 8. 필드 하나 저장
    # --------------------------------------------------

    def finish_field() -> None:

        if len(fields) >= max_fields:
            raise DelimiterParseError(
                "message exceeds max_fields"
            )

        fields.append(
            "".join(chars)
        )

        chars.clear()

    # --------------------------------------------------
    # 9. 상태 기반 파싱
    # --------------------------------------------------

    while i < size:

        # 따옴표 밖에서는 구분자를 검사한다.
        if (
            state in (
                "start",
                "unquoted",
                "after_quote"
            )
            and text.startswith(delimiter, i)
        ):

            finish_field()

            state = "start"

            i += len(delimiter)

            continue

        char = text[i]

        # ----------------------------------------------
        # 상태 A: 필드 시작
        # ----------------------------------------------

        if state == "start":

            if (
                quote_char is not None
                and char == quote_char
            ):

                state = "quoted"

            elif char in "\r\n":

                raise DelimiterParseError(
                    "unquoted newline is not supported"
                )

            else:

                add_char(char)

                state = "unquoted"

            i += 1

        # ----------------------------------------------
        # 상태 B: 따옴표 없는 일반 필드
        # ----------------------------------------------

        elif state == "unquoted":

            if (
                quote_char is not None
                and char == quote_char
            ):

                raise DelimiterParseError(
                    f"unexpected quote at character {i}"
                )

            if char in "\r\n":

                raise DelimiterParseError(
                    "unquoted newline is not supported"
                )

            add_char(char)

            i += 1

        # ----------------------------------------------
        # 상태 C: 따옴표로 감싼 필드
        # ----------------------------------------------

        elif state == "quoted":

            if char == quote_char:

                # 연속된 따옴표는 실제 따옴표 하나를 의미
                if (
                    i + 1 < size
                    and text[i + 1] == quote_char
                ):

                    add_char(quote_char)

                    i += 2

                else:

                    state = "after_quote"

                    i += 1

            else:

                add_char(char)

                i += 1

        # ----------------------------------------------
        # 상태 D: 닫는 따옴표 이후
        # ----------------------------------------------

        elif state == "after_quote":

            raise DelimiterParseError(
                f"unexpected character after closing quote at {i}"
            )

    # --------------------------------------------------
    # 10. 마지막 상태 검증
    # --------------------------------------------------

    if state == "quoted":

        raise DelimiterParseError(
            "unterminated quoted field"
        )

    # 마지막 필드 저장
    finish_field()

    # --------------------------------------------------
    # 11. 필드 개수 검증
    # --------------------------------------------------

    if (
        expected_fields is not None
        and len(fields) != expected_fields
    ):

        raise DelimiterParseError(
            f"expected {expected_fields} fields "
            f"but parsed {len(fields)}"
        )

    # --------------------------------------------------
    # 12. 결과 반환
    # --------------------------------------------------

    return [
        DelimiterRecord(
            index=0,
            values=tuple(fields)
        )
    ]