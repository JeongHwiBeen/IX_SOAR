"""
IX SOAR - Field Mapper

역할:
    장비별 매핑 프로파일을 이용해
    Parser가 추출한 필드를 IX SOAR 표준 필드로 변환한다.

지원:
    - JSON / KV: 필드 경로 기반 매핑
    - Delimiter: 필드 위치 기반 매핑
    - Syslog: 헤더 기반 매핑

주의:
    - 원본 필드는 변경하지 않는다.
    - 타입 변환과 값 검증은 수행하지 않는다.
    - 로그 ID 및 Kafka 메타데이터는 매핑하지 않는다.
"""

from __future__ import annotations

import json
import re

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping


# --------------------------------------------------
# 1. 매핑 오류
# --------------------------------------------------

class MappingError(ValueError):
    """잘못된 매핑 설정 또는 매핑할 수 없는 입력"""


# --------------------------------------------------
# 2. 매핑 가능한 표준 필드
# --------------------------------------------------

ALLOWED_TARGETS = frozenset({
    "device_id",
    "event_time",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "protocol",
    "action",
})


# --------------------------------------------------
# 3. 사용 가능한 Syslog 헤더
# --------------------------------------------------

SYSLOG_HEADERS = frozenset({
    "standard",
    "priority",
    "facility",
    "severity",
    "timestamp_text",
    "event_time",
    "hostname",
    "app_name",
    "proc_id",
    "msg_id",
})


# --------------------------------------------------
# 4. 공통 설정
# --------------------------------------------------

_PROFILE_ID = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$"
)

_MISSING = object()


# --------------------------------------------------
# 5. 매핑 규칙
# --------------------------------------------------

@dataclass(frozen=True)
class MappingRule:

    target: str

    # path / index / syslog
    source_kind: str

    source: tuple[str | int, ...] | int | str

    required: bool = False


# --------------------------------------------------
# 6. 장비별 매핑 프로파일
# --------------------------------------------------

@dataclass(frozen=True)
class MappingProfile:

    profile_id: str
    version: int
    rules: tuple[MappingRule, ...]


# --------------------------------------------------
# 7. 필드 매핑 결과
# --------------------------------------------------

@dataclass(frozen=True)
class MappedRecord:

    fields: dict[str, Any]

    profile_id: str
    profile_version: int


# --------------------------------------------------
# 8. 프로파일 검증
# --------------------------------------------------

def parse_profile(
    config: Mapping[str, Any]
) -> MappingProfile:

    """
    JSON 기반 매핑 설정을 검증하고
    MappingProfile 객체로 변환한다.
    """

    # 프로파일 구조 확인
    if not isinstance(config, dict):

        raise MappingError(
            "profile must be a JSON object"
        )

    if set(config) != {
        "profile_id",
        "version",
        "rules"
    }:

        raise MappingError(
            "profile keys must be: "
            "profile_id, version, rules"
        )

    pid = config["profile_id"]
    version = config["version"]
    raw_rules = config["rules"]

    # 프로파일 ID 확인
    if (
        not isinstance(pid, str)
        or not _PROFILE_ID.fullmatch(pid)
    ):

        raise MappingError(
            "invalid profile_id"
        )

    # 버전 확인
    if type(version) is not int or version < 1:

        raise MappingError(
            "version must be a positive integer"
        )

    # 매핑 규칙 개수 확인
    if (
        not isinstance(raw_rules, list)
        or not 1 <= len(raw_rules) <= 128
    ):

        raise MappingError(
            "rules must contain 1..128 entries"
        )

    rules = []
    seen_targets = set()

    # --------------------------------------------------
    # 개별 매핑 규칙 확인
    # --------------------------------------------------

    for index, entry in enumerate(raw_rules):

        if not isinstance(entry, dict):

            raise MappingError(
                f"rule {index} must be an object"
            )

        # 매핑 출처 선택
        source_keys = [
            key
            for key in ("path", "index", "syslog")
            if key in entry
        ]

        if len(source_keys) != 1:

            raise MappingError(
                f"rule {index} requires "
                "exactly one source selector"
            )

        kind = source_keys[0]

        # 지원하지 않는 설정 방지
        if set(entry) - {
            "target",
            "required",
            kind
        }:

            raise MappingError(
                f"rule {index} contains unsupported keys"
            )

        target = entry.get("target")

        # 표준 필드 검사
        if (
            not isinstance(target, str)
            or target not in ALLOWED_TARGETS
        ):

            raise MappingError(
                f"rule {index}: unsupported target {target!r}"
            )

        # 동일한 표준 필드에 중복 매핑 방지
        if target in seen_targets:

            raise MappingError(
                f"duplicate target: {target}"
            )

        seen_targets.add(target)

        required = entry.get("required", False)

        if type(required) is not bool:

            raise MappingError(
                f"rule {index}: required must be boolean"
            )

        source = entry[kind]

        # --------------------------------------------------
        # A. 필드명 / JSON 경로 기반
        # --------------------------------------------------

        if kind == "path":

            if (
                not isinstance(source, list)
                or not 1 <= len(source) <= 16
            ):

                raise MappingError(
                    f"rule {index}: path must have 1..16 segments"
                )

            for segment in source:

                if not (
                    isinstance(segment, str) and bool(segment)
                    or type(segment) is int and segment >= 0
                ):

                    raise MappingError(
                        f"rule {index}: invalid path segment"
                    )

            source = tuple(source)

        # --------------------------------------------------
        # B. Delimiter 위치 기반
        # --------------------------------------------------

        elif kind == "index":

            if type(source) is not int or source < 0:

                raise MappingError(
                    f"rule {index}: "
                    "index must be nonnegative integer"
                )

        # --------------------------------------------------
        # C. Syslog 헤더 기반
        # --------------------------------------------------

        else:

            if (
                not isinstance(source, str)
                or source not in SYSLOG_HEADERS
            ):

                raise MappingError(
                    f"rule {index}: unsupported Syslog header"
                )

        rules.append(
            MappingRule(
                target=target,
                source_kind=kind,
                source=source,
                required=required
            )
        )

    return MappingProfile(
        profile_id=pid,
        version=version,
        rules=tuple(rules)
    )


# --------------------------------------------------
# 9. JSON 프로파일 로딩
# --------------------------------------------------

def load_profile(
    filename: str | Path
) -> MappingProfile:

    """
    장비별 JSON 매핑 설정을 읽는다.
    """

    try:

        data = json.loads(
            Path(filename).read_text(
                encoding="utf-8"
            )
        )

    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError
    ) as exc:

        raise MappingError(
            "unable to read mapping profile JSON"
        ) from exc

    return parse_profile(data)


# --------------------------------------------------
# 10. JSON / KV 필드 경로 탐색
# --------------------------------------------------

def _path_value(
    payload: Mapping[str, Any],
    path: tuple[str | int, ...]
) -> Any:

    """
    중첩된 필드 경로를 따라 값을 추출한다.

    예:
        path = ("source", "ip")

        payload = {
            "source": {
                "ip": "192.0.2.10"
            }
        }
    """

    value = payload

    for segment in path:

        # 딕셔너리 Key 탐색
        if (
            isinstance(segment, str)
            and isinstance(value, dict)
        ):

            if segment not in value:
                return _MISSING

            value = value[segment]

        # 리스트 Index 탐색
        elif (
            type(segment) is int
            and isinstance(value, (list, tuple))
        ):

            if segment >= len(value):
                return _MISSING

            value = value[segment]

        else:

            return _MISSING

    return value


# --------------------------------------------------
# 11. Field Mapper
# --------------------------------------------------

def map_fields(
    parsed: dict[str, Any] | tuple[str, ...] | list[str],
    profile: MappingProfile,
    *,
    syslog: Any = None
) -> MappedRecord:

    """
    Parser 결과를 표준 필드로 매핑한다.

    Args:
        parsed:
            JSON/KV Parser의 fields 또는
            Delimiter Parser의 values

        profile:
            장비별 MappingProfile

        syslog:
            Syslog Parser 결과 (선택)

    Returns:
        MappedRecord
    """

    # 1. 프로파일 확인
    if not isinstance(profile, MappingProfile):

        raise TypeError(
            "profile must be MappingProfile"
        )

    # 2. Parser 결과 타입 확인
    if not isinstance(parsed, (dict, tuple, list)):

        raise TypeError(
            "parsed must be dict, tuple, or list"
        )

    mapped = {}

    # --------------------------------------------------
    # 3. 매핑 규칙 순회
    # --------------------------------------------------

    for rule in profile.rules:

        value = _MISSING

        # ----------------------------------------------
        # A. JSON / KV 경로 기반 매핑
        # ----------------------------------------------

        if rule.source_kind == "path":

            if not isinstance(parsed, dict):

                raise MappingError(
                    "path source requires named parser fields"
                )

            value = _path_value(
                parsed,
                rule.source
            )

        # ----------------------------------------------
        # B. Delimiter 인덱스 기반 매핑
        # ----------------------------------------------

        elif rule.source_kind == "index":

            if not isinstance(parsed, (tuple, list)):

                raise MappingError(
                    "index source requires positional parser values"
                )

            if rule.source < len(parsed):

                value = parsed[rule.source]

        # ----------------------------------------------
        # C. Syslog 헤더 기반 매핑
        # ----------------------------------------------

        else:

            if syslog is not None:

                value = getattr(
                    syslog,
                    rule.source,
                    _MISSING
                )

        # ----------------------------------------------
        # 4. 필수 필드 검사
        # ----------------------------------------------

        if value is _MISSING or value is None:

            if rule.required:

                raise MappingError(
                    f"missing required value for {rule.target}"
                )

            continue

        # ----------------------------------------------
        # 5. 복합 데이터 매핑 방지
        # ----------------------------------------------

        if not isinstance(
            value,
            (str, int, float, bool, datetime)
        ):

            raise MappingError(
                f"non-scalar value for {rule.target}"
            )

        # ----------------------------------------------
        # 6. 표준 필드 저장
        # ----------------------------------------------

        mapped[rule.target] = value

    # --------------------------------------------------
    # 7. 결과 반환
    # --------------------------------------------------

    return MappedRecord(
        fields=mapped,
        profile_id=profile.profile_id,
        profile_version=profile.version
    )