import json
import tempfile
import unittest

from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from ix_normalizer.field_mapper import (
    MappingError,
    load_profile,
    map_fields,
    parse_profile
)


# --------------------------------------------------
# 테스트용 프로파일 생성
# --------------------------------------------------

def profile(*rules):

    return parse_profile({
        "profile_id": "fw-v1",
        "version": 1,
        "rules": list(rules)
    })


class MappingTests(unittest.TestCase):

    # 1. 일반 JSON 매핑
    def test_flat_json(self):

        p = profile(
            {
                "target": "src_ip",
                "path": ["src"],
                "required": True
            },
            {
                "target": "action",
                "path": ["act"]
            }
        )

        result = map_fields(
            {
                "src": "192.0.2.10",
                "act": "deny"
            },
            p
        )

        self.assertEqual(
            result.fields,
            {
                "src_ip": "192.0.2.10",
                "action": "deny"
            }
        )

        self.assertEqual(
            result.profile_id,
            "fw-v1"
        )

    # 2. 중첩 JSON 매핑
    def test_nested_json(self):

        p = profile({
            "target": "src_ip",
            "path": ["source", "ip"]
        })

        result = map_fields(
            {
                "source": {
                    "ip": "192.0.2.10"
                }
            },
            p
        )

        self.assertEqual(
            result.fields["src_ip"],
            "192.0.2.10"
        )

    # 3. JSON 배열 내부 탐색
    def test_array_index_in_path(self):

        p = profile({
            "target": "src_ip",
            "path": ["network", 0, "ip"]
        })

        result = map_fields(
            {
                "network": [
                    {"ip": "192.0.2.10"}
                ]
            },
            p
        )

        self.assertEqual(
            result.fields["src_ip"],
            "192.0.2.10"
        )

    # 4. 점이 포함된 실제 필드명
    def test_literal_dot_key(self):

        p = profile({
            "target": "src_ip",
            "path": ["src.ip"]
        })

        result = map_fields(
            {"src.ip": "192.0.2.10"},
            p
        )

        self.assertEqual(
            result.fields["src_ip"],
            "192.0.2.10"
        )

    # 5. KV 필드 매핑
    def test_kv_fields(self):

        p = profile(
            {
                "target": "src_ip",
                "path": ["src"]
            },
            {
                "target": "dst_port",
                "path": ["dport"]
            }
        )

        result = map_fields(
            {
                "src": "192.0.2.10",
                "dport": "443"
            },
            p
        )

        # 아직 숫자로 변환하지 않음
        self.assertEqual(
            result.fields["dst_port"],
            "443"
        )

    # 6. Delimiter 위치 기반 매핑
    def test_delimiter_values(self):

        p = profile(
            {
                "target": "src_ip",
                "index": 0
            },
            {
                "target": "dst_port",
                "index": 1
            }
        )

        result = map_fields(
            ("192.0.2.10", "443"),
            p
        )

        self.assertEqual(
            result.fields,
            {
                "src_ip": "192.0.2.10",
                "dst_port": "443"
            }
        )

    # 7. Syslog 헤더 매핑
    def test_header(self):

        p = profile(
            {
                "target": "device_id",
                "syslog": "hostname"
            },
            {
                "target": "event_time",
                "syslog": "event_time"
            }
        )

        event_time = datetime(
            2026, 11, 11,
            tzinfo=timezone.utc
        )

        syslog = SimpleNamespace(
            hostname="fw-01",
            event_time=event_time
        )

        result = map_fields(
            {},
            p,
            syslog=syslog
        )

        self.assertEqual(
            result.fields,
            {
                "device_id": "fw-01",
                "event_time": event_time
            }
        )

    # 8. 필수 필드 누락
    def test_required_missing(self):

        p = profile({
            "target": "src_ip",
            "path": ["src"],
            "required": True
        })

        with self.assertRaises(MappingError):

            map_fields({}, p)

    # 9. 선택 필드 누락
    def test_optional_missing(self):

        p = profile({
            "target": "src_ip",
            "path": ["src"]
        })

        self.assertEqual(
            map_fields({}, p).fields,
            {}
        )

    # 10. None 값 처리
    def test_none_missing(self):

        p = profile({
            "target": "event_time",
            "syslog": "event_time"
        })

        syslog = SimpleNamespace(
            event_time=None
        )

        self.assertEqual(
            map_fields(
                {},
                p,
                syslog=syslog
            ).fields,
            {}
        )

    # 11. 복합 객체 직접 매핑 방지
    def test_non_scalar_rejected(self):

        p = profile({
            "target": "src_ip",
            "path": ["source"]
        })

        with self.assertRaises(MappingError):

            map_fields(
                {
                    "source": {
                        "ip": "192.0.2.10"
                    }
                },
                p
            )

    # 12. 원본 필드 불변성
    def test_not_mutating_input(self):

        p = profile({
            "target": "src_ip",
            "path": ["src"]
        })

        original = {
            "src": "192.0.2.10",
            "other": {
                "name": "value"
            }
        }

        original_copy = json.loads(
            json.dumps(original)
        )

        map_fields(original, p)

        self.assertEqual(
            original,
            original_copy
        )

    # 13. 중복 Target 방지
    def test_duplicate_targets(self):

        with self.assertRaises(MappingError):

            profile(
                {
                    "target": "src_ip",
                    "path": ["src"]
                },
                {
                    "target": "src_ip",
                    "path": ["source_ip"]
                }
            )

    # 14. 허용되지 않은 Target
    def test_unknown_target(self):

        with self.assertRaises(MappingError):

            profile({
                "target": "log_id",
                "path": ["log_id"]
            })

    # 15. 빈 경로
    def test_invalid_empty_path(self):

        with self.assertRaises(MappingError):

            profile({
                "target": "src_ip",
                "path": []
            })

    # 16. 잘못된 배열 인덱스
    def test_invalid_boolean_path_index(self):

        with self.assertRaises(MappingError):

            profile({
                "target": "src_ip",
                "path": [True]
            })

    # 17. 잘못된 필수 여부 설정
    def test_invalid_required_type(self):

        with self.assertRaises(MappingError):

            profile({
                "target": "src_ip",
                "path": ["src"],
                "required": "true"
            })

    # 18. 잘못된 버전
    def test_invalid_version(self):

        with self.assertRaises(MappingError):

            parse_profile({
                "profile_id": "fw",
                "version": True,
                "rules": [
                    {
                        "target": "src_ip",
                        "path": ["src"]
                    }
                ]
            })

    # 19. 딕셔너리에 인덱스 매핑 시도
    def test_index_wrong_input_type(self):

        p = profile({
            "target": "src_ip",
            "index": 0
        })

        with self.assertRaises(MappingError):

            map_fields(
                {"src": "192.0.2.10"},
                p
            )

    # 20. 튜플에 경로 매핑 시도
    def test_path_wrong_input_type(self):

        p = profile({
            "target": "src_ip",
            "path": ["src"]
        })

        with self.assertRaises(MappingError):

            map_fields(
                ("192.0.2.10",),
                p
            )

    # 21. Syslog 선택 필드 누락
    def test_unavailable_syslog_optional(self):

        p = profile({
            "target": "device_id",
            "syslog": "hostname"
        })

        self.assertEqual(
            map_fields({}, p).fields,
            {}
        )

    # 22. Syslog 필수 필드 누락
    def test_unavailable_syslog_required(self):

        p = profile({
            "target": "device_id",
            "syslog": "hostname",
            "required": True
        })

        with self.assertRaises(MappingError):

            map_fields({}, p)

    # 23. 지원하지 않는 Syslog 헤더
    def test_unsupported_header(self):

        with self.assertRaises(MappingError):

            profile({
                "target": "device_id",
                "syslog": "__class__"
            })

    # 24. 출처가 두 개 지정된 규칙
    def test_more_than_one_source(self):

        with self.assertRaises(MappingError):

            profile({
                "target": "src_ip",
                "index": 0,
                "path": ["src"]
            })

    # 25. JSON 파일 프로파일 로딩
    def test_loader(self):

        config = {
            "profile_id": "fw",
            "version": 1,
            "rules": [
                {
                    "target": "src_ip",
                    "path": ["src"]
                }
            ]
        }

        with tempfile.TemporaryDirectory() as tmp:

            filename = Path(tmp) / "profile.json"

            filename.write_text(
                json.dumps(config),
                encoding="utf-8"
            )

            loaded = load_profile(filename)

            self.assertEqual(
                loaded.profile_id,
                "fw"
            )

    # 26. 잘못된 프로파일 속성
    def test_profile_malformed(self):

        with self.assertRaises(MappingError):

            profile({
                "target": "src_ip",
                "path": ["src"],
                "require": True
            })


if __name__ == "__main__":
    unittest.main()