import unittest

from ix_normalizer.format_detector import (
    LogFormat,
    detect_format
)


class FormatDetectorTests(unittest.TestCase):

    # 1. JSON 객체
    def test_json_object(self):

        raw = b'{"src_ip":"192.0.2.10","action":"deny"}'

        result = detect_format(raw)

        self.assertEqual(
            result.format,
            LogFormat.JSON
        )

    # 2. JSON 배열
    def test_json_array(self):

        raw = '[{"id":1}]'

        result = detect_format(raw)

        self.assertEqual(
            result.format,
            LogFormat.JSON
        )

    # 3. 잘못된 JSON
    def test_invalid_json(self):

        raw = '{"src_ip":}'

        result = detect_format(raw)

        self.assertEqual(
            result.format,
            LogFormat.UNKNOWN
        )

    # 4. Key-Value
    def test_key_value(self):

        raw = "src=192.0.2.10 action=deny"

        result = detect_format(raw)

        self.assertEqual(
            result.format,
            LogFormat.KEY_VALUE
        )

    # 5. 따옴표가 포함된 Key-Value
    def test_key_value_quoted(self):

        raw = 'msg="login failed" action=deny'

        result = detect_format(raw)

        self.assertEqual(
            result.format,
            LogFormat.KEY_VALUE
        )

    # 6. RFC5424 Syslog
    def test_syslog_rfc5424_with_kv_body(self):

        raw = (
            "<134>1 2026-11-11T20:30:00Z "
            "fw-01 FW - - - "
            "src=192.0.2.10 action=deny"
        )

        result = detect_format(raw)

        self.assertEqual(
            result.format,
            LogFormat.SYSLOG
        )

    # 7. RFC3164 Syslog
    def test_syslog_rfc3164(self):

        raw = "<34>Nov 11 20:30:00 fw-01 app: test"

        result = detect_format(raw)

        self.assertEqual(
            result.format,
            LogFormat.SYSLOG
        )

    # 8. PRI 없는 Syslog
    def test_syslog_without_priority(self):

        raw = "Nov 11 20:30:00 fw-01 app: test"

        result = detect_format(raw)

        self.assertEqual(
            result.format,
            LogFormat.SYSLOG
        )

    # 9. 알 수 없는 형식
    def test_unknown(self):

        raw = "login failed"

        result = detect_format(raw)

        self.assertEqual(
            result.format,
            LogFormat.UNKNOWN
        )

    # 10. 빈 로그
    def test_empty(self):

        result = detect_format(b"  \n")

        self.assertEqual(
            result.reason,
            "empty_log"
        )

    # 11. UTF-8 디코딩 실패
    def test_non_utf8(self):

        result = detect_format(b"\xff\xfe")

        self.assertEqual(
            result.reason,
            "invalid_utf8"
        )

    # 12. 잘못된 Syslog Priority
    def test_invalid_syslog_priority(self):

        result = detect_format("<999>bad log")

        self.assertEqual(
            result.format,
            LogFormat.UNKNOWN
        )

    # 13. 설정되지 않은 Delimiter는 추정하지 않음
    def test_delimiter_without_profile(self):

        result = detect_format(
            "a|b|c"
        )

        self.assertEqual(
            result.format,
            LogFormat.UNKNOWN
        )

    # 14. 설정된 파이프 구분자
    def test_delimiter_pipe(self):

        result = detect_format(
            "a|b|c",
            delimiter="|",
            expected_fields=3
        )

        self.assertEqual(
            result.format,
            LogFormat.DELIMITED
        )

    # 15. 여러 글자 구분자
    def test_delimiter_multi_character(self):

        result = detect_format(
            "a||b||c",
            delimiter="||",
            expected_fields=3
        )

        self.assertEqual(
            result.format,
            LogFormat.DELIMITED
        )

    # 16. 필드 개수 불일치
    def test_delimiter_invalid_fields(self):

        result = detect_format(
            "a|b|c",
            delimiter="|",
            expected_fields=4
        )

        self.assertEqual(
            result.reason,
            "invalid_delimited"
        )

    # 17. 기존 KV 판별 유지
    def test_delimiter_kv_priority(self):

        result = detect_format(
            "src=1|dst=2",
            delimiter="|"
        )

        self.assertEqual(
            result.format,
            LogFormat.KEY_VALUE
        )

    # 18. 잘못된 Delimiter 설정
    def test_delimiter_missing_config(self):

        with self.assertRaises(ValueError):

            detect_format(
                "a|b",
                expected_fields=2
            )


if __name__ == "__main__":
    unittest.main()