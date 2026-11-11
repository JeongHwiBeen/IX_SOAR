import unittest

from datetime import datetime, timezone

from ix_normalizer.syslog_parser import (
    SyslogParseError,
    parse_syslog
)


class SyslogParserTests(unittest.TestCase):

    # 1. RFC5424 기본 로그
    def test_5424_kv(self):

        raw = (
            "<134>1 2026-11-11T20:30:00Z "
            "fw-01 FW - - - "
            "src=192.0.2.10 action=deny"
        )

        result = parse_syslog(raw)

        self.assertEqual(
            result.standard,
            "rfc5424"
        )

        self.assertEqual(
            result.facility,
            16
        )

        self.assertEqual(
            result.severity,
            6
        )

        self.assertEqual(
            result.hostname,
            "fw-01"
        )

        self.assertEqual(
            result.message,
            "src=192.0.2.10 action=deny"
        )

        self.assertEqual(
            result.event_time,
            datetime(
                2026, 11, 11,
                20, 30,
                tzinfo=timezone.utc
            )
        )

        self.assertIsNone(
            result.proc_id
        )

    # 2. RFC5424 Structured Data
    def test_5424_structured_data(self):

        raw = (
            '<165>1 2003-08-24T05:14:15.000003-07:00 '
            'fw app 123 ID47 '
            '[example@32473 who="user\\]name" '
            'a="hello\\"world"][meta id="1"] '
            '{"act":"deny"}'
        )

        result = parse_syslog(raw)

        self.assertEqual(
            result.standard,
            "rfc5424"
        )

        self.assertEqual(
            result.structured_data,
            '[example@32473 who="user\\]name" '
            'a="hello\\"world"][meta id="1"]'
        )

        self.assertEqual(
            result.message,
            '{"act":"deny"}'
        )

        self.assertEqual(
            result.event_time,
            datetime(
                2003, 8, 24,
                12, 14, 15, 3,
                tzinfo=timezone.utc
            )
        )

    # 3. RFC5424 메시지가 없는 경우
    def test_5424_no_message(self):

        result = parse_syslog(
            "<34>1 - - - - - -"
        )

        self.assertEqual(
            result.message,
            ""
        )

    # 4. Structured Data가 없는 경우
    def test_5424_no_sd(self):

        result = parse_syslog(
            "<34>1 - - - - - - msg"
        )

        self.assertIsNone(
            result.structured_data
        )

        self.assertIsNone(
            result.event_time
        )

    # 5. Structured Data만 존재
    def test_5424_sd_no_message(self):

        result = parse_syslog(
            "<34>1 - host app - - [a]"
        )

        self.assertEqual(
            result.message,
            ""
        )

    # 6. UTF-8 BOM
    def test_5424_with_bom(self):

        raw = (
            b"<34>1 - host app - - - "
            b"\xef\xbb\xbfhello"
        )

        result = parse_syslog(raw)

        self.assertEqual(
            result.message,
            "hello"
        )

    # 7. RFC3164 기본
    def test_3164(self):

        raw = (
            "<34>Nov 11 20:30:00 "
            "fw-01 sshd[123]: Failed password"
        )

        result = parse_syslog(raw)

        self.assertEqual(
            (
                result.priority,
                result.facility,
                result.severity
            ),
            (34, 4, 2)
        )

        self.assertEqual(
            (
                result.app_name,
                result.proc_id
            ),
            ("sshd", "123")
        )

        self.assertEqual(
            result.timestamp_text,
            "Nov 11 20:30:00"
        )

        self.assertIsNone(
            result.event_time
        )

        self.assertEqual(
            result.message,
            "Failed password"
        )

    # 8. PRI 없는 RFC3164
    def test_3164_no_priority(self):

        raw = (
            "Nov  7 01:02:03 "
            "fw app: action=deny"
        )

        result = parse_syslog(raw)

        self.assertEqual(
            result.timestamp_text,
            "Nov  7 01:02:03"
        )

        self.assertIsNone(
            result.priority
        )

        self.assertEqual(
            result.message,
            "action=deny"
        )

    # 9. TAG 없는 RFC3164
    def test_3164_no_tag(self):

        raw = (
            "Nov 11 20:30:00 "
            "fw src=1 action=deny"
        )

        result = parse_syslog(raw)

        self.assertIsNone(
            result.app_name
        )

        self.assertEqual(
            result.message,
            "src=1 action=deny"
        )

    # 10. 연도 없는 2월 29일
    def test_feb29_allowed_without_year(self):

        result = parse_syslog(
            "Feb 29 12:30:00 fw app: hi"
        )

        self.assertEqual(
            result.standard,
            "rfc3164"
        )

    # 11. 잘못된 Priority
    def test_invalid_priority(self):

        with self.assertRaises(SyslogParseError):

            parse_syslog(
                "<999>Nov 11 20:30:00 fw test"
            )

    # 12. 잘못된 RFC5424 날짜
    def test_invalid_date(self):

        with self.assertRaises(SyslogParseError):

            parse_syslog(
                "<34>1 2026-02-30T12:00:00Z "
                "fw app - - - hello"
            )

    # 13. 잘못된 RFC3164 시간
    def test_invalid_clock(self):

        with self.assertRaises(SyslogParseError):

            parse_syslog(
                "Nov 11 25:30:00 fw app: hi"
            )

    # 14. RFC5424 헤더 누락
    def test_missing_fields(self):

        with self.assertRaises(SyslogParseError):

            parse_syslog(
                "<34>1 - fw app - -"
            )

    # 15. 닫히지 않은 Structured Data
    def test_unterminated_sd(self):

        with self.assertRaises(SyslogParseError):

            parse_syslog(
                '<34>1 - fw app - - [x p="v"'
            )

    # 16. 잘못된 Structured Data 대괄호
    def test_unescaped_bracket_sd(self):

        with self.assertRaises(SyslogParseError):

            parse_syslog(
                '<34>1 - fw app - - '
                '[x p="v]bad"] hi'
            )

    # 17. 중복 Structured Data Parameter
    def test_duplicate_sd_param(self):

        with self.assertRaises(SyslogParseError):

            parse_syslog(
                '<34>1 - fw app - - '
                '[x p="1" p="2"] hi'
            )

    # 18. 지원하지 않는 RFC5424 버전
    def test_wrong_version(self):

        with self.assertRaises(SyslogParseError):

            parse_syslog(
                "<34>2 - fw app - - - hello"
            )

    # 19. 잘못된 UTF-8
    def test_invalid_utf8(self):

        with self.assertRaises(SyslogParseError):

            parse_syslog(
                b"\xff"
            )

    # 20. 메시지 크기 초과
    def test_max_bytes(self):

        with self.assertRaises(SyslogParseError):

            parse_syslog(
                "<34>1 - fw app - - - hi",
                max_bytes=4
            )

    # 21. 잘못된 입력 타입
    def test_non_string(self):

        with self.assertRaises(TypeError):

            parse_syslog(123)

    # 22. KV 본문 보존
    def test_kv_body_preserved(self):

        raw = (
            "<134>1 2026-11-11T20:30:00Z "
            "fw-01 FW - - - "
            "src=192.0.2.10 action=deny"
        )

        result = parse_syslog(raw)

        self.assertEqual(
            result.message.split()[0],
            "src=192.0.2.10"
        )


if __name__ == "__main__":
    unittest.main()