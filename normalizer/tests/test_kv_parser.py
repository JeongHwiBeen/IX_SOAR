import unittest

from ix_normalizer.kv_parser import (
    KVParseError,
    parse_kv
)


class KVParserTests(unittest.TestCase):

    # 1. 기본 Key-Value
    def test_simple(self):

        records = parse_kv(
            b"src=192.0.2.10 action=deny"
        )

        self.assertEqual(records[0].index, 0)

        self.assertEqual(
            records[0].fields,
            {
                "src": "192.0.2.10",
                "action": "deny"
            }
        )

    # 2. 공백이 있는 문자열
    def test_quoted_spaces(self):

        raw = 'msg="login failed from user" action=deny'

        records = parse_kv(raw)

        self.assertEqual(
            records[0].fields["msg"],
            "login failed from user"
        )

    # 3. 작은따옴표
    def test_single_quotes(self):

        raw = "msg='login failed' action=deny"

        records = parse_kv(raw)

        self.assertEqual(
            records[0].fields["msg"],
            "login failed"
        )

    # 4. 세미콜론 구분자
    def test_semicolon(self):

        raw = "src=1;dst=2;action=deny"

        records = parse_kv(
            raw,
            field_separators=";"
        )

        self.assertEqual(
            records[0].fields["dst"],
            "2"
        )

    # 5. 파이프 구분자
    def test_pipe(self):

        raw = "src=1|dst=2"

        records = parse_kv(
            raw,
            field_separators="|"
        )

        self.assertEqual(
            records[0].fields["dst"],
            "2"
        )

    # 6. 따옴표 안의 구분자
    def test_quoted_separator(self):

        raw = 'msg="failed; retry";action=deny'

        records = parse_kv(
            raw,
            field_separators=";"
        )

        self.assertEqual(
            records[0].fields["msg"],
            "failed; retry"
        )

    # 7. 이스케이프된 따옴표
    def test_escaped_quote(self):

        raw = r'msg="user said \"hello\"" action=deny'

        records = parse_kv(raw)

        self.assertEqual(
            records[0].fields["msg"],
            'user said "hello"'
        )

    # 8. 이스케이프된 공백
    def test_escaped_space(self):

        raw = r"msg=login\ failed action=deny"

        records = parse_kv(raw)

        self.assertEqual(
            records[0].fields["msg"],
            "login failed"
        )

    # 9. Value에 포함된 '='
    def test_equals_in_value(self):

        raw = (
            "url=https://example.test/?x=1&y=2 "
            "action=deny"
        )

        records = parse_kv(raw)

        self.assertEqual(
            records[0].fields["url"],
            "https://example.test/?x=1&y=2"
        )

    # 10. UTF-8 BOM
    def test_utf8_bom(self):

        records = parse_kv(
            b'\xef\xbb\xbfaction=deny'
        )

        self.assertEqual(
            records[0].fields["action"],
            "deny"
        )

    # 11. 빈 Value
    def test_empty_value(self):

        records = parse_kv(
            "msg= action=deny"
        )

        self.assertEqual(
            records[0].fields["msg"],
            ""
        )

    # 12. 중복 Key
    def test_duplicate_key(self):

        with self.assertRaises(KVParseError):

            parse_kv(
                "src=1 src=2"
            )

    # 13. '=' 누락
    def test_missing_equals(self):

        with self.assertRaises(KVParseError):

            parse_kv(
                "src=1 broken"
            )

    # 14. 닫히지 않은 따옴표
    def test_unterminated_quote(self):

        with self.assertRaises(KVParseError):

            parse_kv(
                'msg="not closed'
            )

    # 15. 따옴표 뒤의 잘못된 문자
    def test_quote_trailing(self):

        with self.assertRaises(KVParseError):

            parse_kv(
                'msg="ok"extra'
            )

    # 16. 잘못된 UTF-8
    def test_invalid_utf8(self):

        with self.assertRaises(KVParseError):

            parse_kv(
                b"\xff\xfe"
            )

    # 17. 메시지 크기 초과
    def test_max_bytes(self):

        with self.assertRaises(KVParseError):

            parse_kv(
                "src=192.0.2.10",
                max_bytes=5
            )

    # 18. 필드 개수 초과
    def test_max_fields(self):

        with self.assertRaises(KVParseError):

            parse_kv(
                "a=1 b=2",
                max_fields=1
            )

    # 19. 빈 로그
    def test_empty_log(self):

        with self.assertRaises(KVParseError):

            parse_kv(
                " \t "
            )

    # 20. 잘못된 Key
    def test_invalid_key(self):

        with self.assertRaises(KVParseError):

            parse_kv(
                "1src=192.0.2.10"
            )

    # 21. Windows 경로의 역슬래시 보존
    def test_windows_path_preserved(self):

        raw = r"path=C:\Windows\System32 action=deny"

        records = parse_kv(raw)

        self.assertEqual(
            records[0].fields["path"],
            r"C:\Windows\System32"
        )

    # 22. 잘못된 입력 타입
    def test_non_string_input(self):

        with self.assertRaises(TypeError):

            parse_kv(123)


if __name__ == "__main__":
    unittest.main()