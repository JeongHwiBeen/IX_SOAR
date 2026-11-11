import unittest

from ix_normalizer.delimiter_parser import (
    DelimiterParseError,
    parse_delimited
)


class DelimiterParserTests(unittest.TestCase):

    # 1. 쉼표 구분자
    def test_comma(self):

        result = parse_delimited(
            "192.0.2.10,443,deny"
        )

        self.assertEqual(
            result[0].values,
            ("192.0.2.10", "443", "deny")
        )

    # 2. 파이프 구분자
    def test_pipe(self):

        result = parse_delimited(
            "src|dst|deny",
            delimiter="|"
        )

        self.assertEqual(
            result[0].values,
            ("src", "dst", "deny")
        )

    # 3. 세미콜론
    def test_semicolon(self):

        result = parse_delimited(
            "a;b",
            delimiter=";"
        )

        self.assertEqual(
            result[0].values,
            ("a", "b")
        )

    # 4. 탭
    def test_tab(self):

        result = parse_delimited(
            "a\tb",
            delimiter="\t"
        )

        self.assertEqual(
            result[0].values,
            ("a", "b")
        )

    # 5. 여러 글자 구분자
    def test_multi_character(self):

        result = parse_delimited(
            "a||b||c",
            delimiter="||"
        )

        self.assertEqual(
            result[0].values,
            ("a", "b", "c")
        )

    # 6. 따옴표 내부 구분자
    def test_quoted_delimiter(self):

        result = parse_delimited(
            'deny,"blocked, policy 10",443'
        )

        self.assertEqual(
            result[0].values,
            ("deny", "blocked, policy 10", "443")
        )

    # 7. 연속된 따옴표
    def test_escaped_quote(self):

        result = parse_delimited(
            'a,"user said ""no""",c'
        )

        self.assertEqual(
            result[0].values,
            ('a', 'user said "no"', 'c')
        )

    # 8. 중간 빈 필드
    def test_empty_middle_field(self):

        result = parse_delimited(
            "a,,c"
        )

        self.assertEqual(
            result[0].values,
            ("a", "", "c")
        )

    # 9. 마지막 빈 필드
    def test_trailing_empty_field(self):

        result = parse_delimited(
            "a,b,"
        )

        self.assertEqual(
            result[0].values,
            ("a", "b", "")
        )

    # 10. 첫 번째 빈 필드
    def test_leading_empty_field(self):

        result = parse_delimited(
            ",b"
        )

        self.assertEqual(
            result[0].values,
            ("", "b")
        )

    # 11. 공백 보존
    def test_preserves_spaces(self):

        result = parse_delimited(
            " a , b "
        )

        self.assertEqual(
            result[0].values,
            (" a ", " b ")
        )

    # 12. UTF-8 BOM
    def test_utf8_bom(self):

        result = parse_delimited(
            b"\xef\xbb\xbfa,b"
        )

        self.assertEqual(
            result[0].values,
            ("a", "b")
        )

    # 13. 잘못된 UTF-8
    def test_utf8_invalid(self):

        with self.assertRaises(DelimiterParseError):

            parse_delimited(
                b"\xff,1"
            )

    # 14. 필드 개수 불일치
    def test_expected_count_mismatch(self):

        with self.assertRaises(DelimiterParseError):

            parse_delimited(
                "a,b",
                expected_fields=3
            )

    # 15. 필드 개수 일치
    def test_expected_count_good(self):

        result = parse_delimited(
            "a,b",
            expected_fields=2
        )

        self.assertEqual(
            result[0].values,
            ("a", "b")
        )

    # 16. 닫히지 않은 따옴표
    def test_unterminated_quote(self):

        with self.assertRaises(DelimiterParseError):

            parse_delimited(
                'a,"b'
            )

    # 17. 따옴표 뒤 잘못된 문자
    def test_garbage_after_quote(self):

        with self.assertRaises(DelimiterParseError):

            parse_delimited(
                '"a"x,b'
            )

    # 18. 일반 필드 내부의 잘못된 따옴표
    def test_unquoted_quote(self):

        with self.assertRaises(DelimiterParseError):

            parse_delimited(
                'a"b,c'
            )

    # 19. 따옴표 밖 줄바꿈
    def test_newline_outside_quotes(self):

        with self.assertRaises(DelimiterParseError):

            parse_delimited(
                "a,b\nc,d"
            )

    # 20. 따옴표 내부 줄바꿈
    def test_newline_inside_quotes(self):

        result = parse_delimited(
            'a,"line1\nline2"'
        )

        self.assertEqual(
            result[0].values,
            ("a", "line1\nline2")
        )

    # 21. 최대 메시지 크기
    def test_max_bytes(self):

        with self.assertRaises(DelimiterParseError):

            parse_delimited(
                "abc,def",
                max_bytes=5
            )

    # 22. 최대 필드 개수
    def test_max_fields(self):

        with self.assertRaises(DelimiterParseError):

            parse_delimited(
                "a,b,c",
                max_fields=2
            )

    # 23. 최대 필드 길이
    def test_max_field_chars(self):

        with self.assertRaises(DelimiterParseError):

            parse_delimited(
                "abc,d",
                max_field_chars=2
            )

    # 24. 잘못된 설정
    def test_bad_config(self):

        with self.assertRaises(ValueError):
            parse_delimited(
                "a,b",
                delimiter=""
            )

        with self.assertRaises(ValueError):
            parse_delimited(
                "a,b",
                delimiter='"'
            )

        with self.assertRaises(ValueError):
            parse_delimited(
                "a,b",
                expected_fields=0
            )

    # 25. 잘못된 입력 타입
    def test_bad_type(self):

        with self.assertRaises(TypeError):

            parse_delimited(7)

    # 26. 따옴표 기능 비활성화
    def test_disable_quotes(self):

        result = parse_delimited(
            'a,"b,c',
            quote_char=None
        )

        self.assertEqual(
            result[0].values,
            ("a", '"b', "c")
        )

    # 27. 빈 입력
    def test_empty_input(self):

        with self.assertRaises(DelimiterParseError):

            parse_delimited("")

    # 28. 구분자만 존재
    def test_only_delimiter(self):

        result = parse_delimited(",")

        self.assertEqual(
            result[0].values,
            ("", "")
        )

    # 29. Windows 경로 보존
    def test_windows_path_untouched(self):

        result = parse_delimited(
            r"C:\Windows\System32|deny",
            delimiter="|"
        )

        self.assertEqual(
            result[0].values,
            (r"C:\Windows\System32", "deny")
        )


if __name__ == "__main__":
    unittest.main()