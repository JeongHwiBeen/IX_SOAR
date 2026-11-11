import unittest

from ix_normalizer.json_parser import (
    JSONParseError,
    parse_json
)


class JSONParserTests(unittest.TestCase):

    # 1. JSON 객체
    def test_json_object(self):

        raw = b'{"src":"192.0.2.10","act":"deny"}'

        records = parse_json(raw)

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].index, 0)

        self.assertEqual(
            records[0].fields["src"],
            "192.0.2.10"
        )

        self.assertEqual(
            records[0].fields["act"],
            "deny"
        )

    # 2. JSON 배열
    def test_json_array(self):

        raw = '[{"id":1},{"id":2}]'

        records = parse_json(raw)

        self.assertEqual(
            [r.index for r in records],
            [0, 1]
        )

        self.assertEqual(
            [r.fields["id"] for r in records],
            [1, 2]
        )

    # 3. 중첩 JSON
    def test_nested_object_is_preserved(self):

        raw = (
            '{"network":'
            '{"src":{"ip":"192.0.2.10"}}}'
        )

        records = parse_json(raw)

        self.assertEqual(
            records[0].fields["network"]["src"]["ip"],
            "192.0.2.10"
        )

    # 4. UTF-8 BOM
    def test_utf8_bom(self):

        records = parse_json(
            b'\xef\xbb\xbf{"id":1}'
        )

        self.assertEqual(
            records[0].fields["id"],
            1
        )

    # 5. 잘못된 JSON
    def test_invalid_json(self):

        with self.assertRaises(JSONParseError):

            parse_json('{"src":}')

    # 6. 배열 내부에 잘못된 타입
    def test_non_object_array_element(self):

        with self.assertRaises(JSONParseError):

            parse_json('[{"id":1}, 2]')

    # 7. 빈 JSON 배열
    def test_empty_array(self):

        with self.assertRaises(JSONParseError):

            parse_json('[]')

    # 8. 중복 Key
    def test_duplicate_key(self):

        with self.assertRaises(JSONParseError):

            parse_json(
                '{"src":"A","src":"B"}'
            )

    # 9. 비표준 NaN
    def test_nonstandard_nan(self):

        with self.assertRaises(JSONParseError):

            parse_json('{"score":NaN}')

    # 10. 잘못된 UTF-8
    def test_invalid_utf8(self):

        with self.assertRaises(JSONParseError):

            parse_json(b'\xff\xfe')

    # 11. 메시지 크기 초과
    def test_max_bytes(self):

        with self.assertRaises(JSONParseError):

            parse_json(
                '{"message":"very long"}',
                max_bytes=10
            )

    # 12. 레코드 수 초과
    def test_max_records(self):

        with self.assertRaises(JSONParseError):

            parse_json(
                '[{"id":1},{"id":2}]',
                max_records=1
            )

    # 13. 잘못된 입력 타입
    def test_non_json_type(self):

        with self.assertRaises(TypeError):

            parse_json(123)

    # 14. JSON 기본값
    def test_top_level_primitive(self):

        with self.assertRaises(JSONParseError):

            parse_json('123')


if __name__ == "__main__":
    unittest.main()