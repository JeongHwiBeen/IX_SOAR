import unittest

from datetime import datetime, timedelta, timezone

from ix_normalizer.field_mapper import MappedRecord
from ix_normalizer.validator import validate_fields


class ValidatorTests(unittest.TestCase):

    # 공통 오류 검증 함수
    def check_bad(self, field, value):

        result = validate_fields({
            field: value
        })

        self.assertEqual(
            result.status,
            "failed"
        )

        self.assertFalse(
            result.is_valid
        )

        self.assertNotIn(
            field,
            result.fields
        )

        self.assertTrue(
            any(
                issue.field == field
                and issue.severity == "error"
                for issue in result.issues
            )
        )

    # ----------------------------------------------
    # IP 검증
    # ----------------------------------------------

    def test_ipv4(self):

        result = validate_fields({
            "src_ip": "192.0.2.10"
        })

        self.assertEqual(
            result.fields["src_ip"],
            "192.0.2.10"
        )

    def test_ipv6(self):

        result = validate_fields({
            "dst_ip": "2001:0DB8:0:0::1"
        })

        self.assertEqual(
            result.fields["dst_ip"],
            "2001:db8::1"
        )

    def test_bad_ipv4(self):

        self.check_bad(
            "src_ip",
            "999.999.999.999"
        )

    def test_cidr_not_ip(self):

        self.check_bad(
            "src_ip",
            "192.0.2.0/24"
        )

    def test_hostname_not_ip(self):

        self.check_bad(
            "src_ip",
            "firewall.local"
        )

    def test_zone_scoped_ipv6_rejected(self):

        self.check_bad(
            "src_ip",
            "fe80::1%eth0"
        )

    def test_ip_not_a_string(self):

        self.check_bad(
            "src_ip",
            123
        )

    # ----------------------------------------------
    # Port 검증
    # ----------------------------------------------

    def test_port_zero(self):

        result = validate_fields({
            "src_port": "0"
        })

        self.assertEqual(
            result.fields["src_port"],
            0
        )

    def test_port_65535(self):

        result = validate_fields({
            "dst_port": 65535
        })

        self.assertEqual(
            result.fields["dst_port"],
            65535
        )

    def test_port_spaces(self):

        result = validate_fields({
            "dst_port": " 00443 "
        })

        self.assertEqual(
            result.fields["dst_port"],
            443
        )

    def test_port_overflow(self):

        self.check_bad(
            "src_port",
            "65536"
        )

    def test_port_negative(self):

        self.check_bad(
            "src_port",
            "-1"
        )

    def test_port_bool(self):

        self.check_bad(
            "src_port",
            True
        )

    def test_port_float(self):

        self.check_bad(
            "src_port",
            443.0
        )

    def test_port_unicode_digits(self):

        self.check_bad(
            "src_port",
            "٤٤٣"
        )

    # ----------------------------------------------
    # Protocol 검증
    # ----------------------------------------------

    def test_protocol_number_str(self):

        result = validate_fields({
            "protocol": "6"
        })

        self.assertEqual(
            result.fields["protocol"],
            "TCP"
        )

    def test_protocol_number_int(self):

        result = validate_fields({
            "protocol": 17
        })

        self.assertEqual(
            result.fields["protocol"],
            "UDP"
        )

    def test_protocol_text(self):

        result = validate_fields({
            "protocol": "icmpv6"
        })

        self.assertEqual(
            result.fields["protocol"],
            "ICMPV6"
        )

    def test_protocol_unknown(self):

        result = validate_fields({
            "protocol": "HTTPS"
        })

        self.assertEqual(
            result.status,
            "partial"
        )

        self.assertTrue(
            result.is_valid
        )

        self.assertEqual(
            result.fields["protocol"],
            "HTTPS"
        )

        self.assertEqual(
            result.issues[0].code,
            "unknown_protocol"
        )

    def test_protocol_unknown_number(self):

        result = validate_fields({
            "protocol": "253"
        })

        self.assertEqual(
            result.status,
            "partial"
        )

        self.assertEqual(
            result.fields["protocol"],
            "253"
        )

    def test_protocol_number_out_of_range(self):

        self.check_bad(
            "protocol",
            256
        )

    def test_protocol_invalid(self):

        self.check_bad(
            "protocol",
            "tcp*?"
        )

    # ----------------------------------------------
    # Action 검증
    # ----------------------------------------------

    def test_action_block(self):

        result = validate_fields({
            "action": "BLOCK"
        })

        self.assertEqual(
            result.fields["action"],
            "deny"
        )

    def test_action_drop_not_deny(self):

        result = validate_fields({
            "action": "DROP"
        })

        self.assertEqual(
            result.fields["action"],
            "drop"
        )

    def test_action_allow(self):

        result = validate_fields({
            "action": "Permit"
        })

        self.assertEqual(
            result.fields["action"],
            "allow"
        )

    def test_action_unknown(self):

        result = validate_fields({
            "action": "investigate"
        })

        self.assertEqual(
            result.status,
            "partial"
        )

        self.assertEqual(
            result.fields["action"],
            "investigate"
        )

        self.assertEqual(
            result.issues[0].code,
            "unknown_action"
        )

    def test_action_control_character(self):

        self.check_bad(
            "action",
            "deny\nblock"
        )

    # ----------------------------------------------
    # Event Time 검증
    # ----------------------------------------------

    def test_time_utc(self):

        result = validate_fields({
            "event_time": "2026-11-11T20:30:00Z"
        })

        self.assertEqual(
            result.fields["event_time"],
            datetime(
                2026, 11, 11, 20, 30,
                tzinfo=timezone.utc
            )
        )

    def test_time_timezone_offset(self):

        result = validate_fields({
            "event_time": "2026-11-11T20:30:00+09:00"
        })

        self.assertEqual(
            result.fields["event_time"],
            datetime(
                2026, 11, 11, 11, 30,
                tzinfo=timezone.utc
            )
        )

    def test_time_aware_datetime(self):

        dt = datetime(
            2026, 11, 11, 20, 30,
            tzinfo=timezone(
                timedelta(hours=9)
            )
        )

        result = validate_fields({
            "event_time": dt
        })

        self.assertEqual(
            result.fields["event_time"],
            datetime(
                2026, 11, 11, 11, 30,
                tzinfo=timezone.utc
            )
        )

    def test_naive_time_rejected(self):

        self.check_bad(
            "event_time",
            "2026-11-11 20:30:00"
        )

    def test_naive_datetime_rejected(self):

        self.check_bad(
            "event_time",
            datetime(2026, 11, 11, 20, 30)
        )

    def test_naive_time_fixed_timezone(self):

        result = validate_fields(
            {
                "event_time": "2026-11-11 20:30:00"
            },
            assume_timezone=timezone(
                timedelta(hours=9)
            )
        )

        self.assertEqual(
            result.fields["event_time"],
            datetime(
                2026, 11, 11, 11, 30,
                tzinfo=timezone.utc
            )
        )

    def test_invalid_date(self):

        self.check_bad(
            "event_time",
            "2026-02-30T12:00:00Z"
        )

    def test_invalid_timestamp(self):

        self.check_bad(
            "event_time",
            "Nov 11 20:30:00"
        )

    def test_event_time_none_from_3164(self):

        result = validate_fields({
            "event_time": None
        })

        self.assertEqual(
            result.status,
            "success"
        )

        self.assertNotIn(
            "event_time",
            result.fields
        )

    # ----------------------------------------------
    # Device ID 검증
    # ----------------------------------------------

    def test_device(self):

        result = validate_fields({
            "device_id": " FW-01 "
        })

        self.assertEqual(
            result.fields["device_id"],
            "FW-01"
        )

    def test_invalid_device(self):

        self.check_bad(
            "device_id",
            " "
        )

    def test_invalid_device_control(self):

        self.check_bad(
            "device_id",
            "abc\x00"
        )

    # ----------------------------------------------
    # 공통 처리
    # ----------------------------------------------

    def test_unknown_field(self):

        result = validate_fields({
            "log_id": "abc"
        })

        self.assertEqual(
            result.issues[0].code,
            "unsupported_field"
        )

        self.assertEqual(
            result.status,
            "failed"
        )

    def test_input_unmodified(self):

        original = {
            "src_port": "443",
            "action": "BLOCK"
        }

        result = validate_fields(original)

        self.assertEqual(
            original,
            {
                "src_port": "443",
                "action": "BLOCK"
            }
        )

        self.assertEqual(
            result.fields,
            {
                "src_port": 443,
                "action": "deny"
            }
        )

        self.assertEqual(
            result.status,
            "success"
        )

    def test_mapped_record(self):

        mapped = MappedRecord(
            fields={
                "src_ip": "192.0.2.10"
            },
            profile_id="fw-kv-v1",
            profile_version=1
        )

        result = validate_fields(mapped)

        self.assertEqual(
            result.fields["src_ip"],
            "192.0.2.10"
        )

    def test_bad_input(self):

        with self.assertRaises(TypeError):

            validate_fields(1)

    def test_bad_timezone_type(self):

        with self.assertRaises(TypeError):

            validate_fields(
                {},
                assume_timezone="Asia/Seoul"
            )

    def test_errors_prioritize_warnings(self):

        result = validate_fields({
            "src_ip": "not-ip",
            "action": "vendorCustom"
        })

        self.assertEqual(
            result.status,
            "failed"
        )

        self.assertEqual(
            len(result.issues),
            2
        )

        self.assertIn(
            "action",
            result.fields
        )

        self.assertNotIn(
            "src_ip",
            result.fields
        )


if __name__ == "__main__":
    unittest.main()