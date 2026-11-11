-- =============================================
-- IX SOAR ClickHouse Insert Test
-- =============================================

INSERT INTO ix_soar.raw_logs
(
    log_id,
    collector_message_id,
    device_id,
    collector_source,
    transport,
    received_at,
    event_time,
    src_ip,
    src_port,
    dst_ip,
    dst_port,
    protocol,
    action,
    parse_status,
    parser_id,
    parser_version,
    raw_log,
    raw_partition,
    raw_offset
)
VALUES
(
    'LOG-001',
    'MSG-001',
    'FW-001',
    '192.0.2.100',
    'syslog-udp',
    now64(3),
    now64(3),
    '192.0.2.10',
    50000,
    '198.51.100.20',
    443,
    'TCP',
    'deny',
    'success',
    'fw-kv-v1',
    1,
    'src=192.0.2.10 dst=198.51.100.20 sport=50000 dport=443 action=deny',
    0,
    1
);


-- =============================================
-- Insert 결과 확인
-- =============================================

SELECT
    log_id,
    device_id,
    received_at,
    src_ip,
    src_port,
    dst_ip,
    dst_port,
    protocol,
    action,
    parse_status
FROM ix_soar.raw_logs
WHERE log_id = 'LOG-001';