-- =============================================
-- IX SOAR ClickHouse Schema
-- Database: ix_soar
-- Table: raw_logs
-- =============================================

CREATE DATABASE IF NOT EXISTS ix_soar;


CREATE TABLE IF NOT EXISTS ix_soar.raw_logs
(
    -- 1. 로그 식별 정보
    log_id String,
    collector_message_id String,

    -- 2. 수집 장비 정보
    device_id LowCardinality(String),
    collector_source String,
    transport LowCardinality(String),

    -- 3. 시간 정보
    received_at DateTime64(3, 'UTC'),
    event_time Nullable(DateTime64(3, 'UTC')),

    -- 4. 네트워크 정보
    src_ip String DEFAULT '',
    src_port Nullable(UInt16),

    dst_ip String DEFAULT '',
    dst_port Nullable(UInt16),

    protocol LowCardinality(String) DEFAULT '',

    -- 5. 보안 로그 정보
    action LowCardinality(String) DEFAULT '',

    -- 6. 파서 정보
    parse_status LowCardinality(String),
    parser_id String DEFAULT '',
    parser_version UInt32 DEFAULT 0,

    -- 7. 원본 및 확장 필드
    raw_log String,
    raw_base64 String DEFAULT '',
    attributes_json String DEFAULT '{}',

    -- 8. Kafka 추적 정보
    raw_topic LowCardinality(String) DEFAULT 'ix.raw.logs',
    raw_partition Int32,
    raw_offset Int64,

    -- 9. DB 적재 시간
    ingested_at DateTime64(3, 'UTC') DEFAULT now64(3),

    -- 10. 로그 ID 검색을 위한 보조 인덱스
    INDEX idx_log_id log_id TYPE bloom_filter(0.01)
        GRANULARITY 1

)
ENGINE = MergeTree

PARTITION BY toYYYYMM(received_at)

ORDER BY (
    device_id,
    received_at,
    log_id
)

SETTINGS index_granularity = 8192;