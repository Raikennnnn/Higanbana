-- Schema for the private analysis database.
--
-- Naming rule: any column ending in _private holds raw attacker data
-- (IPs, passwords, command lines, URLs, raw payloads). Public APIs and the
-- public summary export must never select these columns.
--
-- src_ip_private is text, not inet: public datasets (e.g. CyberLab) replace
-- IPs with pseudonymous hashes. The enrichment worker only looks up values
-- that parse as IP addresses.

CREATE TABLE IF NOT EXISTS sensors (
    sensor_id   text PRIMARY KEY,
    provider    text,
    region      text,
    notes       text,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS raw_events (
    id               bigserial PRIMARY KEY,
    sensor_id        text NOT NULL REFERENCES sensors (sensor_id),
    event_hash       char(64) NOT NULL,
    eventid          text NOT NULL,
    ts               timestamptz NOT NULL,
    session_id       text,
    src_ip_private   text,
    payload_private  jsonb NOT NULL,
    ingested_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (sensor_id, event_hash)
);
CREATE INDEX IF NOT EXISTS raw_events_ts_idx ON raw_events (ts);
CREATE INDEX IF NOT EXISTS raw_events_eventid_idx ON raw_events (eventid);

CREATE TABLE IF NOT EXISTS sessions (
    sensor_id       text NOT NULL REFERENCES sensors (sensor_id),
    session_id      text NOT NULL,
    src_ip_private  text,
    src_country     text,           -- from the dataset or the enrichment worker
    src_port        integer,
    dst_port        integer,
    protocol        text,
    client_version  text,
    first_seen_at   timestamptz NOT NULL,
    last_seen_at    timestamptz NOT NULL,
    duration_s      double precision,
    login_success   boolean NOT NULL DEFAULT false,
    PRIMARY KEY (sensor_id, session_id)
);
CREATE INDEX IF NOT EXISTS sessions_first_seen_idx ON sessions (first_seen_at);

CREATE TABLE IF NOT EXISTS auth_attempts (
    id                bigserial PRIMARY KEY,
    raw_event_id      bigint NOT NULL UNIQUE REFERENCES raw_events (id),
    sensor_id         text NOT NULL,
    session_id        text NOT NULL,
    ts                timestamptz NOT NULL,
    username          text,
    password_private  text,
    success           boolean NOT NULL,
    FOREIGN KEY (sensor_id, session_id) REFERENCES sessions (sensor_id, session_id)
);
CREATE INDEX IF NOT EXISTS auth_attempts_ts_idx ON auth_attempts (ts);

CREATE TABLE IF NOT EXISTS commands (
    id             bigserial PRIMARY KEY,
    raw_event_id   bigint NOT NULL UNIQUE REFERENCES raw_events (id),
    sensor_id      text NOT NULL,
    session_id     text NOT NULL,
    ts             timestamptz NOT NULL,
    input_private  text NOT NULL,
    FOREIGN KEY (sensor_id, session_id) REFERENCES sessions (sensor_id, session_id)
);
CREATE INDEX IF NOT EXISTS commands_ts_idx ON commands (ts);

CREATE TABLE IF NOT EXISTS file_events (
    id             bigserial PRIMARY KEY,
    raw_event_id   bigint NOT NULL UNIQUE REFERENCES raw_events (id),
    sensor_id      text NOT NULL,
    session_id     text NOT NULL,
    ts             timestamptz NOT NULL,
    kind           text NOT NULL,  -- download | download_failed | upload
    url_private    text,
    shasum         text,
    outfile        text,
    FOREIGN KEY (sensor_id, session_id) REFERENCES sessions (sensor_id, session_id)
);

-- IP enrichment cache (ASN/org, country), for sources that are real IP addresses.
CREATE TABLE IF NOT EXISTS ip_enrichment_cache (
    ip_private    inet PRIMARY KEY,
    asn           integer,
    as_org        text,
    country_code  char(2),
    reputation    jsonb,
    source        text NOT NULL,
    fetched_at    timestamptz NOT NULL DEFAULT now(),
    expires_at    timestamptz NOT NULL
);

-- Behaviour labels written by collector/classifier.py.
CREATE TABLE IF NOT EXISTS behavior_labels (
    id                bigserial PRIMARY KEY,
    sensor_id         text NOT NULL,
    session_id        text NOT NULL,
    rule_id           text NOT NULL,
    label             text NOT NULL,
    attack_technique  text,
    confidence        text NOT NULL,
    evidence_private  text,
    created_at        timestamptz NOT NULL DEFAULT now(),
    UNIQUE (sensor_id, session_id, rule_id),
    FOREIGN KEY (sensor_id, session_id) REFERENCES sessions (sensor_id, session_id)
);
