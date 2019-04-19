DROP TABLE IF EXISTS web_alerts;

CREATE TABLE web_alerts (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    sid                 TEXT,
    search_name         TEXT,
    app                 TEXT,
    result_message      TEXT,
    result_host         TEXT,
    result_source       TEXT,
    result_sourcetype   TEXT,
    results_link        TEXT,
    status              INTEGER NOT NULL DEFAULT 0,    -- 0:created, 1:published, 2:recovered, 3:recover_sent
    create_time         TEXT,
    publish_time        TEXT,
    recovery_time       TEXT
);

CREATE UNIQUE INDEX web_sid_idx ON web_alerts(sid);
