DROP TABLE if exists alerts;

CREATE TABLE alerts (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    sid                 TEXT,
    alert_group         TEXT,
    savedsearch_name    TEXT,
    alert_type          TEXT,
    digest_mode         INTEGER,
    severity            INTEGER,
    expiration_time     TEXT,
    status              INTEGER NOT NULL DEFAULT 0,    -- 0:created, 1:published, 2:recovered, 3:recover_sent
    create_time         TEXT,
    publish_time        TEXT,
    recovery_time       TEXT
);
