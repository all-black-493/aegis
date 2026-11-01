from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | None = None
depends_on: str | None = None

UPGRADE = (
    """
    CREATE TABLE aegis.audit_events (
        id bigint GENERATED ALWAYS AS IDENTITY,
        event_id uuid NOT NULL,
        occurred_at timestamptz NOT NULL DEFAULT now(),
        event_type text NOT NULL,
        source text NOT NULL,
        outcome text NOT NULL,
        actor_id uuid,
        actor_kind text,
        target_type text,
        target_id text,
        task_id uuid,
        job_id uuid,
        decision_id uuid,
        request_id text,
        reason_code text,
        policy_version text,
        details jsonb NOT NULL DEFAULT '{}'::jsonb,
        CONSTRAINT pk_audit_events PRIMARY KEY (event_id),
        CONSTRAINT uq_audit_events_id UNIQUE (id),
        CONSTRAINT ck_audit_events_event_type CHECK (
            event_type ~ '^[a-z]+(_[a-z]+)*\\.[a-z]+(_[a-z]+)*$' AND length(event_type) <= 64
        ),
        CONSTRAINT ck_audit_events_source CHECK (source IN ('api', 'worker', 'cli', 'system')),
        CONSTRAINT ck_audit_events_outcome CHECK (outcome IN ('success', 'failure', 'denied')),
        CONSTRAINT ck_audit_events_actor CHECK ((actor_id IS NULL) = (actor_kind IS NULL)),
        CONSTRAINT ck_audit_events_actor_kind CHECK (actor_kind IN ('human', 'service', 'system')),
        CONSTRAINT ck_audit_events_target CHECK (
            (target_type IS NULL) = (target_id IS NULL)
            AND target_type ~ '^[a-z][a-z_]{0,63}$'
            AND length(target_id) BETWEEN 1 AND 128
        ),
        CONSTRAINT ck_audit_events_request_id CHECK (request_id ~ '^[A-Za-z0-9._:-]{1,128}$'),
        CONSTRAINT ck_audit_events_reason_code CHECK (reason_code ~ '^[a-z][a-z0-9_]{0,63}$'),
        CONSTRAINT ck_audit_events_policy_version CHECK (length(policy_version) BETWEEN 1 AND 64),
        CONSTRAINT ck_audit_events_details CHECK (
            jsonb_typeof(details) = 'object' AND octet_length(details::text) <= 4096
        )
    )
    """,
    "CREATE INDEX ix_audit_events_occurred_at ON aegis.audit_events (occurred_at)",
    "CREATE INDEX ix_audit_events_event_type_occurred_at"
    " ON aegis.audit_events (event_type, occurred_at)",
    "CREATE INDEX ix_audit_events_actor_id_occurred_at"
    " ON aegis.audit_events (actor_id, occurred_at)",
    "CREATE INDEX ix_audit_events_task_id ON aegis.audit_events (task_id)",
    """
    CREATE FUNCTION aegis.audit_events_stamp() RETURNS trigger
        LANGUAGE plpgsql SET search_path = pg_catalog AS $$
    BEGIN
        NEW.occurred_at := now();
        RETURN NEW;
    END;
    $$
    """,
    """
    CREATE FUNCTION aegis.audit_events_reject_change() RETURNS trigger
        LANGUAGE plpgsql SET search_path = pg_catalog AS $$
    BEGIN
        RAISE EXCEPTION 'aegis.audit_events is append-only';
    END;
    $$
    """,
    "REVOKE ALL ON FUNCTION aegis.audit_events_stamp() FROM PUBLIC",
    "REVOKE ALL ON FUNCTION aegis.audit_events_reject_change() FROM PUBLIC",
    "CREATE TRIGGER audit_events_stamp BEFORE INSERT ON aegis.audit_events"
    " FOR EACH ROW EXECUTE FUNCTION aegis.audit_events_stamp()",
    "CREATE TRIGGER audit_events_no_update_delete BEFORE UPDATE OR DELETE ON aegis.audit_events"
    " FOR EACH ROW EXECUTE FUNCTION aegis.audit_events_reject_change()",
    "CREATE TRIGGER audit_events_no_truncate BEFORE TRUNCATE ON aegis.audit_events"
    " FOR EACH STATEMENT EXECUTE FUNCTION aegis.audit_events_reject_change()",
    "REVOKE ALL ON aegis.audit_events FROM PUBLIC",
    """
    GRANT INSERT (
        event_id, event_type, source, outcome, actor_id, actor_kind, target_type, target_id,
        task_id, job_id, decision_id, request_id, reason_code, policy_version, details
    ) ON aegis.audit_events TO aegis_app
    """,
)

DOWNGRADE = (
    "DROP TABLE aegis.audit_events",
    "DROP FUNCTION aegis.audit_events_reject_change()",
    "DROP FUNCTION aegis.audit_events_stamp()",
)


def upgrade() -> None:
    for statement in UPGRADE:
        op.execute(statement)


def downgrade() -> None:
    for statement in DOWNGRADE:
        op.execute(statement)
