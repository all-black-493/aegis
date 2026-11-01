from alembic import op

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | None = None
depends_on: str | None = None

CODE = "'^[a-z][a-z0-9_]{0,63}$'"
IDENTIFIER = "'^[A-Za-z0-9._:-]{1,128}$'"

HISTORY_BEFORE_INSERT = """
    CREATE OR REPLACE FUNCTION aegis.task_state_transitions_before_insert() RETURNS trigger
        LANGUAGE plpgsql SET search_path = pg_catalog AS $$
    DECLARE
        job record;
    BEGIN
        NEW.occurred_at := now();
        IF NOT EXISTS (
            SELECT 1 FROM aegis.task_transition_rules r
            WHERE r.from_state = NEW.from_state AND r.to_state = NEW.to_state
                AND r.action IS NOT DISTINCT FROM NEW.decision_action
                AND r.effect IS NOT DISTINCT FROM NEW.decision_effect
                AND r.stage IS NOT DISTINCT FROM NEW.decision_stage
                AND r.requires_job = (NEW.job_id IS NOT NULL)
        ) THEN
            RAISE EXCEPTION 'no rule allows % to % with this decision and job',
                NEW.from_state, NEW.to_state;
        END IF;
        IF NEW.decision_id IS NOT NULL AND EXISTS (
            SELECT 1 FROM aegis.security_decisions d
            WHERE d.id = NEW.decision_id
                AND (d.job_id, d.job_attempt) IS DISTINCT FROM (NEW.job_id, NEW.job_attempt)
        ) THEN
            RAISE EXCEPTION 'the decision was made for a different job attempt';
        END IF;
        IF NEW.job_id IS NOT NULL THEN
            SELECT j.state, j.attempt, j.lease_expires_at INTO job
            FROM aegis.jobs j WHERE j.id = NEW.job_id AND j.task_id = NEW.task_id;
            IF NOT FOUND OR job.state <> 'running' OR job.attempt <> NEW.job_attempt THEN
                RAISE EXCEPTION 'a worker''s history row must carry its job''s current attempt';
            END IF;
            -- Only recovery's moves (interrupting, or cancelling on request) may outlive a lease.
            IF NEW.from_state IN ('queued', 'running')
                AND NEW.to_state NOT IN ('interrupted', 'cancelled')
                AND job.lease_expires_at <= now() THEN
                RAISE EXCEPTION 'the job''s lease has expired';
            END IF;
        END IF;
        RETURN NEW;
    END;
    $$
"""

PREVIOUS_HISTORY_BEFORE_INSERT = """
    CREATE OR REPLACE FUNCTION aegis.task_state_transitions_before_insert() RETURNS trigger
        LANGUAGE plpgsql SET search_path = pg_catalog AS $$
    BEGIN
        NEW.occurred_at := now();
        IF NOT EXISTS (
            SELECT 1 FROM aegis.task_transition_rules r
            WHERE r.from_state = NEW.from_state AND r.to_state = NEW.to_state
                AND r.action IS NOT DISTINCT FROM NEW.decision_action
                AND r.effect IS NOT DISTINCT FROM NEW.decision_effect
                AND r.stage IS NOT DISTINCT FROM NEW.decision_stage
                AND r.requires_job = (NEW.job_id IS NOT NULL)
        ) THEN
            RAISE EXCEPTION 'no rule allows % to % with this decision and job',
                NEW.from_state, NEW.to_state;
        END IF;
        IF NEW.decision_id IS NOT NULL AND EXISTS (
            SELECT 1 FROM aegis.security_decisions d
            WHERE d.id = NEW.decision_id
                AND (d.job_id, d.job_attempt) IS DISTINCT FROM (NEW.job_id, NEW.job_attempt)
        ) THEN
            RAISE EXCEPTION 'the decision was made for a different job attempt';
        END IF;
        RETURN NEW;
    END;
    $$
"""

UPGRADE = (
    f"""
    CREATE TABLE aegis.jobs (
        id uuid NOT NULL,
        task_id uuid NOT NULL,
        state text NOT NULL DEFAULT 'pending',
        attempt integer NOT NULL DEFAULT 0,
        max_attempts integer NOT NULL,
        run_after timestamptz NOT NULL DEFAULT now(),
        lease_owner text,
        lease_expires_at timestamptz,
        heartbeat_at timestamptz,
        last_error_code text,
        correlation_id text,
        created_at timestamptz NOT NULL DEFAULT now(),
        updated_at timestamptz NOT NULL DEFAULT now(),
        finished_at timestamptz,
        CONSTRAINT pk_jobs PRIMARY KEY (id),
        CONSTRAINT uq_jobs_id_task_id UNIQUE (id, task_id),
        CONSTRAINT fk_jobs_task_id_tasks FOREIGN KEY (task_id) REFERENCES aegis.tasks (id),
        CONSTRAINT ck_jobs_state CHECK (state IN ('pending', 'running', 'finished')),
        CONSTRAINT ck_jobs_max_attempts CHECK (max_attempts BETWEEN 1 AND 10),
        CONSTRAINT ck_jobs_attempt CHECK (attempt BETWEEN 0 AND max_attempts),
        CONSTRAINT ck_jobs_lease CHECK (
            (state = 'running') = (lease_owner IS NOT NULL)
            AND (lease_owner IS NULL) = (lease_expires_at IS NULL)
            AND (state <> 'running' OR attempt >= 1)
        ),
        CONSTRAINT ck_jobs_lease_owner CHECK (lease_owner ~ {IDENTIFIER}),
        CONSTRAINT ck_jobs_last_error_code CHECK (last_error_code ~ {CODE}),
        CONSTRAINT ck_jobs_correlation_id CHECK (correlation_id ~ {IDENTIFIER}),
        CONSTRAINT ck_jobs_finished CHECK ((finished_at IS NOT NULL) = (state = 'finished'))
    )
    """,
    "CREATE UNIQUE INDEX uq_jobs_active_task_id ON aegis.jobs (task_id)"
    " WHERE state IN ('pending', 'running')",
    "CREATE INDEX ix_jobs_pending ON aegis.jobs (run_after, id) WHERE state = 'pending'",
    "CREATE INDEX ix_jobs_running ON aegis.jobs (lease_expires_at) WHERE state = 'running'",
    """
    CREATE FUNCTION aegis.jobs_before_insert() RETURNS trigger
        LANGUAGE plpgsql SET search_path = pg_catalog AS $$
    BEGIN
        IF NEW.state <> 'pending' OR NEW.attempt <> 0 OR num_nonnulls(
            NEW.lease_owner, NEW.lease_expires_at, NEW.heartbeat_at, NEW.last_error_code,
            NEW.finished_at
        ) > 0 THEN
            RAISE EXCEPTION 'jobs start pending at attempt 0, without a lease or outcome';
        END IF;
        NEW.created_at := now();
        NEW.updated_at := now();
        RETURN NEW;
    END;
    $$
    """,
    """
    CREATE FUNCTION aegis.jobs_before_update() RETURNS trigger
        LANGUAGE plpgsql SET search_path = pg_catalog AS $$
    BEGIN
        IF (NEW.id, NEW.task_id, NEW.max_attempts, NEW.correlation_id, NEW.created_at)
            IS DISTINCT FROM
           (OLD.id, OLD.task_id, OLD.max_attempts, OLD.correlation_id, OLD.created_at) THEN
            RAISE EXCEPTION 'a job''s fixed columns cannot change';
        END IF;
        IF OLD.state = 'finished' THEN
            RAISE EXCEPTION 'a finished job cannot change';
        END IF;
        IF OLD.state <> NEW.state AND (OLD.state, NEW.state) NOT IN (
            ('pending', 'running'), ('running', 'pending'), ('running', 'finished'),
            ('pending', 'finished')
        ) THEN
            RAISE EXCEPTION 'illegal job transition from % to %', OLD.state, NEW.state;
        END IF;
        IF (NEW.attempt IS DISTINCT FROM OLD.attempt
            OR (OLD.state = 'pending' AND NEW.state = 'running'))
            AND NOT (OLD.state = 'pending' AND NEW.state = 'running'
                AND NEW.attempt = OLD.attempt + 1) THEN
            RAISE EXCEPTION 'a job''s attempt rises by exactly 1, and only when it is claimed';
        END IF;
        IF OLD.state = 'running' AND NEW.state = 'running' AND OLD.lease_expires_at <= now() THEN
            RAISE EXCEPTION 'an expired lease cannot be renewed';
        END IF;
        IF NEW.state = 'running' AND NEW.lease_expires_at <= now() THEN
            RAISE EXCEPTION 'a running job needs a lease that has not expired';
        END IF;
        IF NEW.state = 'finished' THEN
            NEW.finished_at := now();
        END IF;
        NEW.updated_at := now();
        RETURN NEW;
    END;
    $$
    """,
    HISTORY_BEFORE_INSERT,
    *(
        f"REVOKE ALL ON FUNCTION aegis.{function}() FROM PUBLIC"
        for function in ("jobs_before_insert", "jobs_before_update")
    ),
    "CREATE TRIGGER jobs_before_insert BEFORE INSERT ON aegis.jobs"
    " FOR EACH ROW EXECUTE FUNCTION aegis.jobs_before_insert()",
    "CREATE TRIGGER jobs_before_update BEFORE UPDATE ON aegis.jobs"
    " FOR EACH ROW EXECUTE FUNCTION aegis.jobs_before_update()",
    "CREATE TRIGGER jobs_no_delete BEFORE DELETE ON aegis.jobs"
    " FOR EACH ROW EXECUTE FUNCTION aegis.reject_delete()",
    "CREATE TRIGGER jobs_no_truncate BEFORE TRUNCATE ON aegis.jobs"
    " FOR EACH STATEMENT EXECUTE FUNCTION aegis.reject_delete()",
    """
    ALTER TABLE aegis.task_state_transitions ADD CONSTRAINT fk_task_state_transitions_job_id_jobs
        FOREIGN KEY (job_id, task_id) REFERENCES aegis.jobs (id, task_id)
    """,
    """
    ALTER TABLE aegis.security_decisions ADD CONSTRAINT fk_security_decisions_job_id_jobs
        FOREIGN KEY (job_id, task_id) REFERENCES aegis.jobs (id, task_id)
    """,
    """
    ALTER TABLE aegis.audit_events ADD CONSTRAINT fk_audit_events_job_id_jobs
        FOREIGN KEY (job_id) REFERENCES aegis.jobs (id)
    """,
    "REVOKE ALL ON aegis.jobs FROM PUBLIC",
    "GRANT SELECT ON aegis.jobs TO aegis_app",
    "GRANT INSERT (id, task_id, max_attempts, run_after, correlation_id)"
    " ON aegis.jobs TO aegis_app",
    """
    GRANT UPDATE (
        state, attempt, run_after, lease_owner, lease_expires_at, heartbeat_at, last_error_code
    ) ON aegis.jobs TO aegis_app
    """,
)

DOWNGRADE = (
    "ALTER TABLE aegis.audit_events DROP CONSTRAINT fk_audit_events_job_id_jobs",
    "ALTER TABLE aegis.security_decisions DROP CONSTRAINT fk_security_decisions_job_id_jobs",
    "ALTER TABLE aegis.task_state_transitions"
    " DROP CONSTRAINT fk_task_state_transitions_job_id_jobs",
    PREVIOUS_HISTORY_BEFORE_INSERT,
    "DROP TABLE aegis.jobs",
    "DROP FUNCTION aegis.jobs_before_update()",
    "DROP FUNCTION aegis.jobs_before_insert()",
)


def upgrade() -> None:
    for statement in UPGRADE:
        op.execute(statement)


def downgrade() -> None:
    for statement in DOWNGRADE:
        op.execute(statement)
