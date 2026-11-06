from alembic import op

revision: str = "0009"
down_revision: str | None = "0008"
branch_labels: str | None = None
depends_on: str | None = None

CODE = "'^[a-z][a-z0-9_]{0,63}$'"
DIGEST = "'^[0-9a-f]{64}$'"
ACTIONS = "'task.submit', 'task.read', 'task.list', 'task.list_all', 'task.cancel', 'task.execute'"
ROLES = "'admin', 'operator', 'auditor', 'worker'"


ROLE_CHECK = """
    CREATE OR REPLACE FUNCTION aegis.identity_roles_check_kind() RETURNS trigger
        LANGUAGE plpgsql SET search_path = pg_catalog AS $$
    DECLARE
        identity_kind text;
    BEGIN
        SELECT kind INTO identity_kind FROM aegis.identities WHERE id = NEW.identity_id;
        IF (identity_kind = 'system') <> (NEW.role IN (SYSTEM_ROLES)) THEN
            RAISE EXCEPTION 'role % cannot be held by a % identity', NEW.role, identity_kind;
        END IF;
        RETURN NEW;
    END;
    $$
"""


UPGRADE = (
    "ALTER TABLE aegis.identity_roles DROP CONSTRAINT ck_identity_roles_role",
    f"ALTER TABLE aegis.identity_roles ADD CONSTRAINT ck_identity_roles_role"
    f" CHECK (role IN ({ROLES}, 'agent'))",
    ROLE_CHECK.replace("SYSTEM_ROLES", "'worker', 'agent'"),
    "ALTER TABLE aegis.security_decisions DROP CONSTRAINT ck_security_decisions_action",
    f"ALTER TABLE aegis.security_decisions ADD CONSTRAINT ck_security_decisions_action"
    f" CHECK (action IN ({ACTIONS}, 'tool.invoke'))",
    # Survives a development downgrade: identities are never deleted.
    """
    INSERT INTO aegis.identities (id, kind, name)
    VALUES ('00000000-0000-4000-8000-000000000003', 'system', 'system:agent')
    ON CONFLICT DO NOTHING
    """,
    """
    INSERT INTO aegis.identity_roles (identity_id, role, granted_by) VALUES
        ('00000000-0000-4000-8000-000000000003', 'agent', '00000000-0000-4000-8000-000000000002')
    """,
    f"""
    CREATE TABLE aegis.agent_runs (
        id uuid NOT NULL,
        task_id uuid NOT NULL,
        job_id uuid NOT NULL,
        job_attempt integer NOT NULL,
        agent_id uuid NOT NULL,
        scenario text NOT NULL,
        capabilities text[] NOT NULL,
        sandbox text NOT NULL,
        policy_version text NOT NULL,
        policy_digest text NOT NULL,
        started_at timestamptz NOT NULL DEFAULT now(),
        CONSTRAINT pk_agent_runs PRIMARY KEY (id),
        CONSTRAINT uq_agent_runs_job_attempt UNIQUE (job_id, job_attempt),
        CONSTRAINT fk_agent_runs_job_id_jobs
            FOREIGN KEY (job_id, task_id) REFERENCES aegis.jobs (id, task_id),
        CONSTRAINT fk_agent_runs_agent_id_identities
            FOREIGN KEY (agent_id) REFERENCES aegis.identities (id),
        CONSTRAINT ck_agent_runs_job_attempt CHECK (job_attempt >= 1),
        CONSTRAINT ck_agent_runs_scenario CHECK (scenario ~ '^[a-z][a-z0-9-]{{0,63}}$'),
        CONSTRAINT ck_agent_runs_capabilities CHECK (cardinality(capabilities) <= 16),
        CONSTRAINT ck_agent_runs_sandbox CHECK (length(sandbox) BETWEEN 1 AND 64),
        CONSTRAINT ck_agent_runs_policy_version CHECK (length(policy_version) BETWEEN 1 AND 64),
        CONSTRAINT ck_agent_runs_policy_digest CHECK (policy_digest ~ {DIGEST})
    )
    """,
    "CREATE INDEX ix_agent_runs_task_id ON aegis.agent_runs (task_id)",
    f"""
    CREATE TABLE aegis.agent_steps (
        id bigint GENERATED ALWAYS AS IDENTITY,
        run_id uuid NOT NULL,
        sequence integer NOT NULL,
        kind text NOT NULL,
        code text NOT NULL,
        tool_name text,
        tool_version text,
        decision_id uuid,
        content jsonb NOT NULL,
        content_sha256 text NOT NULL,
        content_bytes integer NOT NULL,
        prompt_tokens integer,
        output_tokens integer,
        duration_ms integer,
        occurred_at timestamptz NOT NULL DEFAULT now(),
        CONSTRAINT pk_agent_steps PRIMARY KEY (id),
        CONSTRAINT uq_agent_steps_run_id_sequence UNIQUE (run_id, sequence),
        CONSTRAINT uq_agent_steps_decision_id UNIQUE (decision_id),
        CONSTRAINT fk_agent_steps_run_id_agent_runs
            FOREIGN KEY (run_id) REFERENCES aegis.agent_runs (id),
        CONSTRAINT fk_agent_steps_decision_id_security_decisions
            FOREIGN KEY (decision_id) REFERENCES aegis.security_decisions (id),
        CONSTRAINT ck_agent_steps_sequence CHECK (sequence >= 1),
        CONSTRAINT ck_agent_steps_kind CHECK (kind IN ('model', 'tool', 'end')),
        CONSTRAINT ck_agent_steps_code CHECK (code ~ {CODE}),
        CONSTRAINT ck_agent_steps_tool CHECK (
            (kind = 'tool') = (tool_name IS NOT NULL)
            AND (kind = 'tool') = (decision_id IS NOT NULL)
        ),
        CONSTRAINT ck_agent_steps_tool_name CHECK (tool_name ~ {CODE}),
        CONSTRAINT ck_agent_steps_content
            CHECK (jsonb_typeof(content) = 'object' AND octet_length(content::text) <= 81920),
        CONSTRAINT ck_agent_steps_content_sha256 CHECK (content_sha256 ~ {DIGEST}),
        CONSTRAINT ck_agent_steps_counts CHECK (
            content_bytes >= 0 AND prompt_tokens >= 0 AND output_tokens >= 0 AND duration_ms >= 0
        )
    )
    """,
    """
    CREATE FUNCTION aegis.agent_runs_before_insert() RETURNS trigger
        LANGUAGE plpgsql SET search_path = pg_catalog AS $$
    BEGIN
        NEW.started_at := now();
        IF NOT EXISTS (
            SELECT 1 FROM aegis.jobs j
            WHERE j.id = NEW.job_id AND j.task_id = NEW.task_id
                AND j.state = 'running' AND j.attempt = NEW.job_attempt
        ) THEN
            RAISE EXCEPTION 'an agent run needs its job running at this attempt';
        END IF;
        RETURN NEW;
    END;
    $$
    """,
    """
    CREATE FUNCTION aegis.agent_steps_before_insert() RETURNS trigger
        LANGUAGE plpgsql SET search_path = pg_catalog AS $$
    DECLARE
        run aegis.agent_runs;
        latest integer;
        decision aegis.security_decisions;
    BEGIN
        NEW.occurred_at := now();
        SELECT * INTO run FROM aegis.agent_runs WHERE id = NEW.run_id;
        IF NOT EXISTS (
            SELECT 1 FROM aegis.jobs j
            WHERE j.id = run.job_id AND j.state = 'running' AND j.attempt = run.job_attempt
        ) THEN
            RAISE EXCEPTION 'an agent step needs its job running at the run''s attempt';
        END IF;
        IF EXISTS (
            SELECT 1 FROM aegis.agent_steps s WHERE s.run_id = NEW.run_id AND s.kind = 'end'
        ) THEN
            RAISE EXCEPTION 'a finished agent run takes no more steps';
        END IF;
        SELECT coalesce(max(s.sequence), 0) INTO latest
        FROM aegis.agent_steps s WHERE s.run_id = NEW.run_id;
        IF NEW.sequence <> latest + 1 THEN
            RAISE EXCEPTION 'agent steps are numbered without gaps';
        END IF;
        IF NEW.decision_id IS NOT NULL THEN
            SELECT * INTO decision FROM aegis.security_decisions d WHERE d.id = NEW.decision_id;
            IF decision.action IS DISTINCT FROM 'tool.invoke'
                OR decision.task_id IS DISTINCT FROM run.task_id
                OR decision.job_id IS DISTINCT FROM run.job_id
                OR decision.job_attempt IS DISTINCT FROM run.job_attempt THEN
                RAISE EXCEPTION 'a tool step needs a tool decision for this run''s job attempt';
            END IF;
            IF (decision.effect = 'allow') = (NEW.code = 'not_authorized') THEN
                RAISE EXCEPTION 'a tool step must match its decision';
            END IF;
        END IF;
        RETURN NEW;
    END;
    $$
    """,
    *(
        f"REVOKE ALL ON FUNCTION aegis.{function}() FROM PUBLIC"
        for function in ("agent_runs_before_insert", "agent_steps_before_insert")
    ),
    "CREATE TRIGGER agent_runs_before_insert BEFORE INSERT ON aegis.agent_runs"
    " FOR EACH ROW EXECUTE FUNCTION aegis.agent_runs_before_insert()",
    "CREATE TRIGGER agent_steps_before_insert BEFORE INSERT ON aegis.agent_steps"
    " FOR EACH ROW EXECUTE FUNCTION aegis.agent_steps_before_insert()",
    *(
        statement
        for table in ("agent_runs", "agent_steps")
        for statement in (
            f"CREATE TRIGGER {table}_no_update_delete BEFORE UPDATE OR DELETE ON aegis.{table}"
            " FOR EACH ROW EXECUTE FUNCTION aegis.append_only()",
            f"CREATE TRIGGER {table}_no_truncate BEFORE TRUNCATE ON aegis.{table}"
            " FOR EACH STATEMENT EXECUTE FUNCTION aegis.append_only()",
            f"REVOKE ALL ON aegis.{table} FROM PUBLIC",
            f"GRANT SELECT ON aegis.{table} TO aegis_app",
        )
    ),
    """
    GRANT INSERT (
        id, task_id, job_id, job_attempt, agent_id, scenario, capabilities, sandbox,
        policy_version, policy_digest
    ) ON aegis.agent_runs TO aegis_app
    """,
    """
    GRANT INSERT (
        run_id, sequence, kind, code, tool_name, tool_version, decision_id, content,
        content_sha256, content_bytes, prompt_tokens, output_tokens, duration_ms
    ) ON aegis.agent_steps TO aegis_app
    """,
)

# Development only (ADR-0003). Run records go with their tables. Tool decisions stay as history
# under NOT VALID constraints, and the identity stays, because neither can be deleted.
DOWNGRADE = (
    "DROP TABLE aegis.agent_steps",
    "DROP TABLE aegis.agent_runs",
    "DROP FUNCTION aegis.agent_steps_before_insert()",
    "DROP FUNCTION aegis.agent_runs_before_insert()",
    "DELETE FROM aegis.identity_roles WHERE identity_id = '00000000-0000-4000-8000-000000000003'",
    "ALTER TABLE aegis.security_decisions DROP CONSTRAINT ck_security_decisions_action",
    f"ALTER TABLE aegis.security_decisions ADD CONSTRAINT ck_security_decisions_action"
    f" CHECK (action IN ({ACTIONS})) NOT VALID",
    ROLE_CHECK.replace("SYSTEM_ROLES", "'worker'"),
    "ALTER TABLE aegis.identity_roles DROP CONSTRAINT ck_identity_roles_role",
    f"ALTER TABLE aegis.identity_roles ADD CONSTRAINT ck_identity_roles_role"
    f" CHECK (role IN ({ROLES}))",
)


def upgrade() -> None:
    for statement in UPGRADE:
        op.execute(statement)


def downgrade() -> None:
    for statement in DOWNGRADE:
        op.execute(statement)
