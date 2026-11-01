from alembic import op

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | None = None
depends_on: str | None = None

STATES = (
    "'created', 'queued', 'awaiting_approval', 'running', 'succeeded', 'failed', 'cancelled',"
    " 'interrupted'"
)
TERMINAL = "'succeeded', 'failed', 'cancelled'"
ACTIONS = "'task.submit', 'task.read', 'task.list', 'task.list_all', 'task.cancel', 'task.execute'"
CODE = "'^[a-z][a-z0-9_]{0,63}$'"
REQUEST_ID = "'^[A-Za-z0-9._:-]{1,128}$'"

UPGRADE = (
    """
    CREATE FUNCTION aegis.valid_reason_codes(codes text[]) RETURNS boolean
        LANGUAGE sql IMMUTABLE STRICT SET search_path = pg_catalog AS $$
        SELECT cardinality(codes) BETWEEN 1 AND 16
            AND coalesce(bool_and(code IS NOT NULL AND code ~ '^[a-z][a-z0-9_]{0,63}$'), false)
        FROM unnest(codes) AS code
    $$
    """,
    "ALTER TABLE aegis.identities ADD CONSTRAINT uq_identities_id_kind UNIQUE (id, kind)",
    "ALTER TABLE aegis.credentials"
    " ADD CONSTRAINT uq_credentials_id_identity_id UNIQUE (id, identity_id)",
    f"""
    CREATE TABLE aegis.tasks (
        id uuid NOT NULL,
        initiator_id uuid NOT NULL,
        owner_id uuid NOT NULL,
        submitted_credential_id uuid NOT NULL,
        kind text NOT NULL,
        input jsonb NOT NULL,
        state text NOT NULL DEFAULT 'created',
        version integer NOT NULL DEFAULT 0,
        idempotency_key text NOT NULL,
        request_fingerprint text NOT NULL,
        cancel_requested_at timestamptz,
        cancel_requested_by uuid,
        result jsonb,
        failure_code text,
        created_at timestamptz NOT NULL DEFAULT now(),
        updated_at timestamptz NOT NULL DEFAULT now(),
        finished_at timestamptz,
        CONSTRAINT pk_tasks PRIMARY KEY (id),
        CONSTRAINT uq_tasks_id_initiator_id UNIQUE (id, initiator_id),
        CONSTRAINT uq_tasks_id_owner_id UNIQUE (id, owner_id),
        CONSTRAINT uq_tasks_initiator_id_idempotency_key UNIQUE (initiator_id, idempotency_key),
        CONSTRAINT fk_tasks_initiator_id_identities
            FOREIGN KEY (initiator_id) REFERENCES aegis.identities (id),
        CONSTRAINT fk_tasks_owner_id_identities
            FOREIGN KEY (owner_id) REFERENCES aegis.identities (id),
        CONSTRAINT fk_tasks_submitted_credential_id_credentials
            FOREIGN KEY (submitted_credential_id, initiator_id)
            REFERENCES aegis.credentials (id, identity_id),
        CONSTRAINT fk_tasks_cancel_requested_by_identities
            FOREIGN KEY (cancel_requested_by) REFERENCES aegis.identities (id),
        CONSTRAINT ck_tasks_owner CHECK (owner_id = initiator_id),
        CONSTRAINT ck_tasks_kind CHECK (kind IN ('noop', 'wait')),
        CONSTRAINT ck_tasks_input CHECK (
            jsonb_typeof(input) = 'object' AND octet_length(input::text) <= 16384
        ),
        CONSTRAINT ck_tasks_state CHECK (state IN ({STATES})),
        CONSTRAINT ck_tasks_version CHECK (version >= 0),
        CONSTRAINT ck_tasks_idempotency_key CHECK (idempotency_key ~ '^[A-Za-z0-9_.:-]{{8,128}}$'),
        CONSTRAINT ck_tasks_request_fingerprint CHECK (request_fingerprint ~ '^[0-9a-f]{{64}}$'),
        CONSTRAINT ck_tasks_cancel_requested
            CHECK ((cancel_requested_at IS NULL) = (cancel_requested_by IS NULL)),
        CONSTRAINT ck_tasks_result CHECK (
            result IS NULL OR (
                state = 'succeeded'
                AND jsonb_typeof(result) = 'object'
                AND octet_length(result::text) <= 16384
            )
        ),
        CONSTRAINT ck_tasks_failure_code CHECK (
            (state = 'failed') = (failure_code IS NOT NULL) AND failure_code ~ {CODE}
        ),
        CONSTRAINT ck_tasks_finished CHECK ((finished_at IS NOT NULL) = (state IN ({TERMINAL})))
    )
    """,
    f"""
    CREATE TABLE aegis.security_decisions (
        id uuid NOT NULL,
        decided_at timestamptz NOT NULL DEFAULT now(),
        actor_id uuid NOT NULL,
        actor_kind text NOT NULL,
        actor_credential_id uuid,
        subject_id uuid NOT NULL,
        action text NOT NULL,
        resource_type text NOT NULL,
        resource_id text,
        resource_owner_id uuid,
        task_id uuid,
        effect text NOT NULL,
        stage text NOT NULL,
        reason_codes text[] NOT NULL,
        policy_version text NOT NULL,
        policy_digest text NOT NULL,
        request_id text,
        job_id uuid,
        job_attempt integer,
        CONSTRAINT pk_security_decisions PRIMARY KEY (id),
        CONSTRAINT uq_security_decisions_transition_key
            UNIQUE (id, task_id, action, effect, stage, decided_at),
        CONSTRAINT fk_security_decisions_actor_id_identities
            FOREIGN KEY (actor_id, actor_kind) REFERENCES aegis.identities (id, kind),
        CONSTRAINT fk_security_decisions_actor_credential_id_credentials
            FOREIGN KEY (actor_credential_id, actor_id)
            REFERENCES aegis.credentials (id, identity_id),
        CONSTRAINT fk_security_decisions_subject_id_identities
            FOREIGN KEY (subject_id) REFERENCES aegis.identities (id),
        CONSTRAINT fk_security_decisions_task_id_tasks
            FOREIGN KEY (task_id, subject_id) REFERENCES aegis.tasks (id, initiator_id),
        CONSTRAINT fk_security_decisions_task_id_owner_tasks
            FOREIGN KEY (task_id, resource_owner_id) REFERENCES aegis.tasks (id, owner_id),
        CONSTRAINT ck_security_decisions_actor_kind
            CHECK (actor_kind IN ('human', 'service', 'system')),
        CONSTRAINT ck_security_decisions_system_actor
            CHECK (actor_kind <> 'system' OR actor_credential_id IS NULL),
        CONSTRAINT ck_security_decisions_action CHECK (action IN ({ACTIONS})),
        CONSTRAINT ck_security_decisions_resource_type CHECK (resource_type IN ('task')),
        CONSTRAINT ck_security_decisions_resource
            CHECK ((resource_id IS NULL) = (resource_owner_id IS NULL)),
        CONSTRAINT ck_security_decisions_task_resource
            CHECK (task_id IS NULL OR resource_id = task_id::text),
        CONSTRAINT ck_security_decisions_effect
            CHECK (effect IN ('allow', 'deny', 'approval_required')),
        CONSTRAINT ck_security_decisions_stage CHECK (
            stage IN ('authorization', 'policy')
            AND NOT (stage = 'authorization' AND effect = 'approval_required')
        ),
        CONSTRAINT ck_security_decisions_reason_codes
            CHECK (aegis.valid_reason_codes(reason_codes)),
        CONSTRAINT ck_security_decisions_policy_version
            CHECK (length(policy_version) BETWEEN 1 AND 64),
        CONSTRAINT ck_security_decisions_policy_digest CHECK (policy_digest ~ '^[0-9a-f]{{64}}$'),
        CONSTRAINT ck_security_decisions_request_id CHECK (request_id ~ {REQUEST_ID}),
        CONSTRAINT ck_security_decisions_job
            CHECK ((job_id IS NULL) = (job_attempt IS NULL) AND job_attempt >= 1)
    )
    """,
    "CREATE INDEX ix_security_decisions_task_id ON aegis.security_decisions (task_id)",
    """
    CREATE TABLE aegis.task_transition_rules (
        id smallint NOT NULL,
        from_state text NOT NULL,
        to_state text NOT NULL,
        action text,
        effect text,
        stage text,
        requires_job boolean NOT NULL,
        CONSTRAINT pk_task_transition_rules PRIMARY KEY (id),
        CONSTRAINT uq_task_transition_rules_rule UNIQUE NULLS NOT DISTINCT
            (from_state, to_state, action, effect, stage),
        CONSTRAINT ck_task_transition_rules_decision
            CHECK (num_nulls(action, effect, stage) IN (0, 3))
    )
    """,
    """
    INSERT INTO aegis.task_transition_rules
        (id, from_state, to_state, action, effect, stage, requires_job)
    VALUES
        (1, 'created', 'queued', 'task.submit', 'allow', 'policy', false),
        (2, 'created', 'awaiting_approval', 'task.submit', 'approval_required', 'policy', false),
        (3, 'awaiting_approval', 'cancelled', 'task.cancel', 'allow', 'authorization', false),
        (4, 'queued', 'running', 'task.execute', 'allow', 'policy', true),
        (5, 'queued', 'awaiting_approval', 'task.execute', 'approval_required', 'policy', true),
        (6, 'queued', 'failed', 'task.execute', 'deny', 'authorization', true),
        (7, 'queued', 'failed', 'task.execute', 'deny', 'policy', true),
        (8, 'queued', 'cancelled', 'task.cancel', 'allow', 'authorization', false),
        (9, 'running', 'succeeded', NULL, NULL, NULL, true),
        (10, 'running', 'failed', NULL, NULL, NULL, true),
        (11, 'running', 'cancelled', NULL, NULL, NULL, true),
        (12, 'running', 'interrupted', NULL, NULL, NULL, true),
        (13, 'interrupted', 'queued', NULL, NULL, NULL, true),
        (14, 'interrupted', 'failed', NULL, NULL, NULL, true),
        (15, 'interrupted', 'cancelled', 'task.cancel', 'allow', 'authorization', false)
    """,
    f"""
    CREATE TABLE aegis.task_state_transitions (
        task_id uuid NOT NULL,
        to_version integer NOT NULL,
        from_state text NOT NULL,
        to_state text NOT NULL,
        actor_id uuid NOT NULL,
        reason_code text NOT NULL,
        decision_id uuid,
        decision_action text,
        decision_effect text,
        decision_stage text,
        decision_decided_at timestamptz,
        job_id uuid,
        job_attempt integer,
        request_id text,
        occurred_at timestamptz NOT NULL DEFAULT now(),
        CONSTRAINT pk_task_state_transitions PRIMARY KEY (task_id, to_version),
        CONSTRAINT uq_task_state_transitions_decision_id UNIQUE (decision_id),
        CONSTRAINT fk_task_state_transitions_task_id_tasks
            FOREIGN KEY (task_id) REFERENCES aegis.tasks (id),
        CONSTRAINT fk_task_state_transitions_actor_id_identities
            FOREIGN KEY (actor_id) REFERENCES aegis.identities (id),
        CONSTRAINT fk_task_state_transitions_decision_id_security_decisions
            FOREIGN KEY (
                decision_id, task_id, decision_action, decision_effect, decision_stage,
                decision_decided_at
            )
            REFERENCES aegis.security_decisions (id, task_id, action, effect, stage, decided_at),
        CONSTRAINT ck_task_state_transitions_to_version CHECK (to_version >= 1),
        CONSTRAINT ck_task_state_transitions_decision CHECK (
            num_nulls(
                decision_id, decision_action, decision_effect, decision_stage, decision_decided_at
            ) IN (0, 5)
        ),
        CONSTRAINT ck_task_state_transitions_fresh_decision
            CHECK (decision_decided_at = occurred_at),
        CONSTRAINT ck_task_state_transitions_job
            CHECK ((job_id IS NULL) = (job_attempt IS NULL) AND job_attempt >= 1),
        CONSTRAINT ck_task_state_transitions_reason_code CHECK (reason_code ~ {CODE}),
        CONSTRAINT ck_task_state_transitions_request_id CHECK (request_id ~ {REQUEST_ID})
    )
    """,
    """
    CREATE FUNCTION aegis.append_only() RETURNS trigger
        LANGUAGE plpgsql SET search_path = pg_catalog AS $$
    BEGIN
        RAISE EXCEPTION 'aegis.% is append-only', TG_TABLE_NAME;
    END;
    $$
    """,
    """
    CREATE FUNCTION aegis.tasks_before_insert() RETURNS trigger
        LANGUAGE plpgsql SET search_path = pg_catalog AS $$
    BEGIN
        IF NEW.state <> 'created' OR NEW.version <> 0 THEN
            RAISE EXCEPTION 'tasks start in state created at version 0';
        END IF;
        IF num_nonnulls(NEW.cancel_requested_by, NEW.result, NEW.failure_code) > 0 THEN
            RAISE EXCEPTION 'a new task has no cancellation, result or failure';
        END IF;
        NEW.created_at := now();
        NEW.updated_at := now();
        RETURN NEW;
    END;
    $$
    """,
    """
    CREATE FUNCTION aegis.tasks_before_update() RETURNS trigger
        LANGUAGE plpgsql SET search_path = pg_catalog AS $$
    BEGIN
        IF (NEW.id, NEW.initiator_id, NEW.owner_id, NEW.submitted_credential_id, NEW.kind,
            NEW.input, NEW.idempotency_key, NEW.request_fingerprint, NEW.created_at)
            IS DISTINCT FROM
           (OLD.id, OLD.initiator_id, OLD.owner_id, OLD.submitted_credential_id, OLD.kind,
            OLD.input, OLD.idempotency_key, OLD.request_fingerprint, OLD.created_at) THEN
            RAISE EXCEPTION 'a task''s fixed columns cannot change';
        END IF;
        IF OLD.state IN ('succeeded', 'failed', 'cancelled') THEN
            RAISE EXCEPTION 'a task in a final state cannot change';
        END IF;
        IF OLD.cancel_requested_by IS NOT NULL THEN
            IF (NEW.cancel_requested_at, NEW.cancel_requested_by)
                IS DISTINCT FROM (OLD.cancel_requested_at, OLD.cancel_requested_by) THEN
                RAISE EXCEPTION 'a cancellation request cannot change';
            END IF;
        ELSIF NEW.cancel_requested_by IS NOT NULL THEN
            NEW.cancel_requested_at := now();
        END IF;
        IF NEW.state IS DISTINCT FROM OLD.state THEN
            IF NEW.version IS DISTINCT FROM OLD.version + 1 THEN
                RAISE EXCEPTION 'a state change must raise the version by exactly 1';
            END IF;
            IF NOT EXISTS (
                SELECT 1 FROM aegis.task_transition_rules r
                WHERE r.from_state = OLD.state AND r.to_state = NEW.state
            ) THEN
                RAISE EXCEPTION 'illegal task transition from % to %', OLD.state, NEW.state;
            END IF;
            IF OLD.state = 'running' AND NEW.state = 'cancelled'
                AND NEW.cancel_requested_by IS NULL THEN
                RAISE EXCEPTION 'a running task is cancelled only after a cancellation request';
            END IF;
            IF NOT EXISTS (
                SELECT 1 FROM aegis.task_state_transitions h
                WHERE h.task_id = NEW.id AND h.to_version = NEW.version
                    AND h.from_state = OLD.state AND h.to_state = NEW.state
                    AND h.occurred_at = now()
            ) THEN
                RAISE EXCEPTION 'a task state change needs its history row in the same transaction';
            END IF;
            IF NEW.state IN ('succeeded', 'failed', 'cancelled') THEN
                NEW.finished_at := now();
            END IF;
        ELSIF NEW.version IS DISTINCT FROM OLD.version THEN
            RAISE EXCEPTION 'the version changes only with the state';
        END IF;
        NEW.updated_at := now();
        RETURN NEW;
    END;
    $$
    """,
    """
    CREATE FUNCTION aegis.tasks_not_left_created() RETURNS trigger
        LANGUAGE plpgsql SET search_path = pg_catalog AS $$
    BEGIN
        IF EXISTS (SELECT 1 FROM aegis.tasks WHERE id = NEW.id AND state = 'created') THEN
            RAISE EXCEPTION 'a task cannot be committed in state created';
        END IF;
        RETURN NULL;
    END;
    $$
    """,
    """
    CREATE FUNCTION aegis.security_decisions_stamp() RETURNS trigger
        LANGUAGE plpgsql SET search_path = pg_catalog AS $$
    BEGIN
        NEW.decided_at := now();
        RETURN NEW;
    END;
    $$
    """,
    """
    CREATE FUNCTION aegis.task_state_transitions_before_insert() RETURNS trigger
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
    """,
    """
    CREATE FUNCTION aegis.task_state_transitions_applied() RETURNS trigger
        LANGUAGE plpgsql SET search_path = pg_catalog AS $$
    BEGIN
        IF NOT EXISTS (
            SELECT 1 FROM aegis.tasks t WHERE t.id = NEW.task_id AND t.version >= NEW.to_version
        ) THEN
            RAISE EXCEPTION 'history row for version % of task % has no state change',
                NEW.to_version, NEW.task_id;
        END IF;
        RETURN NULL;
    END;
    $$
    """,
    *(
        f"REVOKE ALL ON FUNCTION aegis.{function}() FROM PUBLIC"
        for function in (
            "append_only",
            "tasks_before_insert",
            "tasks_before_update",
            "tasks_not_left_created",
            "security_decisions_stamp",
            "task_state_transitions_before_insert",
            "task_state_transitions_applied",
        )
    ),
    "REVOKE ALL ON FUNCTION aegis.valid_reason_codes(text[]) FROM PUBLIC",
    "GRANT EXECUTE ON FUNCTION aegis.valid_reason_codes(text[]) TO aegis_app",
    "CREATE TRIGGER tasks_before_insert BEFORE INSERT ON aegis.tasks"
    " FOR EACH ROW EXECUTE FUNCTION aegis.tasks_before_insert()",
    "CREATE TRIGGER tasks_before_update BEFORE UPDATE ON aegis.tasks"
    " FOR EACH ROW EXECUTE FUNCTION aegis.tasks_before_update()",
    "CREATE TRIGGER tasks_no_delete BEFORE DELETE ON aegis.tasks"
    " FOR EACH ROW EXECUTE FUNCTION aegis.reject_delete()",
    "CREATE TRIGGER tasks_no_truncate BEFORE TRUNCATE ON aegis.tasks"
    " FOR EACH STATEMENT EXECUTE FUNCTION aegis.reject_delete()",
    "CREATE CONSTRAINT TRIGGER tasks_not_left_created AFTER INSERT ON aegis.tasks"
    " DEFERRABLE INITIALLY DEFERRED"
    " FOR EACH ROW EXECUTE FUNCTION aegis.tasks_not_left_created()",
    "CREATE TRIGGER security_decisions_stamp BEFORE INSERT ON aegis.security_decisions"
    " FOR EACH ROW EXECUTE FUNCTION aegis.security_decisions_stamp()",
    "CREATE TRIGGER security_decisions_append_only"
    " BEFORE UPDATE OR DELETE ON aegis.security_decisions"
    " FOR EACH ROW EXECUTE FUNCTION aegis.append_only()",
    "CREATE TRIGGER security_decisions_no_truncate BEFORE TRUNCATE ON aegis.security_decisions"
    " FOR EACH STATEMENT EXECUTE FUNCTION aegis.append_only()",
    "CREATE TRIGGER task_state_transitions_before_insert"
    " BEFORE INSERT ON aegis.task_state_transitions"
    " FOR EACH ROW EXECUTE FUNCTION aegis.task_state_transitions_before_insert()",
    "CREATE TRIGGER task_state_transitions_append_only"
    " BEFORE UPDATE OR DELETE ON aegis.task_state_transitions"
    " FOR EACH ROW EXECUTE FUNCTION aegis.append_only()",
    "CREATE TRIGGER task_state_transitions_no_truncate"
    " BEFORE TRUNCATE ON aegis.task_state_transitions"
    " FOR EACH STATEMENT EXECUTE FUNCTION aegis.append_only()",
    "CREATE CONSTRAINT TRIGGER task_state_transitions_applied"
    " AFTER INSERT ON aegis.task_state_transitions DEFERRABLE INITIALLY DEFERRED"
    " FOR EACH ROW EXECUTE FUNCTION aegis.task_state_transitions_applied()",
    "CREATE TRIGGER task_transition_rules_append_only"
    " BEFORE UPDATE OR DELETE ON aegis.task_transition_rules"
    " FOR EACH ROW EXECUTE FUNCTION aegis.append_only()",
    "CREATE TRIGGER task_transition_rules_no_truncate"
    " BEFORE TRUNCATE ON aegis.task_transition_rules"
    " FOR EACH STATEMENT EXECUTE FUNCTION aegis.append_only()",
    """
    ALTER TABLE aegis.audit_events ADD CONSTRAINT fk_audit_events_task_id_tasks
        FOREIGN KEY (task_id) REFERENCES aegis.tasks (id)
    """,
    """
    ALTER TABLE aegis.audit_events ADD CONSTRAINT fk_audit_events_decision_id_security_decisions
        FOREIGN KEY (decision_id) REFERENCES aegis.security_decisions (id)
    """,
    "REVOKE ALL ON aegis.tasks, aegis.security_decisions, aegis.task_transition_rules,"
    " aegis.task_state_transitions FROM PUBLIC",
    "GRANT SELECT ON aegis.tasks, aegis.security_decisions, aegis.task_transition_rules,"
    " aegis.task_state_transitions TO aegis_app",
    """
    GRANT INSERT (
        id, initiator_id, owner_id, submitted_credential_id, kind, input, idempotency_key,
        request_fingerprint
    ) ON aegis.tasks TO aegis_app
    """,
    "GRANT UPDATE (state, version, cancel_requested_by, result, failure_code)"
    " ON aegis.tasks TO aegis_app",
    """
    GRANT INSERT (
        id, actor_id, actor_kind, actor_credential_id, subject_id, action, resource_type,
        resource_id, resource_owner_id, task_id, effect, stage, reason_codes, policy_version,
        policy_digest, request_id, job_id, job_attempt
    ) ON aegis.security_decisions TO aegis_app
    """,
    """
    GRANT INSERT (
        task_id, to_version, from_state, to_state, actor_id, reason_code, decision_id,
        decision_action, decision_effect, decision_stage, decision_decided_at, job_id,
        job_attempt, request_id
    ) ON aegis.task_state_transitions TO aegis_app
    """,
)

DOWNGRADE = (
    "ALTER TABLE aegis.audit_events DROP CONSTRAINT fk_audit_events_decision_id_security_decisions",
    "ALTER TABLE aegis.audit_events DROP CONSTRAINT fk_audit_events_task_id_tasks",
    "DROP TABLE aegis.task_state_transitions",
    "DROP TABLE aegis.task_transition_rules",
    "DROP TABLE aegis.security_decisions",
    "DROP TABLE aegis.tasks",
    "DROP FUNCTION aegis.task_state_transitions_applied()",
    "DROP FUNCTION aegis.task_state_transitions_before_insert()",
    "DROP FUNCTION aegis.security_decisions_stamp()",
    "DROP FUNCTION aegis.tasks_not_left_created()",
    "DROP FUNCTION aegis.tasks_before_update()",
    "DROP FUNCTION aegis.tasks_before_insert()",
    "DROP FUNCTION aegis.append_only()",
    "DROP FUNCTION aegis.valid_reason_codes(text[])",
    "ALTER TABLE aegis.credentials DROP CONSTRAINT uq_credentials_id_identity_id",
    "ALTER TABLE aegis.identities DROP CONSTRAINT uq_identities_id_kind",
)


def upgrade() -> None:
    for statement in UPGRADE:
        op.execute(statement)


def downgrade() -> None:
    for statement in DOWNGRADE:
        op.execute(statement)
