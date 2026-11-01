from alembic import op

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | None = None
depends_on: str | None = None

UPGRADE = (
    """
    CREATE TABLE aegis.identities (
        id uuid NOT NULL,
        kind text NOT NULL,
        name text NOT NULL,
        status text NOT NULL DEFAULT 'active',
        created_at timestamptz NOT NULL DEFAULT now(),
        created_by uuid,
        disabled_at timestamptz,
        CONSTRAINT pk_identities PRIMARY KEY (id),
        CONSTRAINT uq_identities_name UNIQUE (name),
        CONSTRAINT fk_identities_created_by_identities
            FOREIGN KEY (created_by) REFERENCES aegis.identities (id),
        CONSTRAINT ck_identities_kind CHECK (kind IN ('human', 'service', 'system')),
        CONSTRAINT ck_identities_name CHECK (
            name ~ '^[a-z0-9][a-z0-9._:-]{0,62}$' AND (kind = 'system') = (name LIKE 'system:%')
        ),
        CONSTRAINT ck_identities_status CHECK (status IN ('active', 'disabled')),
        CONSTRAINT ck_identities_disabled_at
            CHECK ((status = 'disabled') = (disabled_at IS NOT NULL))
    )
    """,
    """
    CREATE TABLE aegis.identity_roles (
        identity_id uuid NOT NULL,
        role text NOT NULL,
        granted_at timestamptz NOT NULL DEFAULT now(),
        granted_by uuid NOT NULL,
        CONSTRAINT pk_identity_roles PRIMARY KEY (identity_id, role),
        CONSTRAINT fk_identity_roles_identity_id_identities
            FOREIGN KEY (identity_id) REFERENCES aegis.identities (id),
        CONSTRAINT fk_identity_roles_granted_by_identities
            FOREIGN KEY (granted_by) REFERENCES aegis.identities (id),
        CONSTRAINT ck_identity_roles_role CHECK (role IN ('admin', 'operator', 'auditor', 'worker'))
    )
    """,
    """
    CREATE TABLE aegis.credentials (
        id uuid NOT NULL,
        identity_id uuid NOT NULL,
        lookup_id text NOT NULL,
        secret_hash bytea NOT NULL,
        hash_scheme text NOT NULL,
        description text,
        created_at timestamptz NOT NULL DEFAULT now(),
        created_by uuid NOT NULL,
        expires_at timestamptz NOT NULL,
        revoked_at timestamptz,
        revoked_by uuid,
        CONSTRAINT pk_credentials PRIMARY KEY (id),
        CONSTRAINT uq_credentials_lookup_id UNIQUE (lookup_id),
        CONSTRAINT fk_credentials_identity_id_identities
            FOREIGN KEY (identity_id) REFERENCES aegis.identities (id),
        CONSTRAINT fk_credentials_created_by_identities
            FOREIGN KEY (created_by) REFERENCES aegis.identities (id),
        CONSTRAINT fk_credentials_revoked_by_identities
            FOREIGN KEY (revoked_by) REFERENCES aegis.identities (id),
        CONSTRAINT ck_credentials_lookup_id CHECK (lookup_id ~ '^[a-z2-7]{26}$'),
        CONSTRAINT ck_credentials_secret_hash CHECK (octet_length(secret_hash) = 32),
        CONSTRAINT ck_credentials_hash_scheme CHECK (hash_scheme IN ('hmac-sha256-v1')),
        CONSTRAINT ck_credentials_description CHECK (length(description) BETWEEN 1 AND 200),
        CONSTRAINT ck_credentials_lifetime CHECK (
            expires_at > created_at AND expires_at <= created_at + interval '90 days'
        ),
        CONSTRAINT ck_credentials_revoked CHECK ((revoked_at IS NULL) = (revoked_by IS NULL))
    )
    """,
    "CREATE INDEX ix_credentials_identity_id ON aegis.credentials (identity_id)",
    """
    CREATE FUNCTION aegis.reject_delete() RETURNS trigger
        LANGUAGE plpgsql SET search_path = pg_catalog AS $$
    BEGIN
        RAISE EXCEPTION 'rows in aegis.% are never deleted', TG_TABLE_NAME;
    END;
    $$
    """,
    """
    CREATE FUNCTION aegis.identities_guard_update() RETURNS trigger
        LANGUAGE plpgsql SET search_path = pg_catalog AS $$
    BEGIN
        IF (NEW.id, NEW.kind, NEW.name, NEW.created_at, NEW.created_by)
            IS DISTINCT FROM (OLD.id, OLD.kind, OLD.name, OLD.created_at, OLD.created_by) THEN
            RAISE EXCEPTION 'only an identity''s status can change';
        END IF;
        RETURN NEW;
    END;
    $$
    """,
    """
    CREATE FUNCTION aegis.identity_roles_check_kind() RETURNS trigger
        LANGUAGE plpgsql SET search_path = pg_catalog AS $$
    DECLARE
        identity_kind text;
    BEGIN
        SELECT kind INTO identity_kind FROM aegis.identities WHERE id = NEW.identity_id;
        IF (identity_kind = 'system') <> (NEW.role = 'worker') THEN
            RAISE EXCEPTION 'role % cannot be held by a % identity', NEW.role, identity_kind;
        END IF;
        RETURN NEW;
    END;
    $$
    """,
    """
    CREATE FUNCTION aegis.credentials_before_insert() RETURNS trigger
        LANGUAGE plpgsql SET search_path = pg_catalog AS $$
    BEGIN
        IF (SELECT kind FROM aegis.identities WHERE id = NEW.identity_id) = 'system' THEN
            RAISE EXCEPTION 'system identities cannot hold credentials';
        END IF;
        NEW.created_at := now();
        RETURN NEW;
    END;
    $$
    """,
    """
    CREATE FUNCTION aegis.credentials_guard_update() RETURNS trigger
        LANGUAGE plpgsql SET search_path = pg_catalog AS $$
    BEGIN
        IF (NEW.id, NEW.identity_id, NEW.lookup_id, NEW.secret_hash, NEW.hash_scheme,
            NEW.description, NEW.created_at, NEW.created_by, NEW.expires_at)
            IS DISTINCT FROM
           (OLD.id, OLD.identity_id, OLD.lookup_id, OLD.secret_hash, OLD.hash_scheme,
            OLD.description, OLD.created_at, OLD.created_by, OLD.expires_at) THEN
            RAISE EXCEPTION 'credentials can only be revoked';
        END IF;
        IF OLD.revoked_at IS NOT NULL THEN
            RAISE EXCEPTION 'a revoked credential cannot be changed';
        END IF;
        RETURN NEW;
    END;
    $$
    """,
    *(
        f"REVOKE ALL ON FUNCTION aegis.{function}() FROM PUBLIC"
        for function in (
            "reject_delete",
            "identities_guard_update",
            "identity_roles_check_kind",
            "credentials_before_insert",
            "credentials_guard_update",
        )
    ),
    "CREATE TRIGGER identities_no_delete BEFORE DELETE ON aegis.identities"
    " FOR EACH ROW EXECUTE FUNCTION aegis.reject_delete()",
    "CREATE TRIGGER identities_no_truncate BEFORE TRUNCATE ON aegis.identities"
    " FOR EACH STATEMENT EXECUTE FUNCTION aegis.reject_delete()",
    "CREATE TRIGGER identities_guard_update BEFORE UPDATE ON aegis.identities"
    " FOR EACH ROW EXECUTE FUNCTION aegis.identities_guard_update()",
    "CREATE TRIGGER identity_roles_check_kind BEFORE INSERT OR UPDATE ON aegis.identity_roles"
    " FOR EACH ROW EXECUTE FUNCTION aegis.identity_roles_check_kind()",
    "CREATE TRIGGER credentials_before_insert BEFORE INSERT ON aegis.credentials"
    " FOR EACH ROW EXECUTE FUNCTION aegis.credentials_before_insert()",
    "CREATE TRIGGER credentials_guard_update BEFORE UPDATE ON aegis.credentials"
    " FOR EACH ROW EXECUTE FUNCTION aegis.credentials_guard_update()",
    "CREATE TRIGGER credentials_no_delete BEFORE DELETE ON aegis.credentials"
    " FOR EACH ROW EXECUTE FUNCTION aegis.reject_delete()",
    "CREATE TRIGGER credentials_no_truncate BEFORE TRUNCATE ON aegis.credentials"
    " FOR EACH STATEMENT EXECUTE FUNCTION aegis.reject_delete()",
    """
    INSERT INTO aegis.identities (id, kind, name) VALUES
        ('00000000-0000-4000-8000-000000000001', 'system', 'system:worker'),
        ('00000000-0000-4000-8000-000000000002', 'system', 'system:cli')
    """,
    """
    INSERT INTO aegis.identity_roles (identity_id, role, granted_by) VALUES
        ('00000000-0000-4000-8000-000000000001', 'worker', '00000000-0000-4000-8000-000000000002')
    """,
    "REVOKE ALL ON aegis.identities, aegis.identity_roles, aegis.credentials FROM PUBLIC",
    "GRANT SELECT ON aegis.identities, aegis.identity_roles, aegis.credentials TO aegis_app",
    """
    ALTER TABLE aegis.audit_events ADD CONSTRAINT fk_audit_events_actor_id_identities
        FOREIGN KEY (actor_id) REFERENCES aegis.identities (id)
    """,
)

DOWNGRADE = (
    "ALTER TABLE aegis.audit_events DROP CONSTRAINT fk_audit_events_actor_id_identities",
    "DROP TABLE aegis.credentials",
    "DROP TABLE aegis.identity_roles",
    "DROP TABLE aegis.identities",
    "DROP FUNCTION aegis.credentials_guard_update()",
    "DROP FUNCTION aegis.credentials_before_insert()",
    "DROP FUNCTION aegis.identity_roles_check_kind()",
    "DROP FUNCTION aegis.identities_guard_update()",
    "DROP FUNCTION aegis.reject_delete()",
)


def upgrade() -> None:
    for statement in UPGRADE:
        op.execute(statement)


def downgrade() -> None:
    for statement in DOWNGRADE:
        op.execute(statement)
