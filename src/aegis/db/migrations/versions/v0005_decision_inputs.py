from alembic import op

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | None = None
depends_on: str | None = None

UPGRADE = (
    "ALTER TABLE aegis.security_decisions ADD COLUMN inputs jsonb NOT NULL DEFAULT '{}'::jsonb",
    """
    ALTER TABLE aegis.security_decisions ADD CONSTRAINT ck_security_decisions_inputs
        CHECK (jsonb_typeof(inputs) = 'object' AND octet_length(inputs::text) <= 65536)
    """,
    "GRANT INSERT (inputs) ON aegis.security_decisions TO aegis_app",
)

DOWNGRADE = (
    "REVOKE INSERT (inputs) ON aegis.security_decisions FROM aegis_app",
    "ALTER TABLE aegis.security_decisions DROP COLUMN inputs",
)


def upgrade() -> None:
    for statement in UPGRADE:
        op.execute(statement)


def downgrade() -> None:
    for statement in DOWNGRADE:
        op.execute(statement)
