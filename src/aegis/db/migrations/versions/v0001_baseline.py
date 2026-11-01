from alembic import op

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.execute("GRANT USAGE ON SCHEMA aegis TO aegis_app")
    op.execute("GRANT SELECT ON aegis.alembic_version TO aegis_app")


def downgrade() -> None:
    op.execute("REVOKE SELECT ON aegis.alembic_version FROM aegis_app")
    op.execute("REVOKE USAGE ON SCHEMA aegis FROM aegis_app")
