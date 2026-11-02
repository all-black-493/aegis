from alembic import op

revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | None = None
depends_on: str | None = None

UPGRADE = (
    "ALTER TABLE aegis.tasks DROP CONSTRAINT ck_tasks_kind",
    "ALTER TABLE aegis.tasks ADD CONSTRAINT ck_tasks_kind"
    " CHECK (kind IN ('noop', 'wait', 'generate'))",
)

# Development only (ADR-0003). Refused while a generate task is unfinished. Finished ones are kept
# as history: terminal tasks never change, and NOT VALID applies the old rule to every new row.
DOWNGRADE = (
    """
    DO $$
    BEGIN
        IF EXISTS (
            SELECT 1 FROM aegis.tasks WHERE kind = 'generate' AND finished_at IS NULL
        ) THEN
            RAISE EXCEPTION 'unfinished generate tasks exist; let them finish or cancel them';
        END IF;
    END
    $$
    """,
    "ALTER TABLE aegis.tasks DROP CONSTRAINT ck_tasks_kind",
    "ALTER TABLE aegis.tasks ADD CONSTRAINT ck_tasks_kind"
    " CHECK (kind IN ('noop', 'wait')) NOT VALID",
)


def upgrade() -> None:
    for statement in UPGRADE:
        op.execute(statement)


def downgrade() -> None:
    for statement in DOWNGRADE:
        op.execute(statement)
