from alembic import op

revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: str | None = None
depends_on: str | None = None

UPGRADE = (
    "ALTER TABLE aegis.tasks DROP CONSTRAINT ck_tasks_kind",
    "ALTER TABLE aegis.tasks ADD CONSTRAINT ck_tasks_kind"
    " CHECK (kind IN ('noop', 'wait', 'generate', 'enforcement_check'))",
)

# Development only (ADR-0003), as in 0007: refused while an enforcement_check task is unfinished,
# and finished ones are kept as history under a NOT VALID constraint.
DOWNGRADE = (
    """
    DO $$
    BEGIN
        IF EXISTS (
            SELECT 1 FROM aegis.tasks WHERE kind = 'enforcement_check' AND finished_at IS NULL
        ) THEN
            RAISE EXCEPTION
                'unfinished enforcement_check tasks exist; let them finish or cancel them';
        END IF;
    END
    $$
    """,
    "ALTER TABLE aegis.tasks DROP CONSTRAINT ck_tasks_kind",
    "ALTER TABLE aegis.tasks ADD CONSTRAINT ck_tasks_kind"
    " CHECK (kind IN ('noop', 'wait', 'generate')) NOT VALID",
)


def upgrade() -> None:
    for statement in UPGRADE:
        op.execute(statement)


def downgrade() -> None:
    for statement in DOWNGRADE:
        op.execute(statement)
