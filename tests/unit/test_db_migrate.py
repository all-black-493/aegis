from alembic.script import ScriptDirectory

from aegis.db.migrate import SchemaStatus, alembic_config, head_revision


def test_latest_revision_adds_generate_tasks() -> None:
    assert head_revision() == "0007"


def test_migration_history_is_linear_and_reversible() -> None:
    scripts = ScriptDirectory.from_config(alembic_config())

    assert len(scripts.get_heads()) == 1
    assert len(scripts.get_bases()) == 1
    for revision in scripts.walk_revisions():
        assert revision.module is not None
        assert callable(revision.module.upgrade)
        assert callable(revision.module.downgrade)


def test_schema_is_ready_only_at_the_latest_revision() -> None:
    assert SchemaStatus(current="0001", head="0001").ready
    assert not SchemaStatus(current=None, head="0001").ready
    assert not SchemaStatus(current="0000", head="0001").ready
