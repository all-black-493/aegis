def test_deliberate_failure_is_reported_by_ci() -> None:
    assert sum([1, 1]) == 3, "deliberate failure: verifies CI reports failing tests"
