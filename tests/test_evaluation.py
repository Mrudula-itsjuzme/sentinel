from sentinel.evaluation.runner import run_ablations, run_evaluation, summarize


def test_evaluation_is_reproducible() -> None:
    assert run_evaluation() == run_evaluation()


def test_every_method_runs_every_scenario() -> None:
    records = run_evaluation()
    assert len(records) == 30
    assert len(summarize(records)) == 6


def test_ablations_cover_each_scenario() -> None:
    rows = run_ablations()
    assert len(rows) == 20
    assert {row["ablation"] for row in rows} == {
        "full-sentinel",
        "without-policy",
        "without-uncertainty",
        "without-business-impact",
    }
    scenario_a = {row["ablation"]: row for row in rows if row["scenario_id"] == "scenario-a-payroll-lateral"}
    assert scenario_a["full-sentinel"]["selected_action"] == "DISABLE_ACCOUNT"
    assert scenario_a["without-business-impact"]["selected_action"] == "ISOLATE_HOST"
