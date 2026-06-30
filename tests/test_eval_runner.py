from db_agent.eval_runner import run_eval_suite


def test_analyst_eval_suite_passes():
    results = run_eval_suite("evals/analyst_evals.yaml")

    assert results
    assert all(result.passed for result in results)