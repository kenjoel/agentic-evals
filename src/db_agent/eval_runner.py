from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from db_agent.analyst import answer_question_with_trace


@dataclass
class EvalResult:
    eval_id: str
    name: str
    question: str
    passed: bool
    failures: list[str] = field(default_factory=list)
    answer_preview: str = ""
    intent: str = ""
    tool_name: str = ""


def load_eval_cases(path: str | Path = "evals/analyst_evals.yaml") -> list[dict[str, Any]]:
    eval_path = Path(path)

    if not eval_path.exists():
        raise FileNotFoundError(f"Eval file not found: {eval_path}")

    with eval_path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    return data or []


def run_eval_case(case: dict[str, Any]) -> EvalResult:
    eval_id = case["id"]
    name = case.get("name", eval_id)
    question = case["question"]
    expected = case.get("expected", {})

    answer, trace = answer_question_with_trace(question)
    failures = []

    expected_intent = expected.get("intent")
    if expected_intent and trace.intent != expected_intent:
        failures.append(f"Expected intent={expected_intent}, got {trace.intent}")

    expected_tool = expected.get("tool_name")
    if expected_tool and trace.tool_name != expected_tool:
        failures.append(f"Expected tool_name={expected_tool}, got {trace.tool_name}")

    for phrase in expected.get("contains", []):
        if phrase.lower() not in answer.lower():
            failures.append(f"Answer missing expected phrase: {phrase}")

    for phrase in expected.get("not_contains", []):
        if phrase.lower() in answer.lower():
            failures.append(f"Answer contains forbidden phrase: {phrase}")

    for flag in expected.get("security_flags", []):
        if flag not in trace.security_flags:
            failures.append(f"Missing expected security flag: {flag}")

    expected_args = expected.get("tool_args", {})
    for key, value in expected_args.items():
        actual = trace.tool_args.get(key)
        if actual != value:
            failures.append(f"Expected tool_args[{key}]={value}, got {actual}")

    min_rows = expected.get("min_rows_returned")
    if min_rows is not None:
        actual_rows = trace.result_summary.get("rows_returned", 0)
        if actual_rows < min_rows:
            failures.append(f"Expected at least {min_rows} rows, got {actual_rows}")

    expected_policy_decision = expected.get("policy_decision")
    if expected_policy_decision and trace.policy_decision != expected_policy_decision:
        failures.append(
            f"Expected policy_decision={expected_policy_decision}, got {trace.policy_decision}"
        )

    expected_policy_rule = expected.get("policy_rule_id")
    if expected_policy_rule and trace.policy_rule_id != expected_policy_rule:
        failures.append(
            f"Expected policy_rule_id={expected_policy_rule}, got {trace.policy_rule_id}"
        )

    return EvalResult(
        eval_id=eval_id,
        name=name,
        question=question,
        passed=not failures,
        failures=failures,
        answer_preview=answer[:300],
        intent=trace.intent,
        tool_name=trace.tool_name,
    )


def run_eval_suite(path: str | Path = "evals/analyst_evals.yaml") -> list[EvalResult]:
    cases = load_eval_cases(path)
    return [run_eval_case(case) for case in cases]
