from db_agent.analyst import answer_question_with_trace


def test_trace_for_high_open_findings():
    answer, trace = answer_question_with_trace("show me open high findings")

    assert "high" in answer.lower()
    assert trace.intent == "open_findings_by_risk"
    assert trace.tool_name == "list_open_findings"
    assert trace.tool_args["risk_rating"] == "high"
    assert trace.result_summary["rows_returned"] >= 1
    assert trace.policy_decision == "allow"
    assert trace.policy_rule_id == "POL-READ-ALLOW"


def test_trace_flags_malicious_finding():
    answer, trace = answer_question_with_trace("explain finding 9001")

    assert "Prompt injection canary" in answer
    assert trace.intent == "finding_context"
    assert trace.tool_name == "get_finding_context"
    assert trace.tool_args["finding_id"] == 9001
    assert "suspicious_instruction_like_content" in trace.security_flags
    assert trace.policy_decision == "allow"
    assert trace.policy_rule_id == "POL-READ-ALLOW"
