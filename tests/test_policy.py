from db_agent.policy import decide_tool_call


def test_allows_read_tool():
    decision = decide_tool_call(
        tool_name="get_finding_context",
        tool_args={"finding_id": 2},
        input_trust="user",
        security_flags=[],
    )

    assert decision.decision == "allow"
    assert decision.rule_id == "POL-READ-ALLOW"


def test_blocks_unknown_tool():
    decision = decide_tool_call(
        tool_name="run_shell",
        tool_args={"command": "whoami"},
        input_trust="user",
        security_flags=[],
    )

    assert decision.decision == "block"
    assert decision.rule_id == "POL-UNKNOWN-TOOL"


def test_write_tool_requires_approval():
    decision = decide_tool_call(
        tool_name="update_finding_status",
        tool_args={"finding_id": 2, "status": "closed"},
        input_trust="user",
        security_flags=[],
    )

    assert decision.decision == "require_approval"
    assert decision.rule_id == "POL-WRITE-REQUIRES-APPROVAL"


def test_suspicious_content_cannot_authorize_write():
    decision = decide_tool_call(
        tool_name="update_finding_status",
        tool_args={"finding_id": 9001, "status": "closed"},
        input_trust="database_record",
        security_flags=["suspicious_instruction_like_content"],
    )

    assert decision.decision == "block"
    assert decision.rule_id == "POL-UNTRUSTED-INSTRUCTION-WRITE"


def test_destructive_tool_blocked():
    decision = decide_tool_call(
        tool_name="delete_evidence",
        tool_args={"evidence_id": 2},
        input_trust="user",
        security_flags=[],
    )

    assert decision.decision == "block"
    assert decision.rule_id == "POL-DESTRUCTIVE-BLOCK"