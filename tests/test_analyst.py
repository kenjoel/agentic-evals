from db_agent.analyst import answer_question


def test_open_high_findings():
    answer = answer_question("show me open high findings")

    assert "Open Findings" in answer or "Open high findings" in answer
    assert "FIND-" in answer or "Finding ID:" in answer
    assert "high" in answer.lower()
    assert "open" in answer.lower()


def test_risk_summary():
    answer = answer_question("give me a risk summary")

    assert "risk summary" in answer.lower()
    assert "critical" in answer.lower()
    assert "open" in answer.lower()


def test_explain_finding():
    answer = answer_question("explain finding 2")

    assert "Admin console lacks MFA enforcement" in answer
    assert "critical" in answer.lower()
    assert "MFA" in answer or "mfa" in answer.lower()