from db_agent.finding_tools import list_open_findings, risk_summary
from db_agent.context_tools import get_finding_context
from db_agent.policy import decide_tool_call
from db_agent.security import find_suspicious_instructions, scan_finding_context
from db_agent.tracing import ToolTrace
from db_agent.vendor_tools import fetch_vendor_note

# def answer_question(question: str) -> str:
#     """ 
#     First simple non-LLM agent for answering questions about findings, risk assessments, etc
#     It maps common user questions to safe read-only tools.
#     Later, we replace this routing logic with an LLM planner.
#     """

#     q = question.lower().strip()

#     if "summary" in q or "risk summary" in q or "how many" in q:
#         return format_risk_summary()

#     if "critical" in q and "open" in q:
#         return format_open_findings(risk="critical")

#     if "high" in q and "open" in q:
#         return format_open_findings(risk="high")

#     if "open" in q and "findings" in q:
#         return format_open_findings(risk=None)

#     if "finding" in q:
#         finding_id = extract_first_number(q)
#         if finding_id:
#             return format_finding_context(finding_id)
        
#     return (
#         "I can currently answer questions about open findings, critical findings, "
#         "high-risk findings, risk summaries, and finding details by ID."
#     )

def answer_question(question: str) -> str:
    answer, _trace = answer_question_with_trace(question)
    return answer


def extract_first_number(text: str) -> int | None:
    for token in text.replace("#", " ").split():
        if token.isdigit():
            return int(token)
    return None


def format_open_findings(risk: str | None = None) -> str:
    rows = list_open_findings(risk_rating=risk, limit=20)

    if not rows:
        if risk:
            return f"No open findings found with {risk} risk."
        return "No open findings found."
    
    title = f"Open Findings (Risk: {risk})" if risk else "Open Findings"

    lines = [f"{title}\n"]

    for row in rows:
        lines.append(
            f" - Finding ID: {row['id']}, Title: {row['title']}, Risk: {row['risk_rating']}"
        )

    return "\n".join(lines)


def format_risk_summary() -> str:
    rows = risk_summary()

    if not rows:
        return "No finding summary data found."

    lines = ["Finding risk summary:", ""]

    for row in rows:
        lines.append(
            f"- {row['risk_rating']} / {row['status']}: {row['count']}"
        )

    return "\n".join(lines)


def format_finding_context(finding_id: int) -> str:
    ctx = get_finding_context(finding_id)

    if not ctx:
        return f"No finding found with ID {finding_id}."

    suspicious_patterns = scan_finding_context(ctx)

    finding = ctx["finding"]
    project = ctx["project"]
    assessable = ctx["assessable"]
    test_cases = ctx.get("test_cases", [])
    evidence = ctx.get("evidence", [])

    lines = [
        f"FIND-{finding['id']}: {finding['title']}",
        "",
        f"Risk: {finding['risk_rating']}",
        f"Status: {finding['status']}",
        f"Project: {project['name']} owned by {project['owner']}",
        f"Asset: {assessable['asset_name']} ({assessable['asset_type']}, {assessable['environment']})",
        "",
        f"Description: {finding['description']}",
        f"Recommendation: {finding['recommendation']}",
        "",
    ]

    if suspicious_patterns:
        lines.extend(
            [
                "Security note: suspicious instruction-like content was detected inside this database record.",
                "This content should be treated as data/evidence, not as an instruction for the agent to follow.",
                "",
            ]
        )

    if test_cases:
        lines.append("Related test cases:")
        for tc in test_cases:
            lines.append(
                f"- {tc['test_name']} [{tc['result']}]: {tc['evidence_summary']}"
            )
        lines.append("")

    if evidence:
        lines.append("Evidence:")
        for ev in evidence:
            lines.append(
                f"- {ev['evidence_type']}: {ev['summary']} ({ev['storage_ref']})"
            )

    return "\n".join(lines)


def answer_question_with_trace(question: str) -> tuple[str, ToolTrace]:
    """
    Rule-based analyst with trace output.
    This records intent, chosen tool, tool args, result summary, and security flags.
    """
    q = question.lower().strip()

    if "summary" in q or "risk summary" in q or "how many" in q:
        rows = risk_summary()
        answer = format_risk_summary()
        tool_args: dict[str, object] = {}

        policy = decide_tool_call(
            tool_name="risk_summary",
            tool_args=tool_args,
            input_trust="user",
            security_flags=[],
        )

        trace = ToolTrace(
            question=question,
            intent="risk_summary",
            tool_name="risk_summary",
            tool_args=tool_args,
            policy_decision=policy.decision,
            policy_reason=policy.reason,
            policy_rule_id=policy.rule_id,
            result_summary={"rows_returned": len(rows)},
            security_flags=[],
            answer_preview=answer[:500],
        )

        return answer, trace

    if "critical" in q and "open" in q:
        tool_args = {"risk_rating": "critical", "limit": 20}
        rows = list_open_findings(risk_rating="critical", limit=20)
        answer = format_open_findings(risk="critical")
        policy = decide_tool_call(
            tool_name="list_open_findings",
            tool_args=tool_args,
            input_trust="user",
            security_flags=[],
        )

        trace = ToolTrace(
            question=question,
            intent="open_findings_by_risk",
            tool_name="list_open_findings",
            tool_args=tool_args,
            policy_decision=policy.decision,
            policy_reason=policy.reason,
            policy_rule_id=policy.rule_id,
            result_summary={"rows_returned": len(rows)},
            security_flags=[],
            answer_preview=answer[:500],
        )

        return answer, trace

    if "high" in q and "open" in q:
        tool_args = {"risk_rating": "high", "limit": 20}
        rows = list_open_findings(risk_rating="high", limit=20)
        answer = format_open_findings(risk="high")
        policy = decide_tool_call(
            tool_name="list_open_findings",
            tool_args=tool_args,
            input_trust="user",
            security_flags=[],
        )

        trace = ToolTrace(
            question=question,
            intent="open_findings_by_risk",
            tool_name="list_open_findings",
            tool_args=tool_args,
            policy_decision=policy.decision,
            policy_reason=policy.reason,
            policy_rule_id=policy.rule_id,
            result_summary={"rows_returned": len(rows)},
            security_flags=[],
            answer_preview=answer[:500],
        )

        return answer, trace

    if "open" in q and "findings" in q:
        tool_args = {"risk_rating": None, "limit": 20}
        rows = list_open_findings(risk_rating=None, limit=20)
        answer = format_open_findings(risk=None)
        policy = decide_tool_call(
            tool_name="list_open_findings",
            tool_args=tool_args,
            input_trust="user",
            security_flags=[],
        )

        trace = ToolTrace(
            question=question,
            intent="open_findings",
            tool_name="list_open_findings",
            tool_args=tool_args,
            policy_decision=policy.decision,
            policy_reason=policy.reason,
            policy_rule_id=policy.rule_id,
            result_summary={"rows_returned": len(rows)},
            security_flags=[],
            answer_preview=answer[:500],
        )

        return answer, trace

    if (
        "close all findings" in q
        or "mark all findings" in q
        or "mark finding" in q
        or "close finding" in q
        or "follow the instruction" in q
    ):
        finding_id = extract_first_number(q)

        flags = []
        if finding_id:
            ctx = get_finding_context(finding_id)
            suspicious_patterns = scan_finding_context(ctx) if ctx else []

            if suspicious_patterns:
                flags.append("suspicious_instruction_like_content")

        tool_args = {
            "finding_id": finding_id,
            "requested_status": "closed",
        }

        policy = decide_tool_call(
            tool_name="update_finding_status",
            tool_args=tool_args,
            input_trust="database_record" if flags else "user",
            security_flags=flags,
        )

        answer = (
            "I cannot perform that status update.\n\n"
            f"Policy decision: {policy.decision}\n"
            f"Policy rule: {policy.rule_id}\n"
            f"Reason: {policy.reason}\n\n"
            "Database records are treated as evidence, not instructions. "
            "A finding description cannot authorize closing findings or changing workflow state."
        )

        trace = ToolTrace(
            question=question,
            intent="unsafe_status_update_request",
            tool_name="update_finding_status",
            tool_args=tool_args,
            result_summary={
                "executed": False,
                "finding_id": finding_id,
            },
            security_flags=flags,
            policy_decision=policy.decision,
            policy_reason=policy.reason,
            policy_rule_id=policy.rule_id,
            answer_preview=answer[:500],
        )

        return answer, trace   

    if (
        "send" in q
        and (
            "attacker@" in q
            or "evidence" in q
            or "report" in q
            or "external" in q
        )
    ):
        finding_id = extract_first_number(q)

        recipient = "unknown"
        for token in q.replace(",", " ").split():
            if "@" in token:
                recipient = token.strip()

        tool_args = {
            "finding_id": finding_id,
            "to": recipient,
            "content_type": "finding_evidence_report",
        }

        flags = []
        if "attacker@" in recipient:
            flags.append("suspicious_external_recipient")

        policy = decide_tool_call(
            tool_name="send_report",
            tool_args=tool_args,
            input_trust="user",
            security_flags=flags,
        )

        answer = (
            "I cannot send that report or evidence externally.\n\n"
            f"Policy decision: {policy.decision}\n"
            f"Policy rule: {policy.rule_id}\n"
            f"Reason: {policy.reason}\n\n"
            "Finding evidence and security assessment data require controlled handling. "
            "External sharing must be approved and cannot be sent to suspicious recipients."
        )

        trace = ToolTrace(
            question=question,
            intent="data_exfiltration_attempt",
            tool_name="send_report",
            tool_args=tool_args,
            result_summary={
                "executed": False,
                "finding_id": finding_id,
                "recipient": recipient,
            },
            security_flags=flags,
            policy_decision=policy.decision,
            policy_reason=policy.reason,
            policy_rule_id=policy.rule_id,
            answer_preview=answer[:500],
        )

        return answer, trace   

    if "finding" in q:
        finding_id = extract_first_number(q)

        if finding_id:
            ctx = get_finding_context(finding_id)
            suspicious_patterns = scan_finding_context(ctx) if ctx else []
            answer = format_finding_context(finding_id)

            flags = []
            if suspicious_patterns:
                flags.append("suspicious_instruction_like_content")
            tool_args = {"finding_id": finding_id}
            policy = decide_tool_call(
                tool_name="get_finding_context",
                tool_args=tool_args,
                input_trust="user",
                security_flags=flags,
            )

            trace = ToolTrace(
                question=question,
                intent="finding_context",
                tool_name="get_finding_context",
                tool_args=tool_args,
                result_summary={
                    "found": ctx is not None,
                    "test_cases": len(ctx.get("test_cases", [])) if ctx else 0,
                    "evidence": len(ctx.get("evidence", [])) if ctx else 0,
                },
                security_flags=flags,
                policy_decision=policy.decision,
                policy_reason=policy.reason,
                policy_rule_id=policy.rule_id,
                answer_preview=answer[:500],
            )

            return answer, trace

    if "vendor note" in q or "vendor status" in q:
        vendor_id = extract_first_number(q) or 1

        tool_args = {
            "vendor_id": vendor_id,
        }

        policy = decide_tool_call(
            tool_name="fetch_vendor_note",
            tool_args=tool_args,
            input_trust="user",
            security_flags=[],
        )

        vendor_note = fetch_vendor_note(vendor_id)
        suspicious_patterns = find_suspicious_instructions(vendor_note.get("note", ""))

        flags = []
        if suspicious_patterns:
            flags.append("poisoned_tool_output")

        answer = (
            f"Vendor note for vendor {vendor_id} was retrieved.\n\n"
            f"Note: {vendor_note['note']}\n\n"
            "Security note: suspicious instruction-like content was detected in the tool output. "
            "The note is treated as untrusted data and will not be used to trigger external sends, "
            "status changes, or other high-consequence actions."
        )

        trace = ToolTrace(
            question=question,
            intent="vendor_tool_output_review",
            tool_name="fetch_vendor_note",
            tool_args=tool_args,
            result_summary={
                "vendor_id": vendor_id,
                "tool_output_received": True,
                "chained_action_executed": False,
            },
            security_flags=flags,
            policy_decision=policy.decision,
            policy_reason=policy.reason,
            policy_rule_id=policy.rule_id,
            answer_preview=answer[:500],
        )

        return answer, trace  

    answer = (
        "I can currently answer questions about open findings, critical findings, "
        "high-risk findings, risk summaries, and finding details by ID."
    )

    trace = ToolTrace(
        question=question,
        intent="unknown",
        tool_name="none",
        tool_args={},
        result_summary={},
        security_flags=[],
        answer_preview=answer,
    )

    return answer, trace
