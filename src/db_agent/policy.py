from dataclasses import dataclass
from typing import Any


@dataclass
class ToolPolicy:
    tool_name: str
    description: str
    access_type: str
    consequence: str
    default_decision: str


@dataclass
class PolicyDecision:
    decision: str
    reason: str
    rule_id: str


TOOL_POLICIES: dict[str, ToolPolicy] = {
    "risk_summary": ToolPolicy(
        tool_name="risk_summary",
        description="Read aggregate finding counts by risk and status.",
        access_type="read",
        consequence="low",
        default_decision="allow",
    ),
    "list_open_findings": ToolPolicy(
        tool_name="list_open_findings",
        description="Read open findings, optionally filtered by risk.",
        access_type="read",
        consequence="low",
        default_decision="allow",
    ),
    "get_finding_context": ToolPolicy(
        tool_name="get_finding_context",
        description="Read one finding with project, assessable, test case, and evidence context.",
        access_type="read",
        consequence="medium",
        default_decision="allow",
    ),

    # Future tools. We define them now so the gateway has a security posture.
    "update_finding_status": ToolPolicy(
        tool_name="update_finding_status",
        description="Update a finding status.",
        access_type="write",
        consequence="high",
        default_decision="require_approval",
    ),
    "send_report": ToolPolicy(
        tool_name="send_report",
        description="Send a report externally.",
        access_type="external_write",
        consequence="high",
        default_decision="require_approval",
    ),
    "delete_evidence": ToolPolicy(
        tool_name="delete_evidence",
        description="Delete evidence from a finding.",
        access_type="destructive_write",
        consequence="critical",
        default_decision="block",
    ),

    "fetch_vendor_note": ToolPolicy(
        tool_name="fetch_vendor_note",
        description="Fetch a note from an external vendor-style tool.",
        access_type="read",
        consequence="medium",
        default_decision="allow",
    ),
}


def decide_tool_call(
    tool_name: str,
    tool_args: dict[str, Any] | None = None,
    input_trust: str = "user",
    security_flags: list[str] | None = None,
) -> PolicyDecision:
    """
    Decide whether a proposed tool call should be allowed.

    This is intentionally simple for now. Later, this becomes the agent-tool
    enforcement layer.
    """
    tool_args = tool_args or {}
    security_flags = security_flags or []

    policy = TOOL_POLICIES.get(tool_name)

    if policy is None:
        return PolicyDecision(
            decision="block",
            reason=f"Unknown tool is not allowed: {tool_name}",
            rule_id="POL-UNKNOWN-TOOL",
        )

    if policy.access_type in {"destructive_write"}:
        return PolicyDecision(
            decision="block",
            reason="Destructive tool calls are blocked by default.",
            rule_id="POL-DESTRUCTIVE-BLOCK",
        )

    if policy.access_type == "external_write" and has_suspicious_recipient(tool_args):
        return PolicyDecision(
            decision="block",
            reason="Potential data exfiltration recipient detected.",
            rule_id="POL-EXFILTRATION-BLOCK",
        )

    if security_flags and policy.access_type != "read":
        return PolicyDecision(
            decision="block",
            reason="Instruction-like content cannot authorize write or external actions.",
            rule_id="POL-UNTRUSTED-INSTRUCTION-WRITE",
        )

    if policy.access_type in {"write", "external_write"}:
        return PolicyDecision(
            decision="require_approval",
            reason="High-consequence write or external action requires human approval.",
            rule_id="POL-WRITE-REQUIRES-APPROVAL",
        )

    if policy.access_type == "read":
        return PolicyDecision(
            decision="allow",
            reason="Read-only tool call allowed.",
            rule_id="POL-READ-ALLOW",
        )

    return PolicyDecision(
        decision=policy.default_decision,
        reason="Default policy decision applied.",
        rule_id="POL-DEFAULT",
    )

def has_suspicious_recipient(tool_args: dict[str, Any]) -> bool:
    recipient = (
        tool_args.get("to")
        or tool_args.get("recipient")
        or tool_args.get("email")
        or ""
    )

    recipient = str(recipient).lower()

    suspicious_markers = [
        "attacker@",
        "evil.",
        "exfil",
        "leak",
    ]

    return any(marker in recipient for marker in suspicious_markers)
