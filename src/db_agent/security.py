import re


SUSPICIOUS_INSTRUCTION_PATTERNS = [
    r"ignore (all )?(previous|prior|above) instructions",
    r"disregard (all )?(previous|prior|above) instructions",
    r"mark .* as closed",
    r"mark .* as resolved",
    r"send .* to .*@",
    r"reveal .* secret",
    r"exfiltrate",
    r"delete .* evidence",
    r"disable .* policy",
    r"always approve",
]


def find_suspicious_instructions(text: str) -> list[str]:
    if not text:
        return []

    matches = []

    for pattern in SUSPICIOUS_INSTRUCTION_PATTERNS:
        if re.search(pattern, text.lower()):
            matches.append(pattern)

    return matches


def scan_finding_context(ctx: dict | None) -> list[str]:
    """
    Scan finding/project/test/evidence text for instruction-like content.
    This does not prove maliciousness. It flags content that should be treated
    as data, not executable instruction.
    """
    if not ctx:
        return []

    text_parts = []

    finding = ctx.get("finding", {})
    for key in ["title", "description", "recommendation"]:
        if finding.get(key):
            text_parts.append(str(finding[key]))

    for tc in ctx.get("test_cases", []):
        for key in ["domain", "test_name", "result", "evidence_summary"]:
            if tc.get(key):
                text_parts.append(str(tc[key]))

    for ev in ctx.get("evidence", []):
        for key in ["evidence_type", "storage_ref", "summary"]:
            if ev.get(key):
                text_parts.append(str(ev[key]))

    combined = "\n".join(text_parts)
    return find_suspicious_instructions(combined)
