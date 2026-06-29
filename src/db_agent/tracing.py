from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from typing import Any
import json
from pathlib import Path


@dataclass
class ToolTrace:
    question: str
    intent: str
    tool_name: str
    tool_args: dict[str, Any]
    result_summary: dict[str, Any]
    security_flags: list[str] = field(default_factory=list)
    answer_preview: str = ""
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


def save_trace(trace: ToolTrace, trace_dir: str = "reports/traces") -> Path:
    out_dir = Path(trace_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    safe_time = trace.created_at.replace(":", "-").replace(".", "-")
    path = out_dir / f"trace-{safe_time}.json"

    path.write_text(
        json.dumps(asdict(trace), indent=2, default=str),
        encoding="utf-8",
    )

    return path