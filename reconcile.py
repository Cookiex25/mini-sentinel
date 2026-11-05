"""Find bypass gaps by comparing two independent records.

  logs/decisions.jsonl  - what the policy engine decided (allow / redact / block)
  logs/executions.jsonl - what actually ran (our stand-in for network telemetry)

Any execution with no matching allow or redact decision just before it ran
reached the tool without passing the policy check. That is a bypass gap.
"""
import json
from pathlib import Path

LOG_DIR = Path(__file__).resolve().parent / "logs"


def _read(name: str) -> list[dict]:
    path = LOG_DIR / name
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def find_gaps(window_seconds: float = 10.0) -> list[dict]:
    approved = [d for d in _read("decisions.jsonl") if d["decision"] in ("allow", "redact")]
    matched: set[int] = set()
    gaps = []
    for execution in _read("executions.jsonl"):
        match = next(
            (
                i
                for i, d in enumerate(approved)
                if i not in matched
                and d["tool"] == execution["tool"]
                and d["args"] == execution["args"]
                and 0 <= execution["ts"] - d["ts"] <= window_seconds
            ),
            None,
        )
        if match is None:
            gaps.append(execution)
        else:
            matched.add(match)
    return gaps


if __name__ == "__main__":
    gaps = find_gaps()
    print(f"{len(gaps)} execution(s) with no matching policy decision:")
    for gap in gaps:
        print(f"  GAP: {gap['tool']} {gap['args']}")
