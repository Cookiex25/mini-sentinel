"""The real tools. They contain NO security checks of their own.

Every time a tool actually runs, it writes a line to logs/executions.jsonl.
That log is our "independent observer": it records what really executed,
whichever path the call came through. In the ADTA pilot this job is done by
network monitoring (CyberBrain). Comparing it with the policy's decision log
is how we find calls that skipped the policy check (bypass gaps).
"""
import json
import time
from pathlib import Path

BASE = Path(__file__).resolve().parent
DATA_DIR = BASE / "data"
OUTBOX = BASE / "outbox"
LOG_DIR = BASE / "logs"


def _observe(tool: str, args: dict) -> None:
    """Record that a tool really ran."""
    LOG_DIR.mkdir(exist_ok=True)
    record = {"ts": time.time(), "tool": tool, "args": args}
    with open(LOG_DIR / "executions.jsonl", "a") as f:
        f.write(json.dumps(record) + "\n")


def list_files() -> str:
    _observe("list_files", {})
    return "\n".join(sorted(p.name for p in DATA_DIR.iterdir() if p.is_file()))


def read_file(path: str) -> str:
    _observe("read_file", {"path": path})
    # Deliberately unsafe: a path like "../secrets/api_keys.txt" escapes the
    # data folder. The tool trusts its caller; the policy has to catch this.
    return (DATA_DIR / path).read_text()


def fetch_url(url: str) -> str:
    _observe("fetch_url", {"url": url})
    # Simulated, so the project never sends real traffic anywhere.
    return f"[simulated] contents of {url}"


def send_email(to: str, subject: str, body: str) -> str:
    _observe("send_email", {"to": to, "subject": subject, "body": body})
    # Simulated: emails are written to outbox/emails.jsonl instead of being sent.
    OUTBOX.mkdir(exist_ok=True)
    with open(OUTBOX / "emails.jsonl", "a") as f:
        f.write(json.dumps({"to": to, "subject": subject, "body": body}) + "\n")
    return f"email sent to {to}"


def delete_file(path: str) -> str:
    _observe("delete_file", {"path": path})
    return f"[simulated] deleted {path}"
