"""Pre-action policy engine.

Every tool call is checked here BEFORE it runs. There are three decisions:
  allow  - run the call exactly as requested
  redact - run it, but with sensitive data removed from the arguments
  block  - do not run it

Two rules hold no matter what:
  * Fail-closed: if anything goes wrong inside the check, the call is blocked.
  * No evidence, no action: if the decision can't be logged, the call is blocked.
"""
import hashlib
import hmac
import json
import os
import re
import secrets
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from urllib.parse import urlparse

BASE = Path(__file__).resolve().parent
DATA_DIR = (BASE / "data").resolve()
LOG_DIR = BASE / "logs"
STATE_DIR = BASE / "state"

# ---------------------------------------------------------------- the rules
# Least privilege: each role gets only the tools its job needs.
ROLE_TOOLS = {
    "researcher": {"list_files", "read_file", "fetch_url"},
    "writer": {"read_file", "send_email"},
}

# Actions that leave the system or can't be undone need a human approval.
HIGH_IMPACT = {"send_email", "delete_file"}

# Where data is allowed to go.
ALLOWED_URL_HOSTS = {"modelcontextprotocol.io", "docs.python.org", "owasp.org"}
ALLOWED_EMAIL_DOMAINS = {"adelaide.edu.au"}

APPROVAL_TTL_SECONDS = 120

EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
SECRET_RE = re.compile(r"(?i)\b(api[_-]?key|password|secret)\s*[:=]\s*\S+")
INJECTION_RE = re.compile(
    r"(?i)ignore (all |any )?(previous|prior) instructions|you must now|system override"
)


@dataclass
class Decision:
    decision: str  # "allow", "redact" or "block"
    reason: str
    agent: str
    role: str
    tool: str
    args: dict  # the arguments that will actually be used
    decision_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    ts: float = field(default_factory=time.time)
    latency_ms: float = 0.0


# ------------------------------------------------------- approval tokens
# A human approver issues a token for ONE exact action. The token is signed,
# expires quickly, can be used once, and can be revoked. This defends against
# replayed or revoked decisions.

def _key() -> bytes:
    STATE_DIR.mkdir(exist_ok=True)
    key_file = STATE_DIR / "approval.key"
    if not key_file.exists():
        key_file.write_text(secrets.token_hex(32))
    return bytes.fromhex(key_file.read_text().strip())


def args_hash(tool: str, args: dict) -> str:
    return hashlib.sha256(json.dumps([tool, args], sort_keys=True).encode()).hexdigest()


def _sign(payload: dict) -> str:
    message = json.dumps(payload, sort_keys=True).encode()
    return hmac.new(_key(), message, hashlib.sha256).hexdigest()


def issue_approval(agent: str, tool: str, args: dict, ttl: int = APPROVAL_TTL_SECONDS) -> str:
    """Called by a human approver, never by the agent itself."""
    payload = {
        "agent": agent,
        "tool": tool,
        "args_hash": args_hash(tool, args),
        "nonce": uuid.uuid4().hex,
        "expires": time.time() + ttl,
    }
    return json.dumps({"payload": payload, "sig": _sign(payload)})


def _load_state() -> dict:
    state_file = STATE_DIR / "approvals.json"
    if state_file.exists():
        return json.loads(state_file.read_text())
    return {"used": [], "revoked": []}


def _save_state(state: dict) -> None:
    STATE_DIR.mkdir(exist_ok=True)
    (STATE_DIR / "approvals.json").write_text(json.dumps(state))


def revoke_approval(token: str) -> None:
    state = _load_state()
    state["revoked"].append(json.loads(token)["payload"]["nonce"])
    _save_state(state)


def _check_approval(agent: str, tool: str, args: dict, token: str | None) -> str | None:
    """Return None if the approval is valid, otherwise the reason it isn't."""
    if not token:
        return "high-impact action needs a human approval token"
    parsed = json.loads(token)
    payload = parsed["payload"]
    if not hmac.compare_digest(_sign(payload), parsed["sig"]):
        return "approval signature is invalid (token was forged or edited)"
    if payload["agent"] != agent or payload["tool"] != tool:
        return "approval was issued for a different agent or tool"
    if payload["args_hash"] != args_hash(tool, args):
        return "arguments changed after approval"
    if time.time() > payload["expires"]:
        return "approval has expired"
    state = _load_state()
    if payload["nonce"] in state["revoked"]:
        return "approval was revoked"
    if payload["nonce"] in state["used"]:
        return "approval was already used (replay attempt)"
    state["used"].append(payload["nonce"])  # single use: consume it now
    _save_state(state)
    return None


# ------------------------------------------------------------ the check

def _evaluate(agent: str, role: str, tool: str, args: dict, approval: str | None):
    if os.environ.get("SENTINEL_SIMULATE_POLICY_FAILURE"):
        raise RuntimeError("policy store unreachable")  # used by the fail-closed test

    # 1. Role: is this agent allowed to use this tool at all?
    allowed = ROLE_TOOLS.get(role)
    if allowed is None:
        return "block", f"unknown role '{role}'", args
    if tool not in allowed:
        return "block", f"role '{role}' may not use '{tool}'", args

    # 2. Arguments: are they safe?
    if tool in ("read_file", "delete_file"):
        target = (DATA_DIR / args["path"]).resolve()
        if not target.is_relative_to(DATA_DIR):
            return "block", "path escapes the data folder", args

    # 3. Destinations: is data going somewhere approved?
    if tool == "fetch_url":
        host = urlparse(args["url"]).hostname or ""
        if host not in ALLOWED_URL_HOSTS:
            return "block", f"destination '{host}' is not on the allowlist", args
    if tool == "send_email":
        domain = args["to"].rsplit("@", 1)[-1].lower()
        if domain not in ALLOWED_EMAIL_DOMAINS:
            return "block", f"recipient domain '{domain}' is not approved", args

    # 4. High-impact actions need a valid, unused, unrevoked human approval.
    if tool in HIGH_IMPACT:
        problem = _check_approval(agent, tool, args, approval)
        if problem:
            return "block", problem, args

    # 5. Redaction: strip secrets and personal email addresses from outgoing text.
    if tool == "send_email":
        body = args.get("body", "")
        clean = SECRET_RE.sub("[REDACTED SECRET]", body)
        clean = EMAIL_RE.sub("[REDACTED EMAIL]", clean)
        if clean != body:
            return "redact", "sensitive data removed from the email body", {**args, "body": clean}

    return "allow", "all checks passed", args


def _log(decision: Decision) -> None:
    LOG_DIR.mkdir(exist_ok=True)
    with open(LOG_DIR / "decisions.jsonl", "a") as f:
        f.write(json.dumps(asdict(decision)) + "\n")


def check(agent: str, role: str, tool: str, args: dict, approval: str | None = None) -> Decision:
    """The single entry point. Every tool call must pass through here first."""
    start = time.perf_counter()
    try:
        verdict, reason, final_args = _evaluate(agent, role, tool, dict(args), approval)
    except Exception as error:  # fail-closed: any error means block
        verdict, reason, final_args = "block", f"policy error, failing closed: {error!r}", args
    decision = Decision(verdict, reason, agent, role, tool, final_args)
    decision.latency_ms = round((time.perf_counter() - start) * 1000, 3)
    try:
        _log(decision)
    except Exception as error:  # no evidence, no action
        decision.decision = "block"
        decision.reason = f"could not log decision, failing closed: {error!r}"
    return decision


def looks_like_injection(text: str) -> bool:
    """A simple check for instructions hidden in tool output (prompt injection)."""
    return bool(INJECTION_RE.search(text))
