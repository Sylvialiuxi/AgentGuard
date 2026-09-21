import os
from pathlib import Path


# ============================================================
# AgentGuard runtime configuration
# ============================================================
#
# All LLM-backed defenses are optional. When no API key is
# available (or AGENTGUARD_LLM_DEFENSE=0), AgentGuard falls
# back to the deterministic rule engine and behaves exactly
# as before. This keeps the Streamlit demo runnable offline.


def _load_dotenv() -> None:
    """
    Minimal .env loader (no dependency). Existing environment
    variables always win over the file.
    """

    env_path = Path(__file__).resolve().parents[1] / ".env"

    if not env_path.exists():
        return

    for line in env_path.read_text(encoding="utf-8").splitlines():

        line = line.strip()

        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")

        os.environ.setdefault(key, value)


_load_dotenv()


def _env_flag(name: str, default: bool) -> bool:
    raw = os.environ.get(name)

    if raw is None:
        return default

    return raw.strip().lower() in {"1", "true", "yes", "on"}


# ------------------------------------------------------------
# Master switch
# ------------------------------------------------------------

LLM_DEFENSE_ENABLED = _env_flag("AGENTGUARD_LLM_DEFENSE", True)

# Real tool-using agent core (Phase 3). Independent of the
# defense layers so you can run a real agent with rules-only
# defense, or a simulated agent with LLM defense.
LLM_AGENT_ENABLED = _env_flag("AGENTGUARD_LLM_AGENT", True)

# Red-team switch. With this on, the agent runs without the clause
# that tells it to distrust file contents - the standard assumption
# behind every prompt-injection defence, made testable.
#
# It weakens the agent, never AgentGuard: the guard sees exactly the
# same calls and applies exactly the same policy. That is the point,
# and it is the only way to observe the later layers, because a
# well-behaved model refuses the redirect long before they run.
UNSAFE_AGENT = _env_flag("AGENTGUARD_UNSAFE_AGENT", False)

API_KEY = os.environ.get("ANTHROPIC_API_KEY")


# ------------------------------------------------------------
# Models
# ------------------------------------------------------------

# High-volume classifier / reviewer work runs on a small model.
JUDGE_MODEL = os.environ.get(
    "AGENTGUARD_JUDGE_MODEL",
    "claude-haiku-4-5",
)

# The real tool-using agent core (Phase 3).
AGENT_MODEL = os.environ.get(
    "AGENTGUARD_AGENT_MODEL",
    "claude-opus-5",
)


# ------------------------------------------------------------
# Timeouts and limits
# ------------------------------------------------------------

JUDGE_TIMEOUT_SECONDS = float(
    os.environ.get("AGENTGUARD_JUDGE_TIMEOUT", "20")
)

JUDGE_MAX_TOKENS = 1024

# Agent core
AGENT_TIMEOUT_SECONDS = float(
    os.environ.get("AGENTGUARD_AGENT_TIMEOUT", "60")
)

AGENT_MAX_TOKENS = 8000

AGENT_EFFORT = os.environ.get("AGENTGUARD_AGENT_EFFORT", "low")

# Hard cap on agent<->tool round trips per run.
AGENT_MAX_TURNS = int(os.environ.get("AGENTGUARD_AGENT_MAX_TURNS", "6"))

# Untrusted content larger than this is truncated before being
# sent to the classifier (defense inputs should be small).
JUDGE_MAX_INPUT_CHARS = 12000


# ------------------------------------------------------------
# Fail-closed behaviour
# ------------------------------------------------------------
#
# When an LLM defense call fails (timeout, network, unparseable
# response), AgentGuard must not silently allow the action.
# FAIL_CLOSED_SCORE is fed into the policy engine in that case.

FAIL_CLOSED = _env_flag("AGENTGUARD_FAIL_CLOSED", True)

FAIL_CLOSED_SCORE = 100


# ------------------------------------------------------------
# Score merging
# ------------------------------------------------------------
#
# The final risk score is the strongest signal from any layer.
# "max" is intentionally conservative; "avg" is available for
# experimentation.

SCORE_MERGE_STRATEGY = os.environ.get(
    "AGENTGUARD_SCORE_MERGE",
    "max",
)


def merge_scores(*scores: int) -> int:
    """
    Combine risk scores from multiple detection layers.
    """

    values = [
        int(score)
        for score in scores
        if score is not None
    ]

    if not values:
        return 0

    if SCORE_MERGE_STRATEGY == "avg":
        return min(int(sum(values) / len(values)), 100)

    return min(max(values), 100)


def llm_defense_active() -> bool:
    """
    True only when LLM defenses are both enabled and usable.
    """

    return bool(LLM_DEFENSE_ENABLED and API_KEY)


def llm_agent_active() -> bool:
    """
    True only when the real LLM agent core is enabled and usable.
    """

    return bool(LLM_AGENT_ENABLED and API_KEY)
