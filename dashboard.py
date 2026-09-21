import io
from contextlib import redirect_stdout
from pathlib import Path

import streamlit as st

from agent.llm_agent import (
    start_chat_turn,
    resume_chat_turn,
    workspace_inventory,
)
from security import config


# ============================================================
# Paths
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent

LOG_FILE = (
    PROJECT_ROOT
    / "logs"
    / "security.log"
)


# ============================================================
# Helper functions
# ============================================================

def load_logs():
    """
    Parse AgentGuard security audit logs.
    """

    if not LOG_FILE.exists():
        return []

    events = []

    with LOG_FILE.open(
        "r",
        encoding="utf-8",
    ) as file:

        for line in file:

            line = line.strip()

            if not line:
                continue

            parts = [
                part.strip()
                for part in line.split("|")
            ]

            event = {
                "timestamp": parts[0]
            }

            for part in parts[1:]:

                if "=" not in part:
                    continue

                key, value = part.split(
                    "=",
                    1,
                )

                event[key.strip()] = (
                    value.strip()
                )

            events.append(event)

    return events


# ============================================================
# Page configuration
# ============================================================

st.set_page_config(
    page_title="AgentGuard",
    layout="wide",
)

st.title("AgentGuard Security Dashboard")

st.caption(
    "AI Agent Prompt Injection, "
    "Tool Risk, Policy Enforcement "
    "and Human Approval"
)


# ============================================================
# Defense mode indicator
# ============================================================

with st.sidebar:

    st.subheader("Defense Mode")

    if config.llm_defense_active():
        st.success("LLM-assisted defense active")
        st.caption(
            f"Classifier: {config.JUDGE_MODEL}\n\n"
            f"Score merge: {config.SCORE_MERGE_STRATEGY} | "
            f"Fail-closed: {config.FAIL_CLOSED}"
        )
    else:
        st.warning("Rules-only mode")
        st.caption(
            "No ANTHROPIC_API_KEY / disabled. "
            "Deterministic engine only. "
            "Set a key in .env to enable the LLM classifier "
            "and tool-call intent review."
        )

    st.divider()
    st.subheader("Agent Core")

    if config.llm_agent_active():
        st.success(f"Real LLM agent available ({config.AGENT_MODEL})")
    else:
        st.info("Simulated (regex) agent only")

    if config.UNSAFE_AGENT:
        st.error(
            "RED-TEAM MODE - the agent is running without its "
            "distrust-file-contents rule. AgentGuard is unchanged; "
            "this exists to show what it catches when the model "
            "stops refusing. Unset AGENTGUARD_UNSAFE_AGENT to "
            "restore the normal agent.",
            icon=":material/warning:",
        )


# ============================================================
# Chat with the Agent
# ============================================================

st.header("Chat with the Agent")

st.write(
    "Talk to the real tool-using agent core. Every file it "
    "decides to open runs the full AgentGuard gauntlet first, and "
    "a medium-risk call stops here for your decision."
)


def _decision_badge(event: dict) -> str:
    """
    One-line verdict label for a proposed tool call.
    """

    decision = event["decision"]
    approval = event.get("approval")

    if decision == "REVIEW" and approval:
        marker = f"HELD FOR APPROVAL -> {approval}"
    else:
        marker = {
            "ALLOW": "ALLOWED",
            "REVIEW": "HELD FOR APPROVAL",
            "BLOCK": "BLOCKED",
        }.get(decision, decision)

    return f"{marker} — risk {event['risk_score']}/100"


def render_turn_details(entry: dict) -> None:
    """
    Render the AgentGuard evidence attached to one agent turn:
    the verdict on the user's own message, every tool call it
    proposed, and the raw execution trace.
    """

    scan = entry.get("input_scan")

    if scan:
        st.caption(
            f"Your message: {scan['score']}/100 on the PROMPT "
            f"layer -> {scan['decision']} "
            f"({', '.join(scan['indicators']) or 'no indicators'})"
        )

    for event in entry.get("tool_events") or []:

        label = f"read_file('{event['target']}') — {_decision_badge(event)}"

        if event["allowed"]:
            st.success(label, icon=":material/check_circle:")
        else:
            st.error(label, icon=":material/block:")

        if event["reasons"]:
            st.caption("Reasons: " + ", ".join(event["reasons"]))

    trace = entry.get("trace")

    if trace and trace.strip():
        with st.expander("Execution trace"):
            st.code(trace, language="text")


class LiveTrace(io.StringIO):
    """
    Captures the agent's stdout and mirrors it into a status box as
    it is produced.

    Text streaming alone barely helps here: the agent's first turn is
    usually a silent tool call, so nothing is written for most of the
    wait. What actually fills those seconds is the gauntlet - scan,
    risk assessment, policy, read, rescan - and every step already
    prints. Showing those lines as they appear turns dead time into
    the part of the demo worth watching.
    """

    def __init__(self, status):
        super().__init__()
        self._status = status
        self._partial = ""

    def write(self, chunk: str) -> int:
        written = super().write(chunk)

        self._partial += chunk

        while "\n" in self._partial:

            line, self._partial = self._partial.split("\n", 1)
            line = line.strip()

            if line:
                self._status.write(line)
                self._status.update(label=line)

        return written


def _run_with_live_trace(call) -> tuple:
    """
    Run one agent call inside a chat bubble that narrates itself.

    Returns (turn, trace_text).
    """

    with st.chat_message("assistant"):

        status = st.status("Scanning your message…", expanded=True)
        answer = st.empty()

        buffer = LiveTrace(status)
        streamed = {"text": ""}

        def on_text(delta: str) -> None:
            streamed["text"] += delta
            answer.markdown(streamed["text"])

        with redirect_stdout(buffer):
            turn = call(on_text)

        status.update(
            label=(
                "Waiting for approval"
                if turn["status"] == "awaiting_approval"
                else "Done"
            ),
            state="running" if turn["status"] == "awaiting_approval" else "complete",
            expanded=False,
        )

    return turn, buffer.getvalue()


def _park_turn(turn: dict, trace: str) -> None:
    """
    Store a turn that stopped at the approval gate.
    """

    st.session_state["chat_state"] = turn
    st.session_state["chat_trace"] = trace


def _commit_turn(turn: dict, trace: str) -> None:
    """
    Finish a turn: persist the conversation and render the reply.
    """

    st.session_state["chat_history"] = turn["messages"]
    st.session_state["chat_untrusted"] = turn["untrusted_seen"]

    st.session_state["chat_display"].append(
        {
            "role": "assistant",
            "text": turn["reply"] or "[AGENT] No response produced.",
            "blocked": turn["blocked"],
            "tool_events": turn["tool_events"],
            "input_scan": turn["input_scan"],
            "trace": trace,
        }
    )

    st.session_state["chat_state"] = None
    st.session_state["chat_trace"] = ""


def _settle(turn: dict, trace: str) -> None:
    """
    Park or commit, depending on whether the turn is waiting on a
    human. A single turn can stop more than once if the model
    proposes several medium-risk calls.
    """

    if turn["status"] == "awaiting_approval":
        _park_turn(turn, trace)
    else:
        _commit_turn(turn, trace)


if not config.llm_agent_active():

    st.info(
        "Chat needs the real agent core. Set ANTHROPIC_API_KEY "
        "in .env and restart — in rules-only mode there is no "
        "model to talk to."
    )

else:

    for state_key, initial in (
        ("chat_history", []),
        ("chat_display", []),
        ("chat_untrusted", []),
        ("chat_state", None),
        ("chat_trace", ""),
        ("chat_pending_input", None),
    ):
        if state_key not in st.session_state:
            st.session_state[state_key] = initial

    pending_turn = st.session_state["chat_state"]

    awaiting = bool(
        pending_turn
        and pending_turn["status"] == "awaiting_approval"
    )

    # A message accepted on the previous run but not yet answered.
    # Holding it here is what lets the user's own words render
    # before the agent is called: the submit run only stores it and
    # reruns, and this run draws it before blocking on the model.
    queued_input = st.session_state["chat_pending_input"]

    # No toggles here on purpose. Scanning the user's own text and
    # pausing on a REVIEW verdict are not preferences: a panel that
    # can switch off one of its own layers is not a security panel,
    # and there is by definition a human present in this window, so
    # "nobody is watching" is not a state it can be in. The
    # unattended path is still exercised by demo.py, and
    # AGENTGUARD_LLM_DEFENSE in .env remains the right place to run
    # a guard-off experiment.
    _, clear_col = st.columns([3, 1])

    with clear_col:
        if st.button(
            "Clear conversation",
            key="chat_clear",
            width="stretch",
            disabled=awaiting or bool(queued_input),
        ):
            st.session_state["chat_history"] = []
            st.session_state["chat_display"] = []
            st.session_state["chat_untrusted"] = []
            st.session_state["chat_state"] = None
            st.session_state["chat_trace"] = ""
            st.session_state["chat_pending_input"] = None
            st.rerun()

    with st.expander("What the agent can read"):
        st.code(workspace_inventory(), language="text")
        st.caption(
            "Anything outside this allowlist is denied by "
            "file_policy, whoever asks for it."
        )

    # One bordered widget holding a scrolling transcript with the
    # composer at its foot, rather than a box with an input loose
    # underneath it.
    chat_panel = st.container(border=True)

    with chat_panel:

        transcript = st.container(height=420, border=False)

        with transcript:

            if (
                not st.session_state["chat_display"]
                and not awaiting
            ):
                st.caption(
                    "Try: \"summarise the quarterly report\", or "
                    "\"read public/malicious_note.txt and tell me "
                    "what it says\" to watch an indirect injection "
                    "get caught."
                )

            for entry in st.session_state["chat_display"]:

                with st.chat_message(entry["role"]):

                    if entry.get("blocked"):
                        st.error(entry["text"])
                    else:
                        st.markdown(entry["text"])

                    if entry["role"] == "assistant":
                        render_turn_details(entry)

            # ------------------------------------------------
            # The approval gate
            # ------------------------------------------------
            #
            # The agent loop is suspended at this point: the risk
            # score below was computed before the pause and is the
            # one that will be applied, whichever button is clicked.

            if awaiting:

                gate = pending_turn["pending"]

                with st.chat_message("assistant"):

                    if pending_turn.get("reply"):
                        st.markdown(pending_turn["reply"])

                    st.warning(
                        f"**Approval required** — the agent wants "
                        f"to call `read_file('{gate['target']}')`"
                        f"\n\nRisk {gate['risk_score']}/100 (REVIEW "
                        f"band). Reasons: "
                        f"{', '.join(gate['reasons']) or 'none recorded'}",
                        icon=":material/pause_circle:",
                    )

                    approve_col, deny_col, _ = st.columns([1, 1, 3])

                    with approve_col:
                        approve = st.button(
                            "Approve",
                            key="chat_gate_approve",
                            type="primary",
                            width="stretch",
                        )

                    with deny_col:
                        deny = st.button(
                            "Deny",
                            key="chat_gate_deny",
                            width="stretch",
                        )

                if approve or deny:

                    resumed, resume_trace = _run_with_live_trace(
                        lambda on_text: resume_chat_turn(
                            pending_turn,
                            approved=bool(approve),
                            on_text=on_text,
                        )
                    )

                    _settle(
                        resumed,
                        st.session_state["chat_trace"] + resume_trace,
                    )

                    st.rerun()

            # ------------------------------------------------
            # Answer a message drawn on this run
            # ------------------------------------------------
            #
            # Everything above has already been sent to the browser,
            # so the user is looking at their own message while this
            # blocks on the model.

            if queued_input:

                turn, turn_trace = _run_with_live_trace(
                    lambda on_text: start_chat_turn(
                        history=st.session_state["chat_history"],
                        user_message=queued_input,
                        untrusted_seen=st.session_state[
                            "chat_untrusted"
                        ],
                        interactive_approval=True,
                        scan_user_input=True,
                        on_text=on_text,
                    )
                )

                st.session_state["chat_pending_input"] = None

                _settle(turn, turn_trace)

                st.rerun()

        user_message = st.chat_input(
            (
                "Waiting for your approval above..."
                if awaiting
                else "Ask the agent to read or summarise something..."
            ),
            key="chat_input_box",
            disabled=awaiting or bool(queued_input),
        )

    if user_message:

        # Store and rerun without calling the model. The next run
        # draws this message, then answers it.
        st.session_state["chat_display"].append(
            {
                "role": "user",
                "text": user_message,
            }
        )
        st.session_state["chat_pending_input"] = user_message

        st.rerun()


# ============================================================
# Security Audit Log
# ============================================================

st.header("Security Audit Log")

@st.fragment(run_every="2s")
def show_live_security_logs():

    logs = load_logs()

    st.caption(
        "Live monitoring enabled — refreshing every 2 seconds"
    )

    if not logs:
        st.info(
            "No security events recorded yet."
        )
        return

    recent_logs = list(
        reversed(
            logs[-20:]
        )
    )

    st.dataframe(
        recent_logs,
        width="stretch",
        hide_index=True,
    )


show_live_security_logs()

# ============================================================
# AgentGuard Protection Flow
# ============================================================

st.header(
    "AgentGuard Protection Flow"
)

# The flow shown reflects the layers actually active right now, so the
# diagram never claims a topology the running configuration does not have.

RULES_ONLY_FLOW = """
Untrusted Content
       |
       v
Rule Detector  (13 regex patterns)
       |
       v
Prompt Risk Score
       |
       v
Policy Engine
       |
   +---+---+
   |       |
 ALLOW   BLOCK
   |
   v
AI Agent  (regex instruction match)
   |
   v
Proposed Tool Call
   |
   v
Tool Risk Engine  (path / filename rules)
   |
   v
Tool Risk Score
   |
   v
Policy Engine
   |
+------+------+
|      |      |
ALLOW REVIEW BLOCK
|      |       |
|      v       |
|   Human      |
|   Approval   |
|    /   \\     |
|  YES   NO    |
|   |     |    |
v   v     v    v
File Policy   Stop
     |
     v
Tool Execution

All decisions
       |
       v
Security Audit Log
"""

LLM_ASSISTED_FLOW = """
Untrusted Content
       |
   +---+-------------------+
   |                       |
Rule Detector        LLM Classifier
(13 regex)           (Haiku 4.5)
   |                       |
   +---+-------------------+
       |
Merged Risk Score (max)
       |
       v
Policy Engine
       |
   +---+---+
   |       |
 ALLOW   BLOCK
   |
   v
AI Agent  (Claude Opus 5, tool use)
   |
   v
Proposed Tool Call
   |
   +---+-------------------+
   |                       |
Tool Risk Engine     LLM Intent Review
(path / filename)    (serves user goal?)
   |                       |
   +---+-------------------+
       |
Merged Risk Score (max)
       |
       v
Policy Engine
       |
+------+------+
|      |      |
ALLOW REVIEW BLOCK
|      |       |
|      v       |
|   Human      |
|   Approval   |
|    /   \\     |
|  YES   NO    |
|   |     |    |
v   v     v    v
File Policy   Stop
     |
     v
Tool Execution

All decisions
       |
       v
Security Audit Log
(rule_score + llm_score)
"""

if config.llm_defense_active():
    st.caption(
        "LLM layers active — detection and tool review each run "
        "two paths whose scores are merged (max)."
    )
    st.code(LLM_ASSISTED_FLOW)
else:
    st.caption(
        "Rules-only mode — no API key, so the LLM paths are absent "
        "and the deterministic engine runs alone."
    )
    st.code(RULES_ONLY_FLOW)


# ============================================================
# System Status
# ============================================================

st.header(
    "System Status"
)

st.success(
    "AgentGuard security "
    "controls operational."
)