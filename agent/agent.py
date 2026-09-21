import re

from tools.file_tool import read_file
from tools.log_tool import log_security_event

from security import config
from security.prompt_detector import detect_prompt_injection
from security.tool_risk import assess_tool_call
from security.policy_engine import evaluate_policy
from security.approval import request_human_approval
from security.llm_judge import (
    classify_prompt_injection,
    review_tool_call,
)


DEFAULT_USER_GOAL = (
    "Read the provided input file and summarize its contents."
)


def run_agent(
    input_file: str,
    interactive_approval: bool = False,
    user_goal: str = DEFAULT_USER_GOAL,
) -> str:
    """
    AgentGuard protected agent execution flow.

    Security layers:
    1. Prompt risk detection (rules + optional LLM classifier)
    2. Prompt policy evaluation
    3. Tool-call risk assessment (rules + optional LLM intent review)
    4. Tool policy evaluation
    5. Human approval for medium-risk actions
    6. File access enforcement
    7. Audit logging
    """

    print(f"[AGENT] Reading input file: {input_file}")

    # --------------------------------
    # Step 1: Read external content
    # --------------------------------

    content = read_file(input_file)

    if content.startswith("[SECURITY BLOCK]"):
        print(content)
        return content

    print("\n[AGENT] File content:")
    print("-" * 50)
    print(content)
    print("-" * 50)

    # --------------------------------
    # Step 2: Prompt detection
    # --------------------------------

    print(
        "\n[AGENTGUARD] "
        "Scanning untrusted content..."
    )

    detection = detect_prompt_injection(content)

    rule_score = detection["risk_score"]
    indicators = list(detection["indicators"])

    print(
        f"[AGENTGUARD] Rule-based prompt risk score: {rule_score}"
    )

    print(
        f"[AGENTGUARD] Rule indicators: {detection['indicators']}"
    )

    # LLM-backed classifier (advisory, fails closed)
    llm_prompt = classify_prompt_injection(content)

    if llm_prompt["available"]:

        print(
            f"[AGENTGUARD] LLM classifier risk score: "
            f"{llm_prompt['risk_score']} "
            f"({'ok' if llm_prompt['ok'] else llm_prompt['error']})"
        )

        print(
            f"[AGENTGUARD] LLM rationale: {llm_prompt['rationale']}"
        )

        for category in llm_prompt["categories"]:
            if category not in indicators:
                indicators.append(category)

    prompt_risk_score = config.merge_scores(
        rule_score,
        llm_prompt["risk_score"] if llm_prompt["available"] else None,
    )

    print(
        f"[AGENTGUARD] Merged prompt risk score: {prompt_risk_score}"
    )

    # --------------------------------
    # Step 3: Prompt policy
    # --------------------------------

    prompt_policy = evaluate_policy(
        "PROMPT",
        prompt_risk_score,
    )

    print(
        f"[POLICY] Prompt decision: "
        f"{prompt_policy['decision']}"
    )

    print(
        f"[POLICY] Review threshold: "
        f"{prompt_policy['review_threshold']}"
    )

    print(
        f"[POLICY] Block threshold: "
        f"{prompt_policy['block_threshold']}"
    )

    # Log prompt scan
    log_security_event(
        event_type="PROMPT_SCAN",
        source=input_file,
        risk_score=prompt_risk_score,
        verdict=prompt_policy["decision"],
        indicators=indicators,
        rule_score=rule_score,
        llm_score=(
            llm_prompt["risk_score"]
            if llm_prompt["available"]
            else None
        ),
        llm_model=llm_prompt["meta"]["model"],
        llm_latency_ms=(
            llm_prompt["meta"]["latency_ms"] or None
        ),
        llm_error=llm_prompt["error"] if llm_prompt["available"] else None,
    )

    # --------------------------------
    # Step 4: Prompt enforcement
    # --------------------------------

    if prompt_policy["decision"] == "BLOCK":

        result = (
            "[SECURITY BLOCK] "
            "Prompt policy denied execution."
        )

        print(f"\n{result}")
        return result

    if prompt_policy["decision"] == "REVIEW":

        print(
            "\n[SECURITY WARNING] "
            "Suspicious prompt detected. "
            "Tool calls will receive additional review."
        )

    # --------------------------------
    # Step 5: Agent interprets content
    # --------------------------------

    pattern = r"read the file\s+([^\s]+)"

    match = re.search(
        pattern,
        content,
        re.IGNORECASE,
    )

    if not match:

        result = (
            "[AGENT] No executable "
            "file instruction detected."
        )

        print(f"\n{result}")
        return result

    target_file = match.group(1).strip()

    print("\n[AGENT] Instruction detected.")

    print(
        f"[AGENT] Proposed tool call: "
        f"read_file('{target_file}')"
    )

    # --------------------------------
    # Step 6: Tool risk analysis
    # --------------------------------

    print(
        "\n[AGENTGUARD] "
        "Assessing proposed tool call..."
    )

    tool_risk = assess_tool_call(
        "read_file",
        {
            "file_path": target_file
        },
    )

    tool_rule_score = tool_risk["risk_score"]
    tool_reasons = list(tool_risk["reasons"])

    print(
        f"[AGENTGUARD] Rule-based tool risk score: {tool_rule_score}"
    )

    print(
        f"[AGENTGUARD] Tool risk reasons: "
        f"{tool_risk['reasons']}"
    )

    # LLM-backed intent review (advisory, fails closed)
    intent = review_tool_call(
        user_goal=user_goal,
        tool_name="read_file",
        arguments={"file_path": target_file},
        untrusted_context=content,
    )

    if intent["available"]:

        print(
            f"[AGENTGUARD] LLM intent risk score: "
            f"{intent['risk_score']} "
            f"(consistent_with_goal={intent['consistent_with_goal']}, "
            f"{'ok' if intent['ok'] else intent['error']})"
        )

        print(
            f"[AGENTGUARD] LLM intent rationale: {intent['rationale']}"
        )

        if not intent["consistent_with_goal"]:
            tool_reasons.append("llm_goal_mismatch")

    tool_risk_score = config.merge_scores(
        tool_rule_score,
        intent["risk_score"] if intent["available"] else None,
    )

    print(
        f"[AGENTGUARD] Merged tool risk score: {tool_risk_score}"
    )

    # --------------------------------
    # Step 7: Tool policy
    # --------------------------------

    tool_policy = evaluate_policy(
        "TOOL",
        tool_risk_score,
    )

    print(
        f"[POLICY] Tool decision: "
        f"{tool_policy['decision']}"
    )

    print(
        f"[POLICY] Review threshold: "
        f"{tool_policy['review_threshold']}"
    )

    print(
        f"[POLICY] Block threshold: "
        f"{tool_policy['block_threshold']}"
    )

    # Log tool risk
    log_security_event(
        event_type="TOOL_CALL",
        source=target_file,
        risk_score=tool_risk_score,
        verdict=tool_policy["decision"],
        indicators=tool_reasons,
        rule_score=tool_rule_score,
        llm_score=(
            intent["risk_score"] if intent["available"] else None
        ),
        llm_model=intent["meta"]["model"],
        llm_latency_ms=intent["meta"]["latency_ms"] or None,
        llm_error=intent["error"] if intent["available"] else None,
    )

    # --------------------------------
    # Step 8: Block high-risk tool call
    # --------------------------------

    if tool_policy["decision"] == "BLOCK":

        result = (
            "[SECURITY BLOCK] "
            "Tool policy denied execution."
        )

        print(f"\n{result}")
        return result

    # --------------------------------
    # Step 9: Human approval
    # --------------------------------

    if tool_policy["decision"] == "REVIEW":

        print(
            "\n[SECURITY WARNING] "
            "Tool call requires human approval."
        )

        approved = request_human_approval(
            tool_name="read_file",
            target=target_file,
            risk_score=tool_risk_score,
            reasons=tool_reasons,
            interactive=interactive_approval,
        )

        if approved:
            approval_verdict = "APPROVED"
        else:
            approval_verdict = "DENIED"

        # Log human decision
        log_security_event(
            event_type="HUMAN_APPROVAL",
            source=target_file,
            risk_score=tool_risk_score,
            verdict=approval_verdict,
            indicators=tool_reasons,
        )

        if not approved:

            result = (
                "[SECURITY BLOCK] "
                "Tool execution denied by approval gate."
            )

            print(f"\n{result}")
            return result

    # --------------------------------
    # Step 10: Execute tool
    # --------------------------------

    print(
        f"\n[AGENT] Executing tool call: "
        f"read_file('{target_file}')"
    )

    result = read_file(target_file)

    print("\n[AGENT] Tool result:")
    print(result)

    return result