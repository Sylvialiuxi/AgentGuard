import re

from tools.file_tool import read_file
from tools.log_tool import log_security_event

from security.prompt_detector import detect_prompt_injection
from security.tool_risk import assess_tool_call
from security.policy_engine import evaluate_policy
from security.approval import request_human_approval


def run_agent(
    input_file: str,
    interactive_approval: bool = False,
) -> str:
    """
    AgentGuard protected agent execution flow.

    Security layers:
    1. Prompt risk detection
    2. Prompt policy evaluation
    3. Tool-call risk assessment
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

    print(
        f"[AGENTGUARD] Prompt risk score: "
        f"{detection['risk_score']}"
    )

    print(
        f"[AGENTGUARD] Indicators: "
        f"{detection['indicators']}"
    )

    # --------------------------------
    # Step 3: Prompt policy
    # --------------------------------

    prompt_policy = evaluate_policy(
        "PROMPT",
        detection["risk_score"],
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
        risk_score=detection["risk_score"],
        verdict=prompt_policy["decision"],
        indicators=detection["indicators"],
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

    print(
        f"[AGENTGUARD] Tool risk score: "
        f"{tool_risk['risk_score']}"
    )

    print(
        f"[AGENTGUARD] Tool risk level: "
        f"{tool_risk['risk_level']}"
    )

    print(
        f"[AGENTGUARD] Tool risk reasons: "
        f"{tool_risk['reasons']}"
    )

    # --------------------------------
    # Step 7: Tool policy
    # --------------------------------

    tool_policy = evaluate_policy(
        "TOOL",
        tool_risk["risk_score"],
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
        risk_score=tool_risk["risk_score"],
        verdict=tool_policy["decision"],
        indicators=tool_risk["reasons"],
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
            risk_score=tool_risk["risk_score"],
            reasons=tool_risk["reasons"],
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
            risk_score=tool_risk["risk_score"],
            verdict=approval_verdict,
            indicators=tool_risk["reasons"],
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