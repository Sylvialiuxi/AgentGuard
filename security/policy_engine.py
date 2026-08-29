PROMPT_POLICY = {
    "review_threshold": 30,
    "block_threshold": 60,
}

TOOL_POLICY = {
    "review_threshold": 20,
    "block_threshold": 50,
}


def evaluate_policy(event_type: str, risk_score: int) -> dict:
    """
    Convert a risk score into an enforcement decision
    according to AgentGuard security policy.
    """

    event_type = event_type.upper()

    if event_type == "PROMPT":
        policy = PROMPT_POLICY

    elif event_type == "TOOL":
        policy = TOOL_POLICY

    else:
        return {
            "decision": "BLOCK",
            "reason": "unknown_event_type",
            "risk_score": risk_score,
        }

    if risk_score >= policy["block_threshold"]:
        decision = "BLOCK"

    elif risk_score >= policy["review_threshold"]:
        decision = "REVIEW"

    else:
        decision = "ALLOW"

    return {
        "decision": decision,
        "risk_score": risk_score,
        "review_threshold": policy["review_threshold"],
        "block_threshold": policy["block_threshold"],
    }