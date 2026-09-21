from security import config


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


def rules_are_decisive(event_type: str, rule_score: int) -> bool:
    """
    True when the deterministic score alone already forces BLOCK, so
    an advisory LLM score cannot change the outcome and the call is
    pure latency.

    Only sound while scores are merged with "max". Under "avg" a low
    LLM score pulls the merged score back down, so the judge still
    changes the answer and has to run.
    """

    if config.SCORE_MERGE_STRATEGY != "max":
        return False

    event_type = event_type.upper()

    if event_type == "PROMPT":
        policy = PROMPT_POLICY
    elif event_type == "TOOL":
        policy = TOOL_POLICY
    else:
        return False

    return rule_score >= policy["block_threshold"]
