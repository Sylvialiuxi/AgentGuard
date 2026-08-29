def request_human_approval(
    tool_name: str,
    target: str,
    risk_score: int,
    reasons: list,
    interactive: bool = False,
) -> bool:
    """
    Request human approval for a medium-risk tool call.

    If interactive mode is disabled, deny by default.
    """

    print("\n[APPROVAL] Human approval required.")
    print(f"[APPROVAL] Tool: {tool_name}")
    print(f"[APPROVAL] Target: {target}")
    print(f"[APPROVAL] Risk score: {risk_score}")
    print(f"[APPROVAL] Reasons: {reasons}")

    # Secure default: deny if nobody is available
    if not interactive:
        print(
            "[APPROVAL] No interactive approval available. "
            "Denied by default."
        )
        return False

    while True:
        choice = input(
            "[APPROVAL] Approve this tool call? [y/N]: "
        ).strip().lower()

        if choice in {"y", "yes"}:
            print("[APPROVAL] Human decision: APPROVED")
            return True

        if choice in {"", "n", "no"}:
            print("[APPROVAL] Human decision: DENIED")
            return False

        print("[APPROVAL] Please enter y or n.")