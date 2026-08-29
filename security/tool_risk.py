from pathlib import Path


def assess_tool_call(tool_name: str, arguments: dict) -> dict:
    """
    Analyze the risk of an AI agent tool call.

    This component only identifies risk.
    Final enforcement is handled by Policy Engine.
    """

    risk_score = 0
    reasons = []

    # Unknown tools are suspicious
    if tool_name != "read_file":
        risk_score += 50
        reasons.append("unknown_tool")

    if tool_name == "read_file":

        file_path = str(
            arguments.get("file_path", "")
        )

        path = Path(file_path)

        # Sensitive directory access
        if "sensitive" in path.parts:
            risk_score += 80
            reasons.append(
                "sensitive_directory_access"
            )

        # Suspicious filenames
        sensitive_names = [
            "secret",
            "password",
            "credential",
            "token",
            "private",
            "key",
        ]

        filename = path.name.lower()

        if any(
            word in filename
            for word in sensitive_names
        ):
            risk_score += 20
            reasons.append(
                "sensitive_filename"
            )

        # Path traversal
        if ".." in path.parts:
            risk_score += 100
            reasons.append(
                "path_traversal"
            )

    risk_score = min(risk_score, 100)

    if risk_score >= 80:
        risk_level = "CRITICAL"

    elif risk_score >= 50:
        risk_level = "HIGH"

    elif risk_score >= 20:
        risk_level = "MEDIUM"

    else:
        risk_level = "LOW"

    return {
        "tool": tool_name,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "reasons": reasons,
    }