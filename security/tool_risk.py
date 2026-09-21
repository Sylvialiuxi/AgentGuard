import re
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

        # Suspicious filenames.
        #
        # Matched as whole words rather than substrings. As a
        # substring, "key" fired on monkey.txt and turkey_recipe.txt
        # and "token" on tokenizer.py; splitting the name on its
        # separators keeps key_notes.txt matching and drops that
        # entire class of false positive.
        #
        # The weight sits below the REVIEW threshold on purpose. A
        # keyword in a filename is weak evidence by itself -- the
        # file still has to be inside an allowlisted directory to be
        # reachable at all -- so it should corroborate another
        # signal rather than hold a call on its own.
        sensitive_names = {
            "secret",
            "password",
            "credential",
            "token",
            "private",
            "key",
        }

        filename_words = set(
            re.split(r"[^a-z0-9]+", path.name.lower())
        )

        if filename_words & sensitive_names:
            risk_score += 10
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

    return {
        "tool": tool_name,
        "risk_score": risk_score,
        "reasons": reasons,
    }