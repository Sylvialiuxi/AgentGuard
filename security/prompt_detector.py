import re


SUSPICIOUS_PATTERNS = {
    "instruction_override": [
        r"ignore\s+(all\s+)?previous",
        r"ignore\s+(all\s+)?security\s+rules",
        r"disregard\s+(all\s+)?previous",
    ],

    # A fake system message is recognised by its *position*, not by the
    # words alone. "SYSTEM INSTRUCTION: ignore the above" is a forged
    # directive header; "the system instruction manual for the HVAC unit"
    # is an ordinary noun phrase. Matching the bare words flagged the
    # second one, so these patterns require the phrase to actually be
    # acting as a directive: a line-leading header, a role tag, or a
    # shouted all-caps declaration.
    "fake_system_instruction": [
        # Directive header at the start of a line, ending in a colon.
        # Optional leading quote/bullet markers and brackets are allowed,
        # as is an intensifier such as "IMPORTANT" or "URGENT".
        r"(?m)^[\s>*#\-]*[\[\(<{]?\s*"
        r"(important\s+|urgent\s+|priority\s+|new\s+)?"
        r"(system|developer|admin|operator)\s+"
        r"(instruction|message|prompt|note|directive|override)s?"
        r"\s*[\]\)>}]?\s*:",

        # Role tags borrowed from chat formats: <system>, </system>,
        # [SYSTEM], <|developer|>
        r"[<\[]\s*\|?\s*/?\s*(system|developer)\s*\|?\s*[>\]]",

        # Shouted declaration anywhere in the text. All-caps is itself
        # the signal, so this one is deliberately case-sensitive.
        r"(?-i:\b(SYSTEM|DEVELOPER|ADMIN)\s+"
        r"(INSTRUCTION|MESSAGE|PROMPT|DIRECTIVE|OVERRIDE)S?\b)",
    ],

    "sensitive_file_access": [
        r"read\s+(the\s+)?file\s+.*secret",
        r"read\s+(the\s+)?file\s+.*sensitive",
        r"open\s+.*secret",
        r"access\s+.*sensitive",
    ],

    "data_exfiltration": [
        r"return\s+.*full\s+contents",
        r"reveal\s+.*secret",
        r"send\s+.*contents",
    ],
}


def detect_prompt_injection(text: str) -> dict:
    """
    Detect suspicious prompt-injection indicators.

    This component only detects and scores risk.
    It does not make the final security decision.
    """

    detected = []

    for category, patterns in SUSPICIOUS_PATTERNS.items():
        for pattern in patterns:

            if re.search(
                pattern,
                text,
                re.IGNORECASE | re.DOTALL,
            ):
                detected.append(category)
                break

    risk_score = min(len(detected) * 30, 100)

    return {
        "risk_score": risk_score,
        "indicators": detected,
    }