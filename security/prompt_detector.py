import re


SUSPICIOUS_PATTERNS = {
    "instruction_override": [
        r"ignore\s+(all\s+)?previous",
        r"ignore\s+(all\s+)?security\s+rules",
        r"disregard\s+(all\s+)?previous",
    ],

    "fake_system_instruction": [
        r"system\s+instruction",
        r"developer\s+instruction",
        r"important\s+system",
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