from datetime import datetime
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
LOG_DIR = PROJECT_ROOT / "logs"
LOG_FILE = LOG_DIR / "security.log"


def _sanitize(value) -> str:
    """
    Keep log values on a single line and safe for the
    "key=value | key=value" audit format used by the dashboard.
    """

    text = str(value)

    for bad in ("|", "\n", "\r"):
        text = text.replace(bad, " ")

    return text.strip()


def log_security_event(
    event_type: str,
    source: str,
    risk_score: int,
    verdict: str,
    indicators: list,
    **extra,
) -> None:
    """
    Write a security event to the AgentGuard audit log.

    Extra keyword arguments are appended as additional
    "key=value" fields, e.g.:

        log_security_event(
            ...,
            llm_score=88,
            llm_model="claude-haiku-4-5",
            llm_latency_ms=412,
        )
    """

    LOG_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    indicator_text = (
        ",".join(indicators)
        if indicators
        else "none"
    )

    fields = [
        f"event={_sanitize(event_type)}",
        f"source={_sanitize(source)}",
        f"risk_score={_sanitize(risk_score)}",
        f"verdict={_sanitize(verdict)}",
        f"indicators={_sanitize(indicator_text)}",
    ]

    for key, value in extra.items():

        if value is None:
            continue

        fields.append(f"{_sanitize(key)}={_sanitize(value)}")

    log_entry = f"{timestamp} | " + " | ".join(fields) + "\n"

    with LOG_FILE.open("a", encoding="utf-8") as file:
        file.write(log_entry)
