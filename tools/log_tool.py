from datetime import datetime
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
LOG_DIR = PROJECT_ROOT / "logs"
LOG_FILE = LOG_DIR / "security.log"


def log_security_event(
    event_type: str,
    source: str,
    risk_score: int,
    verdict: str,
    indicators: list
) -> None:
    """
    Write a security event to the AgentGuard audit log.
    """

    LOG_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    indicator_text = (
        ",".join(indicators)
        if indicators
        else "none"
    )

    log_entry = (
        f"{timestamp} | "
        f"event={event_type} | "
        f"source={source} | "
        f"risk_score={risk_score} | "
        f"verdict={verdict} | "
        f"indicators={indicator_text}\n"
    )

    with LOG_FILE.open("a", encoding="utf-8") as file:
        file.write(log_entry)