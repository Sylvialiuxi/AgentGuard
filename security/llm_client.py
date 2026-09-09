import json
import time

from security import config


# ============================================================
# Thin wrapper around the Anthropic SDK
# ============================================================
#
# Responsibilities:
#   - lazily build a single client
#   - run a structured-output request and return parsed JSON
#   - never raise into the caller: return a typed error dict so
#     the defense layers can fail closed
#
# The `anthropic` package is an optional dependency. If it is
# not installed, `available()` returns False and callers fall
# back to the deterministic engine.


_client = None
_import_error = None

try:
    import anthropic
except ImportError as exc:  # pragma: no cover - depends on env
    anthropic = None
    _import_error = str(exc)


def available() -> bool:
    """
    True when a real LLM call can be attempted.
    """

    return bool(
        anthropic is not None
        and config.llm_defense_active()
    )


def _get_client():
    global _client

    if _client is None:
        _client = anthropic.Anthropic(api_key=config.API_KEY)

    return _client


def agent_available() -> bool:
    """
    True when the real LLM agent core can be used.
    """

    return bool(
        anthropic is not None
        and config.llm_agent_active()
    )


def raw_client():
    """
    The underlying Anthropic client, or None when unavailable.
    """

    if anthropic is None or not config.API_KEY:
        return None

    return _get_client()


def structured_call(
    system: str,
    user_content: str,
    schema: dict,
    *,
    model: str = None,
    timeout: float = None,
    max_tokens: int = None,
) -> dict:
    """
    Run a single structured-output request.

    Returns a dict:
        {
            "ok": bool,
            "data": <parsed JSON dict>   # when ok
            "error": <str>               # when not ok
            "meta": {
                "model": str,
                "latency_ms": int,
                "input_tokens": int,
                "output_tokens": int,
            }
        }
    """

    model = model or config.JUDGE_MODEL
    timeout = timeout or config.JUDGE_TIMEOUT_SECONDS
    max_tokens = max_tokens or config.JUDGE_MAX_TOKENS

    meta = {
        "model": model,
        "latency_ms": 0,
        "input_tokens": 0,
        "output_tokens": 0,
    }

    if not available():
        return {
            "ok": False,
            "error": _import_error or "llm_defense_inactive",
            "meta": meta,
        }

    started = time.monotonic()

    try:
        client = _get_client()

        response = client.with_options(
            timeout=timeout,
        ).messages.create(
            model=model,
            max_tokens=max_tokens,
            system=[
                {
                    "type": "text",
                    "text": system,
                    "cache_control": {"type": "ephemeral"},
                }
            ],
            output_config={
                "format": {
                    "type": "json_schema",
                    "schema": schema,
                }
            },
            messages=[
                {
                    "role": "user",
                    "content": user_content,
                }
            ],
        )

    except Exception as exc:  # noqa: BLE001 - defense must not crash
        meta["latency_ms"] = int(
            (time.monotonic() - started) * 1000
        )
        return {
            "ok": False,
            "error": f"{type(exc).__name__}: {exc}",
            "meta": meta,
        }

    meta["latency_ms"] = int(
        (time.monotonic() - started) * 1000
    )

    usage = getattr(response, "usage", None)

    if usage is not None:
        meta["input_tokens"] = getattr(
            usage, "input_tokens", 0
        )
        meta["output_tokens"] = getattr(
            usage, "output_tokens", 0
        )

    if response.stop_reason == "refusal":
        return {
            "ok": False,
            "error": "model_refusal",
            "meta": meta,
        }

    text = next(
        (
            block.text
            for block in response.content
            if block.type == "text"
        ),
        "",
    )

    try:
        data = json.loads(text)

    except (ValueError, TypeError) as exc:
        return {
            "ok": False,
            "error": f"unparseable_response: {exc}",
            "meta": meta,
        }

    return {
        "ok": True,
        "data": data,
        "meta": meta,
    }
