"""
AgentGuard prompt-injection detection eval.

Runs the labelled dataset through three configurations and
reports detection rate (recall on malicious) and false-positive
rate (benign flagged), plus the merged decision the policy
engine would take.

    python -m evals.run_eval

With no ANTHROPIC_API_KEY only the rules-only column is
populated; the LLM and merged columns require a key.
"""

import json
from pathlib import Path

from security import config
from security.policy_engine import evaluate_policy
from security.prompt_detector import detect_prompt_injection
from security.llm_judge import classify_prompt_injection


DATASET = Path(__file__).resolve().parent / "dataset.jsonl"
RESULTS = Path(__file__).resolve().parent / "results.json"


def _load():
    rows = []
    for line in DATASET.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            rows.append(json.loads(line))
    return rows


def _flagged(score: int) -> bool:
    """A score is 'flagged' if the policy engine would not ALLOW it."""
    return evaluate_policy("PROMPT", score)["decision"] != "ALLOW"


def _metrics(rows, score_key):
    tp = fp = tn = fn = 0
    skipped = 0

    for row in rows:
        score = row.get(score_key)
        if score is None:
            skipped += 1
            continue

        flagged = _flagged(score)
        malicious = row["label"] == "malicious"

        if malicious and flagged:
            tp += 1
        elif malicious and not flagged:
            fn += 1
        elif not malicious and flagged:
            fp += 1
        else:
            tn += 1

    mal = tp + fn
    ben = fp + tn

    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "skipped": skipped,
        "detection_rate": round(tp / mal, 3) if mal else None,
        "false_positive_rate": round(fp / ben, 3) if ben else None,
    }


def main():
    rows = _load()
    llm_active = config.llm_defense_active()

    print("=" * 70)
    print("           AGENTGUARD PROMPT-INJECTION DETECTION EVAL")
    print(f"  dataset: {len(rows)} rows   |   LLM defense: "
          f"{'active' if llm_active else 'inactive (rules-only)'}")
    print("=" * 70)

    for row in rows:
        rule = detect_prompt_injection(row["text"])["risk_score"]
        row["rule_score"] = rule

        if llm_active:
            verdict = classify_prompt_injection(row["text"])
            row["llm_score"] = (
                verdict["risk_score"] if verdict["ok"] else None
            )
            row["llm_error"] = verdict["error"]
        else:
            row["llm_score"] = None
            row["llm_error"] = "inactive"

        row["merged_score"] = config.merge_scores(
            row["rule_score"], row["llm_score"]
        )

        mark = "MAL " if row["label"] == "malicious" else "ben "
        print(
            f"{mark}{row['id']:<8} "
            f"rule={row['rule_score']:>3}  "
            f"llm={str(row['llm_score']):>4}  "
            f"merged={row['merged_score']:>3}  "
            f"-> {evaluate_policy('PROMPT', row['merged_score'])['decision']}"
        )

    report = {
        "dataset_size": len(rows),
        "llm_defense_active": llm_active,
        "rules_only": _metrics(rows, "rule_score"),
        "llm_only": _metrics(rows, "llm_score"),
        "merged": _metrics(rows, "merged_score"),
    }

    print("\n" + "=" * 70)
    for name in ("rules_only", "llm_only", "merged"):
        m = report[name]
        print(
            f"{name:<12}  detect={m['detection_rate']}  "
            f"false_pos={m['false_positive_rate']}  "
            f"(tp={m['tp']} fn={m['fn']} fp={m['fp']} tn={m['tn']} "
            f"skipped={m['skipped']})"
        )
    print("=" * 70)

    RESULTS.write_text(
        json.dumps(report, indent=2), encoding="utf-8"
    )
    print(f"\nSaved: {RESULTS}")


if __name__ == "__main__":
    main()
