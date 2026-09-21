"""
AgentGuard tool-call enforcement eval.

run_eval.py measures layer 1: does a piece of text look like an
injection. This one measures layers 3 and 4: given a goal, a
proposed tool call and whatever untrusted content the agent has
read, does AgentGuard reach the right decision.

The two datasets are not interchangeable. A row here is a
four-tuple (goal, tool, arguments, context), and the label is a
three-way policy decision rather than a binary one, because the
question is no longer "is this text adversarial" but "should
this call be allowed to run".

    python -m evals.run_tool_eval

With no ANTHROPIC_API_KEY only the rules-only column is
populated; the intent-review and merged columns require a key.


REACHABILITY
------------
A tool call does not arrive out of nowhere. It sits on top of
content the agent was allowed to read, which means the prompt
layer already passed that content. So each row declares where it
sits, and this runner checks the claim rather than trusting it:

  upstream="passes"    the context scores below the PROMPT block
                       threshold, so the pipeline really reaches
                       this state. These rows carry the headline
                       numbers.

  upstream="bypassed"  the prompt layer would block this content
                       outright. The row is counterfactual on
                       purpose - it asks whether this layer still
                       holds if the one in front of it failed.
                       Scored separately, never pooled.

A row whose declared reachability does not match what the prompt
layer actually says is reported as a dataset defect. Without that
check a dataset silently drifts into measuring states the system
can never be in.


THREE NUMBERS MATTER
--------------------
  detection    - share of calls that should be stopped and were
  false_pos    - share of legitimate calls wrongly held or denied
  pair flips   - of the paired rows, how many the column told
                 apart. Each pair holds the tool call constant and
                 varies only goal and context. assess_tool_call()
                 is not given either, so the rule engine scores
                 both rows identically and can never score better
                 than chance here. That gap is the measurement of
                 what the intent reviewer adds.
"""

import json
from pathlib import Path

from security import config
from security.policy_engine import evaluate_policy
from security.prompt_detector import detect_prompt_injection
from security.tool_risk import assess_tool_call
from security.llm_judge import (
    classify_prompt_injection,
    review_tool_call,
)


DATASET = Path(__file__).resolve().parent / "tool_dataset.jsonl"
RESULTS = Path(__file__).resolve().parent / "tool_results.json"

COLUMNS = ("rule_score", "llm_score", "merged_score")

COLUMN_LABELS = {
    "rule_score": "rules_only",
    "llm_score": "intent_only",
    "merged_score": "merged",
}


def _load():
    rows = []

    for line in DATASET.read_text(
        encoding="utf-8"
    ).splitlines():

        line = line.strip()

        if line:
            rows.append(json.loads(line))

    return rows


def _decision(score):
    """
    The decision the policy engine would reach for a score, or
    None when the column has no score for this row.
    """

    if score is None:
        return None

    return evaluate_policy("TOOL", score)["decision"]


def check_reachability(rows, llm_active: bool) -> list:
    """
    Score each distinct context through the PROMPT layer and compare
    the result with what the row claims. Returns the defects found.

    Contexts are scored once each, not once per row: several rows
    deliberately share a context so that only the goal varies.
    """

    verdicts = {}
    defects = []

    for row in rows:

        context = row.get("untrusted_context", "")

        if context not in verdicts:

            rule = detect_prompt_injection(context)["risk_score"]

            llm = (
                classify_prompt_injection(context)
                if llm_active
                else None
            )

            score = config.merge_scores(
                rule,
                llm["risk_score"] if llm and llm["ok"] else None,
            )

            verdicts[context] = {
                "score": score,
                "decision": evaluate_policy("PROMPT", score)[
                    "decision"
                ],
            }

        verdict = verdicts[context]

        actual = (
            "bypassed"
            if verdict["decision"] == "BLOCK"
            else "passes"
        )

        row["context_score"] = verdict["score"]
        row["context_actual"] = actual

        if row.get("upstream") and actual != row["upstream"]:
            defects.append(
                f"{row['id']}: declared upstream="
                f"{row.get('upstream')!r} but the prompt layer "
                f"scores its context {verdict['score']}/100 "
                f"({actual})"
            )

    return defects


def _metrics(rows, score_key):
    """
    Grade one column over one set of rows.

    The headline pass/fail is whether the call was stopped at all
    (REVIEW and BLOCK both stop it, since an unattended REVIEW is
    denied by approval.py). Exact-decision agreement is reported
    alongside it, because holding a call for review when it should
    have been blocked outright is a weaker result than a match.
    """

    tp = fp = tn = fn = 0
    exact = 0
    graded = 0
    skipped = 0

    for row in rows:

        decision = _decision(row.get(score_key))

        if decision is None:
            skipped += 1
            continue

        graded += 1

        want_stopped = row["expected"] != "ALLOW"
        got_stopped = decision != "ALLOW"

        if decision == row["expected"]:
            exact += 1

        if want_stopped and got_stopped:
            tp += 1
        elif want_stopped and not got_stopped:
            fn += 1
        elif not want_stopped and got_stopped:
            fp += 1
        else:
            tn += 1

    should_stop = tp + fn
    should_pass = fp + tn

    return {
        "n": len(rows),
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "skipped": skipped,
        "detection_rate": (
            round(tp / should_stop, 3) if should_stop else None
        ),
        "false_positive_rate": (
            round(fp / should_pass, 3) if should_pass else None
        ),
        "exact_decision_rate": (
            round(exact / graded, 3) if graded else None
        ),
    }


def _pair_metrics(rows, score_key):
    """
    Of the paired rows, how many pairs did this column separate.

    A pair counts as separated only when both of its rows land on
    the correct side. Getting one right by luck is not enough: the
    point is telling the two apart.
    """

    pairs = {}

    for row in rows:

        if not row.get("pair"):
            continue

        pairs.setdefault(row["pair"], []).append(row)

    separated = 0
    total = 0
    detail = {}

    for name, members in pairs.items():

        if len(members) != 2:
            continue

        total += 1
        ok = True

        for row in members:

            decision = _decision(row.get(score_key))

            if decision is None:
                ok = False
                break

            want_stopped = row["expected"] != "ALLOW"
            got_stopped = decision != "ALLOW"

            if want_stopped != got_stopped:
                ok = False

        detail[name] = ok

        if ok:
            separated += 1

    return {
        "pairs": total,
        "separated": separated,
        "detail": detail,
    }


def _table(title, rows, report, key_prefix):
    """
    Print one metrics table and fold it into the report.
    """

    print(f"\n{title}  ({len(rows)} rows)")
    print(
        f"{'column':<13}{'detect':>9}{'false_pos':>12}"
        f"{'exact':>9}{'pairs':>9}"
    )
    print("-" * 78)

    for key in COLUMNS:

        label = COLUMN_LABELS[key]
        metrics = _metrics(rows, key)
        pairs = _pair_metrics(rows, key)

        report[f"{key_prefix}{label}"] = dict(
            metrics, pair_separation=pairs
        )

        print(
            f"{label:<13}"
            f"{str(metrics['detection_rate']):>9}"
            f"{str(metrics['false_positive_rate']):>12}"
            f"{str(metrics['exact_decision_rate']):>9}"
            f"{pairs['separated']:>6}/{pairs['pairs']}"
        )


def _group_table(rows, key, title, report, report_key):
    """
    Break the merged column down by one of the row's own dimensions.

    A single aggregate hides the shape of the failure. By `label` it
    says whether the guard is catching attackers or catching its own
    agent; by `scenario` it says which kind of mistake the stack is
    good at and which it is not - in particular that a goal vague
    enough to license anything leaves the intent reviewer nothing to
    compare against, so the deterministic layers carry those rows.
    """

    groups = {}

    for row in rows:
        groups.setdefault(row[key], []).append(row)

    print(f"\n{title}")
    print(
        f"{key:<18}{'n':>4}{'detect':>9}"
        f"{'false_pos':>12}{'exact':>9}"
    )
    print("-" * 78)

    report[report_key] = {}

    for name in sorted(groups):

        metrics = _metrics(groups[name], "merged_score")
        report[report_key][name] = metrics

        print(
            f"{name:<18}{metrics['n']:>4}"
            f"{str(metrics['detection_rate']):>9}"
            f"{str(metrics['false_positive_rate']):>12}"
            f"{str(metrics['exact_decision_rate']):>9}"
        )


def main():
    rows = _load()
    llm_active = config.llm_defense_active()

    print("=" * 78)
    print("           AGENTGUARD TOOL-CALL ENFORCEMENT EVAL")
    print(
        f"  dataset: {len(rows)} rows   |   intent review: "
        f"{'active' if llm_active else 'inactive (rules-only)'}"
    )
    print("=" * 78)

    # Establish what actually reaches this layer before grading it.
    defects = check_reachability(rows, llm_active)  # noqa: F841

    if defects:
        print("\nDATASET DEFECTS (declared reachability is wrong):")
        for defect in defects:
            print(f"  {defect}")
        print()

    for row in rows:

        rule = assess_tool_call(
            row["tool"], row["args"]
        )["risk_score"]

        row["rule_score"] = rule

        if llm_active:

            verdict = review_tool_call(
                user_goal=row["user_goal"],
                tool_name=row["tool"],
                arguments=row["args"],
                untrusted_context=row.get(
                    "untrusted_context", ""
                ),
            )

            row["llm_score"] = (
                verdict["risk_score"] if verdict["ok"] else None
            )
            row["consistent_with_goal"] = (
                verdict["consistent_with_goal"]
                if verdict["ok"]
                else None
            )

        else:
            row["llm_score"] = None
            row["consistent_with_goal"] = None

        row["merged_score"] = config.merge_scores(
            row["rule_score"], row["llm_score"]
        )

        got = _decision(row["merged_score"])
        hit = "ok " if got == row["expected"] else "MISS"

        print(
            f"{hit} {row['id']:<9} {row['scenario']:<16} "
            f"{row['agent_mode']:<8} [ctx={row['context_score']:>3}]  "
            f"rule={row['rule_score']:>3}  "
            f"intent={str(row['llm_score']):>4}  "
            f"merged={row['merged_score']:>3}  "
            f"-> {got:<6} (want {row['expected']})"
        )

    reachable = [r for r in rows if r.get("upstream", "passes") == "passes"]
    bypassed = [r for r in rows if r.get("upstream") == "bypassed"]

    report = {
        "dataset_size": len(rows),
        "llm_defense_active": llm_active,
        "reachable_rows": len(reachable),
        "bypassed_rows": len(bypassed),
        "dataset_defects": defects,
    }

    print("\n" + "=" * 78)

    _table(
        "REACHABLE - content the prompt layer passed",
        reachable,
        report,
        "",
    )

    if bypassed:
        _table(
            "BYPASSED - defence in depth, prompt layer assumed failed",
            bypassed,
            report,
            "bypassed_",
        )

    _group_table(
        rows, "label", "BY LABEL (merged column)", report, "by_label"
    )
    _group_table(
        rows, "scenario", "BY SCENARIO (merged column)", report,
        "by_scenario",
    )
    _group_table(
        rows, "agent_mode", "BY AGENT MODE (merged column)", report,
        "by_agent_mode",
    )

    print("\n" + "=" * 78)

    misses = [
        row
        for row in rows
        if _decision(row["merged_score"]) != row["expected"]
    ]

    if misses:
        print("\nMerged-column disagreements:")

        for row in misses:
            print(
                f"  {row['id']:<9} ({row['agent_mode']}) got "
                f"{_decision(row['merged_score']):<6} "
                f"want {row['expected']:<6} - {row['note']}"
            )

    RESULTS.write_text(
        json.dumps(report, indent=2), encoding="utf-8"
    )

    print(f"\nSaved: {RESULTS}")


if __name__ == "__main__":
    main()
