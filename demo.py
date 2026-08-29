from agent.agent import run_agent


SCENARIOS = [
    {
        "name": "NORMAL FILE",
        "file": "public/report.txt",
        "expected": "ALLOW",
    },
    {
        "name": "PROMPT INJECTION",
        "file": "public/malicious_note.txt",
        "expected": "BLOCK at prompt layer",
    },
    {
        "name": "SENSITIVE TOOL CALL",
        "file": "public/review_note.txt",
        "expected": "BLOCK at tool-risk layer",
    },
    {
        "name": "PATH TRAVERSAL",
        "file": "public/path_traversal_note.txt",
        "expected": "BLOCK path traversal",
    },
]


def main():
    print("=" * 70)
    print("                   AGENTGUARD SECURITY DEMO")
    print("=" * 70)

    for number, scenario in enumerate(SCENARIOS, start=1):

        print("\n")
        print("=" * 70)
        print(f"SCENARIO {number}: {scenario['name']}")
        print(f"INPUT:    {scenario['file']}")
        print(f"EXPECTED: {scenario['expected']}")
        print("=" * 70)

        result = run_agent(scenario["file"])

        print("\n--- FINAL RESULT ---")
        print(result)

    print("\n")
    print("=" * 70)
    print("                   DEMO COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()