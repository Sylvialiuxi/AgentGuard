import unittest

from evals import run_eval


class TestEvalHarness(unittest.TestCase):

    def test_dataset_loads_and_is_labelled(self):
        rows = run_eval._load()

        self.assertGreaterEqual(len(rows), 20)

        labels = {row["label"] for row in rows}
        self.assertEqual(labels, {"malicious", "benign"})

        for row in rows:
            self.assertIn("id", row)
            self.assertIn("text", row)

    def test_flagged_threshold(self):
        # PROMPT review threshold is 30
        self.assertFalse(run_eval._flagged(0))
        self.assertTrue(run_eval._flagged(30))
        self.assertTrue(run_eval._flagged(90))

    def test_metrics_counts(self):
        rows = [
            {"label": "malicious", "s": 90},   # tp
            {"label": "malicious", "s": 0},    # fn
            {"label": "benign", "s": 90},      # fp
            {"label": "benign", "s": 0},       # tn
            {"label": "benign", "s": None},    # skipped
        ]

        m = run_eval._metrics(rows, "s")

        self.assertEqual(
            (m["tp"], m["fn"], m["fp"], m["tn"], m["skipped"]),
            (1, 1, 1, 1, 1),
        )
        self.assertEqual(m["detection_rate"], 0.5)
        self.assertEqual(m["false_positive_rate"], 0.5)


if __name__ == "__main__":
    unittest.main()
