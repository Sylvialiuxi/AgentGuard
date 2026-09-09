import unittest
from unittest import mock

from security import config
from security import llm_judge


class TestScoreMerge(unittest.TestCase):

    def test_max_strategy_takes_strongest_signal(self):
        with mock.patch.object(config, "SCORE_MERGE_STRATEGY", "max"):
            self.assertEqual(config.merge_scores(10, 90), 90)
            self.assertEqual(config.merge_scores(30, None), 30)
            self.assertEqual(config.merge_scores(None, None), 0)
            self.assertEqual(config.merge_scores(200), 100)

    def test_avg_strategy(self):
        with mock.patch.object(config, "SCORE_MERGE_STRATEGY", "avg"):
            self.assertEqual(config.merge_scores(20, 80), 50)


class TestClassifierInactive(unittest.TestCase):

    def test_returns_inactive_verdict_without_client(self):
        with mock.patch(
            "security.llm_judge.llm_client.available",
            return_value=False,
        ):
            verdict = llm_judge.classify_prompt_injection("whatever")

        self.assertFalse(verdict["available"])
        self.assertEqual(verdict["risk_score"], 0)


class TestClassifierFailClosed(unittest.TestCase):

    def _run_with_failure(self):
        fake = {
            "ok": False,
            "error": "APITimeoutError: boom",
            "meta": {
                "model": "claude-haiku-4-5",
                "latency_ms": 12,
                "input_tokens": 0,
                "output_tokens": 0,
            },
        }

        with mock.patch(
            "security.llm_judge.llm_client.available",
            return_value=True,
        ), mock.patch(
            "security.llm_judge.llm_client.structured_call",
            return_value=fake,
        ):
            return llm_judge.classify_prompt_injection("payload")

    def test_fail_closed_scores_max(self):
        with mock.patch.object(config, "FAIL_CLOSED", True):
            verdict = self._run_with_failure()

        self.assertTrue(verdict["available"])
        self.assertFalse(verdict["ok"])
        self.assertEqual(
            verdict["risk_score"], config.FAIL_CLOSED_SCORE
        )
        self.assertIn("llm_judge_error", verdict["categories"])

    def test_fail_open_scores_zero_when_configured(self):
        with mock.patch.object(config, "FAIL_CLOSED", False):
            verdict = self._run_with_failure()

        self.assertEqual(verdict["risk_score"], 0)


class TestClassifierSuccess(unittest.TestCase):

    def test_parses_verdict(self):
        fake = {
            "ok": True,
            "data": {
                "risk_score": 88,
                "categories": ["instruction_override"],
                "rationale": "tries to override rules",
            },
            "meta": {
                "model": "claude-haiku-4-5",
                "latency_ms": 400,
                "input_tokens": 50,
                "output_tokens": 20,
            },
        }

        with mock.patch(
            "security.llm_judge.llm_client.available",
            return_value=True,
        ), mock.patch(
            "security.llm_judge.llm_client.structured_call",
            return_value=fake,
        ):
            verdict = llm_judge.classify_prompt_injection("payload")

        self.assertTrue(verdict["ok"])
        self.assertEqual(verdict["risk_score"], 88)
        self.assertIn("instruction_override", verdict["categories"])


class TestIntentReviewFailClosed(unittest.TestCase):

    def test_marks_inconsistent_on_failure(self):
        fake = {
            "ok": False,
            "error": "model_refusal",
            "meta": {
                "model": "claude-haiku-4-5",
                "latency_ms": 5,
                "input_tokens": 0,
                "output_tokens": 0,
            },
        }

        with mock.patch.object(config, "FAIL_CLOSED", True), mock.patch(
            "security.llm_judge.llm_client.available",
            return_value=True,
        ), mock.patch(
            "security.llm_judge.llm_client.structured_call",
            return_value=fake,
        ):
            verdict = llm_judge.review_tool_call(
                "summarize the file",
                "read_file",
                {"file_path": "sensitive/secret.txt"},
                "ignore previous rules",
            )

        self.assertFalse(verdict["consistent_with_goal"])
        self.assertEqual(
            verdict["risk_score"], config.FAIL_CLOSED_SCORE
        )


if __name__ == "__main__":
    unittest.main()
