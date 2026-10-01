"""Synthetic regression tests for model-output normalization."""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest


MODULE_PATH = Path(__file__).resolve().parents[1] / "normalize_stage_reasoning_predictions.py"
SPEC = importlib.util.spec_from_file_location("normalize_predictions", MODULE_PATH)
normalize = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(normalize)


class NormalizationTests(unittest.TestCase):
    def test_free_form_claims_and_optional_steps_are_preserved(self):
        chain = [
            {"claim": "A connection is visible.", "evidence_refs": [{"seq": 1, "edge_id": "edge_1"}]},
            {"step": "analysis", "claim": "An outcome is not visible.", "evidence_refs": []},
        ]
        prediction, error = normalize.normalise_single({
            "sample_id": "sample_000001", "predicted_stage": "stage_unclosed", "reasoning_chain": chain,
        })
        self.assertIsNone(error)
        self.assertEqual(prediction["reasoning_chain"], chain)

    def test_invalid_stage_preserves_parseable_reasoning(self):
        chain = [{"step": "analysis", "claim": "A process starts.", "evidence_refs": [{"seq": "2"}]}]
        prediction, error = normalize.normalise_single({
            "sample_id": "sample_000001", "response": json.dumps({
                "predicted_stage": "unknown", "reasoning_chain": chain, "confidence": 0.4,
            }),
        })
        self.assertEqual(prediction["predicted_stage"], "invalid_stage")
        self.assertEqual(prediction["reasoning_chain"][0]["claim"], chain[0]["claim"])
        self.assertEqual(prediction["reasoning_chain"][0]["evidence_refs"], [{"seq": 2}])
        self.assertEqual(prediction["confidence"], 0.4)
        self.assertEqual(error["reason"], "unparseable_predicted_stage")

    def test_identifiable_invalid_responses_keep_sample(self):
        for response in ("", "not JSON", "null", "[]", "1", None, []):
            with self.subTest(response=response):
                prediction, error = normalize.normalise_single({
                    "sample_id": "sample_000001", "response": response,
                })
                self.assertEqual(prediction["sample_id"], "sample_000001")
                self.assertEqual(prediction["predicted_stage"], "invalid_stage")
                self.assertEqual(prediction["reasoning_chain"], [])
                self.assertEqual(error["reason"], "json_extraction_failed")

    def test_empty_wrapper_does_not_fall_back_to_other_fields(self):
        prediction, error = normalize.normalise_single({
            "sample_id": "sample_000001", "response": "", "predicted_stage": "result",
            "output_raw": '{"predicted_stage":"result"}',
        })
        self.assertEqual(prediction["predicted_stage"], "invalid_stage")
        self.assertEqual(error["reason"], "json_extraction_failed")

    def test_openai_empty_content_keeps_sample(self):
        for content in ("", None, []):
            with self.subTest(content=content):
                prediction, error = normalize.normalise_single({
                    "sample_id": "sample_000001", "choices": [{"message": {"content": content}}],
                })
                self.assertEqual(prediction["predicted_stage"], "invalid_stage")
                self.assertIsNotNone(error)

    def test_reference_rows_are_rejected_directly_or_wrapped(self):
        reference = {
            "sample_id": "sample_000001", "task_mode": "ewvaa_reference_reasoning",
            "predicted_stage": "result", "reasoning_chain": [],
        }
        for row in (reference, {"sample_id": "sample_000001", "response": json.dumps(reference)},
                    {"sample_id": "sample_000001", "choices": [{"message": {"content": json.dumps(reference)}}]}):
            with self.subTest(row=row):
                prediction, error = normalize.normalise_single(row)
                self.assertIsNone(prediction)
                self.assertEqual(error["reason"], "ewvaa_reference_reasoning_is_not_model_prediction")

    def test_scalar_and_list_rows_are_rejected(self):
        for row in ([], [{"sample_id": "sample_000001", "predicted_stage": "result"}],
                    None, True, 4, "prediction"):
            with self.subTest(row=row):
                prediction, error = normalize.normalise_single(row)
                self.assertIsNone(prediction)
                self.assertEqual(error["reason"], "input_is_not_an_object")

    def test_anonymous_rows_are_not_assigned_ids(self):
        for row in ({"predicted_stage": "result"}, {"response": ""},
                    {"sample_id": " ", "predicted_stage": "result"}):
            with self.subTest(row=row):
                prediction, error = normalize.normalise_single(row)
                self.assertIsNone(prediction)
                self.assertEqual(error["reason"], "missing_sample_id")

    def test_fenced_prediction_can_supply_explicit_id(self):
        prediction, error = normalize.normalise_single({"response":
            '```json\n{"sample_id":"sample_000001","predicted_stage":"prep"}\n```'})
        self.assertIsNone(error)
        self.assertEqual(prediction["sample_id"], "sample_000001")
        self.assertEqual(prediction["predicted_stage"], "preparation")

    def test_cli_handles_mixed_rows_and_reports_retained_and_rejected(self):
        with tempfile.TemporaryDirectory(prefix="seclog_normalization_") as directory:
            workdir = Path(directory)
            source = workdir / "responses.jsonl"
            output = workdir / "predictions.jsonl"
            rows = [
                {"sample_id": "sample_000001", "predicted_stage": "preparation"},
                {"sample_id": "sample_000002", "response": ""},
                [], None, "text", {"predicted_stage": "result"},
                {"sample_id": "sample_000003", "task_mode": "ewvaa_reference_reasoning"},
            ]
            source.write_text("\n".join(json.dumps(row) for row in rows) + "\n{bad json\n", encoding="utf-8")
            messages = io.StringIO()
            with contextlib.redirect_stderr(messages):
                self.assertEqual(normalize.main(["--input", str(source), "--output", str(output)]), 0)
            predictions = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
            errors = [json.loads(line) for line in (workdir / "invalid_outputs.jsonl").read_text(encoding="utf-8").splitlines()]
            self.assertEqual([row["sample_id"] for row in predictions], ["sample_000001", "sample_000002"])
            self.assertEqual(len(errors), 7)
            self.assertEqual(errors[-1]["line_number"], 8)
            self.assertIn("valid_stages=1 retained_invalid_stages=1 rejected_rows=6 diagnostics=7", messages.getvalue())


if __name__ == "__main__":
    unittest.main()
