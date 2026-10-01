"""Synthetic tests for reasoning-quality metrics and scoring input contracts."""
from __future__ import annotations

import argparse
import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


EVALUATION_DIR = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("score_quality", EVALUATION_DIR / "score_reasoning_quality.py")
score = importlib.util.module_from_spec(SPEC)
sys.path.insert(0, str(EVALUATION_DIR))
try:
    SPEC.loader.exec_module(score)
finally:
    sys.path.pop(0)


def fixture():
    sid = "sample_000001"
    gold = [{"sample_id": sid, "gold_stage": "result"}]
    predictions = [{"sample_id": sid, "predicted_stage": "result", "reasoning_chain": [
        {"claim": "An outcome is visible.", "evidence_refs": [{"seq": 1}]},
    ]}]
    claims = [{
        "sample_id": sid, "reasoning_unit_id": "unit_01", "claim_type": "outcome_inference",
        "is_substantive_claim": True, "evidence_support": "fully_supported",
        "evidence_ref_validity": "valid", "overstatement_level": "none",
    }]
    closures = [{
        "sample_id": sid, "scoring_ready": True, "unresolved_disagreement_count": 0,
        "boundary_discipline": "sound", "stage_closure_coverage_score": 0.0,
        "checklist_coverage": [{
            "condition_id": "condition_01", "importance": "key", "coverage_score": 1.0,
            "covered_by_reasoning_unit_ids": ["unit_01"],
        }],
    }]
    return gold, predictions, claims, closures


class ScoringTests(unittest.TestCase):
    def run_score(self, gold, predictions, claims, closures):
        with tempfile.TemporaryDirectory(prefix="seclog_scoring_") as directory:
            workdir = Path(directory)
            values = {"gold": gold, "predictions": predictions, "claim_checks": claims, "closure_checks": closures}
            arguments = {}
            for name, rows in values.items():
                path = workdir / f"{name}.jsonl"
                path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
                arguments[name] = path
            arguments["output_dir"] = workdir / "scores"
            with patch.object(score, "parse_args", return_value=argparse.Namespace(**arguments)):
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(score.main(), 0)
            output_dir = arguments["output_dir"]
            samples = [json.loads(line) for line in (output_dir / "reasoning_metrics_by_sample.jsonl").read_text(encoding="utf-8").splitlines()]
            summary = json.loads((output_dir / "metrics_summary.json").read_text(encoding="utf-8"))
            return samples, summary

    def test_partial_condition_has_half_scc_and_distinct_stage_contribution(self):
        gold, predictions, claims, closures = fixture()
        closures[0]["checklist_coverage"][0]["coverage_score"] = 0.5
        samples, _ = self.run_score(gold, predictions, claims, closures)
        self.assertEqual(samples[0]["scc"], 0.5)
        self.assertEqual(samples[0]["srp"], 0.65)
        self.assertTrue(samples[0]["reasoning_reliable"])

    def test_scc_uses_key_conditions_not_overall_score_or_optional_conditions(self):
        _, _, _, closures = fixture()
        closures[0]["checklist_coverage"].extend([
            {"condition_id": "condition_02", "importance": "key", "coverage_score": 0.5},
            {"condition_id": "condition_03", "importance": "optional", "coverage_score": 0.0},
        ])
        self.assertEqual(score.stage_condition_coverage(closures[0]), 0.75)

    def test_invalid_coverage_scores_are_rejected(self):
        for value in (float("nan"), float("inf"), float("-inf"), -0.1, 1.1, True, "0.5", None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                score.condition_coverage_score({"coverage_score": value})

    def test_checklist_contract_is_required(self):
        base = fixture()[3][0]
        invalids = []
        for changes in ({"checklist_coverage": []}, {"checklist_coverage": None}):
            invalids.append({**base, **changes})
        for mutation in ("optional_only", "missing_importance", "missing_score", "duplicate_condition"):
            row = copy.deepcopy(base)
            item = row["checklist_coverage"][0]
            if mutation == "optional_only":
                item["importance"] = "optional"
            elif mutation == "missing_importance":
                del item["importance"]
            elif mutation == "missing_score":
                del item["coverage_score"]
            else:
                row["checklist_coverage"].append(copy.deepcopy(item))
            invalids.append(row)
        for row in invalids:
            with self.subTest(row=row), self.assertRaises(ValueError):
                score.stage_condition_coverage(row)

    def test_unreviewed_closures_cannot_be_scored(self):
        for changes in ({"scoring_ready": False}, {"scoring_ready": 1},
                        {"unresolved_disagreement_count": 1}, {"unresolved_disagreement_count": None}):
            rows = fixture()
            rows[3][0].update(changes)
            with self.subTest(changes=changes), self.assertRaisesRegex(ValueError, "scoring-ready"):
                self.run_score(*rows)
        rows = fixture()
        del rows[3][0]["scoring_ready"]
        with self.assertRaisesRegex(ValueError, "scoring-ready"):
            self.run_score(*rows)

    def test_background_claim_risks_still_make_sample_unreliable(self):
        risks = [
            {"critical_evidence_error": True}, {"contradiction": True},
            {"hidden_evidence_use": True}, {"out_of_window_evidence": True},
            {"evidence_support": "contradicted"}, {"evidence_ref_validity": "invalid"},
        ]
        for risk in risks:
            gold, predictions, claims, closures = fixture()
            predictions[0]["reasoning_chain"].append({"claim": "A background claim.", "evidence_refs": []})
            claims.append({**claims[0], "reasoning_unit_id": "unit_02", "is_substantive_claim": False,
                           "claim_type": "background", **risk})
            with self.subTest(risk=risk):
                samples, _ = self.run_score(gold, predictions, claims, closures)
                self.assertEqual(samples[0]["srp"], 1.0)
                self.assertFalse(samples[0]["reasoning_reliable"])
                self.assertEqual(samples[0]["ttff"], "TF")
                risk_field = "sample_level_invalid_evidence_refs" if "evidence_ref_validity" in risk else "sample_level_critical_evidence_error"
                self.assertTrue(samples[0][risk_field])

    def test_empty_reasoning_and_invalid_stage_are_valid_scoring_inputs(self):
        gold, predictions, _, closures = fixture()
        predictions[0].update({"predicted_stage": "invalid_stage", "reasoning_chain": []})
        closures[0]["checklist_coverage"][0].update({"coverage_score": 0.0, "covered_by_reasoning_unit_ids": []})
        samples, summary = self.run_score(gold, predictions, [], closures)
        self.assertEqual(samples[0]["srp"], 0.0)
        self.assertEqual(samples[0]["scc"], 0.0)
        self.assertEqual(samples[0]["ttff"], "FF")
        self.assertEqual(summary["stage_prediction"]["accuracy"], 0.0)

    def test_gold_predictions_and_closure_sets_must_be_identical_nonempty_and_unique(self):
        with self.assertRaisesRegex(ValueError, "nonempty"):
            self.run_score([], [], [], [])
        for index in (0, 1, 3):
            for mutation in ("missing", "extra", "duplicate"):
                rows = fixture()
                if mutation == "missing":
                    rows[index].clear()
                elif mutation == "duplicate":
                    rows[index].append(copy.deepcopy(rows[index][0]))
                else:
                    extra = copy.deepcopy(rows[index][0])
                    extra["sample_id"] = "sample_000002"
                    rows[index].append(extra)
                with self.subTest(index=index, mutation=mutation), self.assertRaises(ValueError):
                    self.run_score(*rows)

    def test_claim_units_must_exactly_match_prediction_units(self):
        for mutation in ("missing", "duplicate", "unknown_unit", "unknown_sample"):
            rows = fixture()
            if mutation == "missing":
                rows[2].clear()
            elif mutation == "duplicate":
                rows[2].append(copy.deepcopy(rows[2][0]))
            elif mutation == "unknown_unit":
                rows[2][0]["reasoning_unit_id"] = "unit_02"
            else:
                rows[2][0]["sample_id"] = "sample_000002"
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.run_score(*rows)

    def test_checklist_cannot_reference_unknown_or_duplicate_units(self):
        for units in (["unit_02"], ["unit_01", "unit_01"], None, [["unit_01"]]):
            rows = fixture()
            rows[3][0]["checklist_coverage"][0]["covered_by_reasoning_unit_ids"] = units
            with self.subTest(units=units), self.assertRaises(ValueError):
                self.run_score(*rows)

    def test_model_srf1_uses_model_mean_srp_and_scc(self):
        first = fixture()
        second = fixture()
        for collection in second:
            for row in collection:
                row["sample_id"] = "sample_000002"
        second[3][0]["checklist_coverage"][0]["coverage_score"] = 0.5
        samples, summary = self.run_score(*(a + b for a, b in zip(first, second)))
        expected = score.harmonic_mean((1.0 + 0.65) / 2, (1.0 + 0.5) / 2)
        self.assertAlmostEqual(summary["reasoning_quality"]["srf1"], expected)
        self.assertNotAlmostEqual(expected, sum(row["srf1"] for row in samples) / 2)


if __name__ == "__main__":
    unittest.main()
