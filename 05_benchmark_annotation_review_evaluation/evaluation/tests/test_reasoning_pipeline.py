"""CLI integration tests using synthetic judgments, never live model results.

The 216-sample test reads the released evidence, references, and labels without
changing them. Its predictions and condition judgments are synthetic fixtures
for interface validation, not estimates of model performance.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


EVALUATION_DIR = Path(__file__).resolve().parents[1]
BENCHMARK_DATA = EVALUATION_DIR.parents[1] / "SecLog-Bench-216" / "data"


def read_jsonl(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def write_jsonl(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows), encoding="utf-8")


def first_ref(evidence):
    spine = (evidence.get("input") or {}).get("spine")
    if spine is None:
        spine = evidence.get("selected_spine", [])
    if not spine:
        raise AssertionError("test fixture requires at least one visible edge")
    return {key: spine[0][key] for key in ("seq", "edge_id") if key in spine[0]}


class ReasoningPipelineTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="seclog_reasoning_pipeline_")
        self.addCleanup(self.temporary.cleanup)
        self.workdir = Path(self.temporary.name)

    def cli(self, script, arguments, expected=0):
        result = subprocess.run(
            [sys.executable, "-B", str(EVALUATION_DIR / script), *map(str, arguments)],
            cwd=self.workdir, capture_output=True, text=True, encoding="utf-8", timeout=60,
        )
        self.assertEqual(result.returncode, expected, result.stdout + "\n" + result.stderr)
        return result

    def prepare(self, response=None, benchmark=False):
        if benchmark:
            evidence_path = BENCHMARK_DATA / "evidence_windows.jsonl"
            references_path = BENCHMARK_DATA / "reference_reasoning_chains.jsonl"
            self.gold_path = BENCHMARK_DATA / "gold_labels.jsonl"
        else:
            sid = "sample_000001"
            evidence_path = self.workdir / "evidence.jsonl"
            references_path = self.workdir / "references.jsonl"
            self.gold_path = self.workdir / "gold.jsonl"
            visible_ref = {"seq": 1, "edge_id": "edge_01"}
            write_jsonl(evidence_path, [{"sample_id": sid, "input": {"spine": [visible_ref]}}])
            write_jsonl(references_path, [{
                "sample_id": sid, "gold_stage": "result", "reference_reasoning_chain": [
                    {"claim": "Synthetic reference condition.", "evidence_refs": [visible_ref]},
                ],
            }])
            write_jsonl(self.gold_path, [{"sample_id": sid, "gold_stage": "result"}])

        evidence_rows = read_jsonl(evidence_path)
        raw = []
        for index, evidence in enumerate(evidence_rows):
            prediction = {
                "sample_id": evidence["sample_id"], "predicted_stage": "preparation",
                "reasoning_chain": [{"step": "analysis", "claim": "Synthetic test claim.",
                                     "evidence_refs": [first_ref(evidence)]}],
            }
            if benchmark and index == 0:
                raw_response = ""
            else:
                if benchmark and index == 1:
                    prediction["predicted_stage"] = "unparseable test stage"
                if benchmark and index == 2:
                    del prediction["reasoning_chain"][0]["step"]
                raw_response = json.dumps(prediction)
            if response is not None:
                raw_response = response
            raw.append({"sample_id": evidence["sample_id"], "response": raw_response})
        raw_path = self.workdir / "raw_predictions.jsonl"
        self.prediction_path = self.workdir / "predictions.jsonl"
        write_jsonl(raw_path, raw)
        self.cli("normalize_stage_reasoning_predictions.py", ["--input", raw_path, "--output", self.prediction_path])

        reference_dir = self.workdir / "reference_packets"
        self.cli("prepare_reasoning_quality_inputs.py", [
            "--reference-only", "--evidence-windows", evidence_path,
            "--reference-chains", references_path, "--output-dir", reference_dir,
        ])
        reference_packets = read_jsonl(reference_dir / "reference_condition_packets.jsonl")
        self.assertTrue(all("predicted_stage" not in packet and "reasoning_units" not in packet for packet in reference_packets))
        conditions_path = self.workdir / "conditions.jsonl"
        write_jsonl(conditions_path, [{
            "sample_id": packet["sample_id"], "stage_conditions": [{
                "condition_id": "condition_01", "importance": "key",
                "description": "Synthetic shared condition for interface testing.",
                "evidence_refs": [first_ref(packet["evidence_window"])],
            }],
        } for packet in reference_packets])
        prepared_dir = self.workdir / "prepared"
        self.cli("prepare_reasoning_quality_inputs.py", [
            "--predictions", self.prediction_path, "--evidence-windows", evidence_path,
            "--reference-chains", references_path, "--stage-conditions", conditions_path,
            "--output-dir", prepared_dir,
        ])
        self.packets_path = prepared_dir / "assistant_packets.jsonl"
        self.packets = read_jsonl(self.packets_path)
        self.runs = [self.assistant_run("synthetic_assistant_1"), self.assistant_run("synthetic_assistant_2")]

    def assistant_run(self, assistant_id):
        rows = []
        for packet in self.packets:
            unit_ids = [unit["reasoning_unit_id"] for unit in packet["reasoning_units"]]
            rows.append({
                "sample_id": packet["sample_id"], "blind_model_id": packet["blind_model_id"],
                "assistant_id": assistant_id,
                "claim_checks": [{
                    "reasoning_unit_id": unit["reasoning_unit_id"], "claim_type": unit["claim_type"],
                    "is_substantive_claim": True, "evidence_support": "fully_supported",
                    "evidence_support_score": 1.0, "stage_condition_alignment": 1.0,
                    "evidence_ref_validity": "valid", "critical_evidence_error": False,
                    "contradiction": False, "hidden_evidence_use": False,
                    "out_of_window_evidence": False, "overstatement_level": "none",
                } for unit in packet["reasoning_units"]],
                "closure_check": {
                    "stage_closure_coverage_score": 1.0, "boundary_discipline": "sound",
                    "sample_level_critical_evidence_error": False, "sample_level_invalid_evidence_refs": False,
                    "checklist_coverage": [{
                        "condition_id": condition["condition_id"], "importance": condition["importance"],
                        "coverage": "full" if unit_ids else "none",
                        "covered_by_reasoning_unit_ids": unit_ids,
                    } for condition in packet["stage_conditions"]],
                },
            })
        return rows

    def aggregate(self, runs=None, adjudications=None, expected=0, preview=False):
        checks = []
        for index, rows in enumerate(self.runs if runs is None else runs):
            path = self.workdir / f"assistant_{index}.jsonl"
            write_jsonl(path, rows)
            checks.extend(["--assistant-checks", path])
        self.aggregated_dir = self.workdir / "aggregated"
        arguments = [*checks, "--assistant-packets", self.packets_path, "--output-dir", self.aggregated_dir]
        if adjudications is not None:
            path = self.workdir / "adjudications.jsonl"
            write_jsonl(path, adjudications)
            arguments.extend(["--adjudications", path])
        if preview:
            arguments.append("--allow-unadjudicated")
        return self.cli("aggregate_reasoning_assistant_checks.py", arguments, expected)

    def score(self, expected=0):
        output_dir = self.workdir / "scores"
        result = self.cli("score_reasoning_quality.py", [
            "--gold", self.gold_path, "--predictions", self.prediction_path,
            "--claim-checks", self.aggregated_dir / "claim_checks.aggregated.jsonl",
            "--closure-checks", self.aggregated_dir / "closure_checks.aggregated.jsonl",
            "--output-dir", output_dir,
        ], expected)
        if expected:
            return result
        return read_jsonl(output_dir / "reasoning_metrics_by_sample.jsonl")

    def test_partial_coverage_not_assistant_overall_score(self):
        self.prepare()
        for index, run in enumerate(self.runs):
            run[0]["closure_check"]["stage_closure_coverage_score"] = float(index)
            run[0]["closure_check"]["checklist_coverage"][0]["coverage"] = "partial"
        self.aggregate()
        closure = read_jsonl(self.aggregated_dir / "closure_checks.aggregated.jsonl")[0]
        self.assertEqual(closure["stage_closure_coverage_score"], 0.5)
        self.assertTrue(closure["scoring_ready"])
        samples = self.score()
        self.assertEqual(samples[0]["scc"], 0.5)
        self.assertEqual(samples[0]["srp"], 0.65)

    def test_condition_disagreement_blocks_until_adjudicated(self):
        self.prepare()
        self.runs[1][0]["closure_check"]["checklist_coverage"][0].update({
            "coverage": "none", "covered_by_reasoning_unit_ids": [],
        })
        self.aggregate(expected=2)
        closure = read_jsonl(self.aggregated_dir / "closure_checks.aggregated.jsonl")[0]
        self.assertFalse(closure["scoring_ready"])
        self.assertEqual(closure["unresolved_disagreement_count"], 1)
        self.assertIn("not scoring-ready", self.score(expected=1).stderr)
        self.aggregate(preview=True)
        self.assertIn("not scoring-ready", self.score(expected=1).stderr)
        self.aggregate(adjudications=[{
            "sample_id": "sample_000001", "field": "stage_condition:condition_01", "value": 0.5,
        }])
        self.assertEqual(self.score()[0]["scc"], 0.5)

    def test_assistant_condition_and_unit_mismatches_are_rejected(self):
        self.prepare()
        for target in ("condition_missing", "condition_unknown", "condition_duplicate",
                       "unit_missing", "unit_unknown", "unit_duplicate"):
            runs = copy.deepcopy(self.runs)
            row = runs[0][0]
            if target.startswith("condition"):
                items = row["closure_check"]["checklist_coverage"]
                key = "condition_id"
            else:
                items = row["claim_checks"]
                key = "reasoning_unit_id"
            if target.endswith("missing"):
                items.clear()
            elif target.endswith("unknown"):
                items[0][key] = "unknown_test_identifier"
            else:
                items.append(copy.deepcopy(items[0]))
            with self.subTest(target=target):
                self.aggregate(runs=runs, expected=1)

    def test_duplicate_and_stale_adjudications_are_rejected(self):
        self.prepare()
        valid = {"sample_id": "sample_000001", "field": "stage_condition:condition_01", "value": 0.5}
        for adjudications in ([valid, valid], [{**valid, "field": "stage_condition:unknown"}],
                             [{**valid, "sample_id": "sample_unknown"}]):
            with self.subTest(adjudications=adjudications):
                self.aggregate(adjudications=adjudications, expected=1)

    def test_zero_reasoning_has_zero_srp_and_scc(self):
        self.prepare(response="")
        self.assertEqual(self.packets[0]["reasoning_units"], [])
        self.aggregate()
        sample = self.score()[0]
        self.assertEqual(sample["predicted_stage"], "invalid_stage")
        self.assertEqual((sample["srp"], sample["scc"], sample["srf1"]), (0.0, 0.0, 0.0))
        self.assertEqual(sample["ttff"], "FF")

    def test_local_invalid_reference_overrides_assistant_valid_judgment(self):
        self.prepare(response=json.dumps({
            "predicted_stage": "result", "reasoning_chain": [{
                "claim": "Synthetic unsupported reference.",
                "evidence_refs": [{"seq": 9999, "edge_id": "edge_not_visible"}],
            }],
        }))
        self.assertTrue(self.packets[0]["reasoning_units"][0]["local_invalid_evidence_refs"])
        self.aggregate()
        sample = self.score()[0]
        self.assertTrue(sample["sample_level_invalid_evidence_refs"])
        self.assertFalse(sample["reasoning_reliable"])
        self.assertEqual(sample["scc"], 0.0)
        self.assertEqual(sample["ttff"], "TF")

    def test_missing_references_cannot_be_declared_valid(self):
        self.prepare(response=json.dumps({
            "predicted_stage": "result", "reasoning_chain": [{
                "claim": "Synthetic uncited fact.", "evidence_refs": [],
            }],
        }))
        self.aggregate()
        claims = read_jsonl(self.aggregated_dir / "claim_checks.aggregated.jsonl")
        self.assertEqual(claims[0]["evidence_ref_validity"], "missing_refs")
        self.assertEqual(self.score()[0]["srp"], 0.4)

    def test_216_cli_pipeline_with_real_evidence_and_synthetic_judgments(self):
        self.assertTrue(BENCHMARK_DATA.is_dir(), "released Benchmark data is required")
        self.prepare(benchmark=True)
        expected_ids = [f"sample_{index:06d}" for index in range(1, 217)]
        self.assertEqual([packet["sample_id"] for packet in self.packets], expected_ids)
        predictions = read_jsonl(self.prediction_path)
        self.assertEqual(len(predictions), 216)
        self.assertEqual(predictions[0]["reasoning_chain"], [])
        self.assertEqual(predictions[1]["predicted_stage"], "invalid_stage")
        self.assertEqual(len(predictions[1]["reasoning_chain"]), 1)
        self.assertNotIn("step", predictions[2]["reasoning_chain"][0])
        self.assertEqual(predictions[3]["reasoning_chain"][0]["step"], "analysis")
        stage_output = self.workdir / "stage_scores"
        self.cli("evaluate_stage_reasoning_predictions.py", [
            "--gold", self.gold_path, "--predictions", self.prediction_path,
            "--model-input", BENCHMARK_DATA / "evidence_windows.jsonl",
            "--sample-index", BENCHMARK_DATA / "sample_index.jsonl",
            "--reference-chains", BENCHMARK_DATA / "reference_reasoning_chains.jsonl",
            "--output-dir", stage_output,
        ])
        stage_rows = read_jsonl(stage_output / "per_sample_results.jsonl")
        self.assertEqual(len(stage_rows), 216)
        self.assertEqual([row["sample_id"] for row in stage_rows], expected_ids)
        self.aggregate()
        samples = self.score()
        self.assertEqual([sample["sample_id"] for sample in samples], expected_ids)
        self.assertEqual(samples[0]["srp"], 0.0)
        self.assertEqual(samples[0]["scc"], 0.0)
        self.assertEqual(samples[1]["predicted_stage"], "invalid_stage")
        self.assertTrue(all(sample["srp"] == 1.0 for sample in samples[1:]))
        summary = json.loads((self.workdir / "scores" / "metrics_summary.json").read_text(encoding="utf-8"))
        self.assertEqual(summary["sample_count"], 216)
        self.assertEqual(sum(summary["prediction_reasoning_consistency"].values()), 216)

    def test_prompt_generation_allows_free_reasoning(self):
        output = self.workdir / "prompts.jsonl"
        self.cli("make_stage_reasoning_prompt_pack.py", [
            "--model-input", BENCHMARK_DATA / "evidence_windows.jsonl",
            "--output", output, "--mode", "cot", "--limit", 1,
        ])
        prompt = read_jsonl(output)[0]["prompt"]
        self.assertNotIn("all four steps", prompt.lower())
        self.assertIn("empty", prompt.lower())

    def test_compact_prompt_preserves_release_level_edge_fields(self):
        output = self.workdir / "compact_prompts.jsonl"
        self.cli("make_stage_reasoning_prompt_pack.py", [
            "--model-input", BENCHMARK_DATA / "evidence_windows.jsonl",
            "--output", output, "--mode", "direct", "--compact", "--limit", 1,
        ])
        prompt = read_jsonl(output)[0]["prompt"]
        self.assertIn('"timestamp"', prompt)
        self.assertIn('"raw_evt_type"', prompt)
        self.assertIn('"container_id"', prompt)


if __name__ == "__main__":
    unittest.main()
