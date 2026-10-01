"""Offline workbench preparation and human-review handoff tests."""

from __future__ import annotations

import copy
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

UI_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(UI_ROOT))

from data_loader import load_workbench, make_draft_from_original, save_draft, smoke_check
from prepare_workbench import EVIDENCE_FILES, prepare_workbench, write_json, write_rows
from regression_check import run_regression_check
from review_packet import export_review_packet_for_sample
from review_status import default_status_for_row, validate_status_record
from validators import EXPECTED_CHAIN_STEPS
from writeback import write_single_sample_draft_to_final_candidate


class PreparationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="seclog-review-preparation-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.run = self.root / "annotation"
        self.masked = self.root / "compact"
        self.output = self.root / "review"
        self.make_inputs()

    def make_inputs(self, count=2, *, mapped=True):
        self.candidates = []
        self.evidence = {key: [] for key in EVIDENCE_FILES}
        sample_map, edge_map = [], []
        stages = ("preparation", "execution", "result", "stage_unclosed")
        for number in range(1, count + 1):
            sid = f"sample_{number:06d}"
            mid = f"sample_m_{number:06d}" if mapped else sid
            edge = f"edge_{number:06d}"
            masked_edge = f"edge_m_{number:06d}" if mapped else edge
            stage = stages[(number - 1) % len(stages)]
            candidate = {
                "sample_id": sid, "label": {"stage": stage},
                "gold_reasoning_chain": [
                    {"step": step, "claim": "The observed process opened a file.",
                     "evidence_refs": [{"edge_id": edge, "seq": 1}]}
                    for step in EXPECTED_CHAIN_STEPS
                ],
                "auxiliary_vulnerability_note": {"claim": "", "not_for_scoring": True},
            }
            spine = [{"edge_id": masked_edge, "seq": 1, "relation": "open",
                      "subject": "process", "object": "file", "audit_context": []}]
            self.candidates.append(candidate)
            self.evidence["model"].append({"sample_id": mid, "input": {"spine": copy.deepcopy(spine)}})
            self.evidence["gold"].append({"sample_id": mid, "label": {"stage": stage}})
            self.evidence["index"].append({"sample_id": mid, "stage": stage})
            self.evidence["prompt"].append({
                "sample_id": mid, "gold_stage": stage,
                "prompt_input": {"sample_id": mid, "gold_stage": stage,
                                 "primary_evidence": {"spine": copy.deepcopy(spine)}},
            })
            sample_map.append({"original": sid, "masked": mid})
            edge_map.append({"original": edge, "masked": masked_edge})
        write_json(self.masked / "id_maps/sample_id_map.json", {"items": sample_map if mapped else []})
        write_json(self.masked / "id_maps/edge_id_map.json", {"items": edge_map if mapped else []})
        self.persist_inputs()

    def persist_inputs(self):
        write_rows(self.run / "final_candidate_gold.jsonl", self.candidates)
        for name, filename in EVIDENCE_FILES.items():
            write_rows(self.masked / filename, self.evidence[name])

    def prepare(self, **kwargs):
        return prepare_workbench(self.run, self.masked, self.output, **kwargs)

    def assert_rejected(self, message):
        self.persist_inputs()
        with self.assertRaisesRegex(ValueError, message):
            self.prepare()
        self.assertFalse(self.output.exists())

    def test_missing_reviews_remain_pending_and_inputs_unchanged(self):
        before = {path: path.read_bytes() for folder in (self.run, self.masked)
                  for path in folder.rglob("*") if path.is_file()}
        summary = self.prepare()
        self.assertEqual(summary["candidate_count"], 2)
        bundle = load_workbench(self.output)
        self.assertFalse(bundle.warnings, bundle.warnings)
        for row in bundle.review_rows:
            self.assertEqual(row["review_status"], "not_reviewed")
            self.assertEqual(row["writeback_status"], "not_written_back")
            self.assertIsNone(row["candidate_index"]["strict_gold_allowed"])
            self.assertEqual(row["candidate_index"]["reviewer_verdict"], "pending")
            self.assertEqual(row["candidate_index"]["candidate_file"], "final_candidate_gold.jsonl")
            self.assertTrue(row["prompt_evidence"])
            self.assertTrue(row["strict_blind_input"])
            self.assertFalse(validate_status_record(default_status_for_row(row)))
        self.assertTrue(run_regression_check(self.output)["passed"])
        self.assertTrue(all(path.read_bytes() == data for path, data in before.items()))

    def test_216_rows_are_all_loaded(self):
        self.make_inputs(216)
        result = self.prepare(expected_count=216)
        self.assertEqual(result["stage_count"], dict.fromkeys(("preparation", "execution", "result", "stage_unclosed"), 54))
        check = smoke_check(self.output)
        self.assertTrue(check["passed"])
        self.assertEqual(check["reviewer_prompt_evidence_loaded_count"], 216)
        self.assertEqual(check["strict_blind_input_loaded_count"], 216)
        self.assertEqual(len(load_workbench(self.output).review_rows), 216)

    def test_candidate_ids_can_already_match_evidence(self):
        self.make_inputs(mapped=False)
        (self.masked / "id_maps/sample_id_map.json").unlink()
        (self.masked / "id_maps/edge_id_map.json").unlink()
        self.prepare()
        self.assertEqual(len(load_workbench(self.output).review_rows), 2)

    def test_actual_compact_prompt_builder_output_is_accepted(self):
        source = UI_ROOT.parent / "results_analysis/release/build_ewvaa_masked_workbench.py"
        spec = importlib.util.spec_from_file_location("compact_builder_test", source)
        builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(builder)
        config = dict(builder.DEFAULT_COMPACT_CONFIG, compact_version="v2",
                      stage_adaptive_budget=True, modality_floor=True, reviewer_more_evidence=True)
        for index in range(len(self.candidates)):
            prompt, _ = builder.build_prompt_row(self.evidence["model"][index],
                                                 self.evidence["gold"][index], None, config, "reviewer")
            self.evidence["prompt"][index] = prompt
        self.persist_inputs()
        self.prepare()
        self.assertTrue(smoke_check(self.output)["passed"])

    def test_supplied_diagnostics_are_joined_without_human_approval(self):
        write_rows(self.run / "reviewer_judge_outputs.jsonl",
                   [{"sample_id": "sample_m_000001", "verdict": "major_revision"}])
        write_rows(self.run / "reviewer_weighted_grounding_cases.jsonl",
                   [{"sample_id": "sample_000001", "strict_gold_allowed": False, "verdict": "weak"}])
        write_json(self.run / "reviewer_weighted_grounding_report.json", {"status": "success"})
        write_rows(self.run / "manual_review_required.jsonl",
                   [{"sample_id": "sample_000001", "reason": "check_action"},
                    {"sample_id": "sample_000001", "reason": "check_timing"}])
        self.prepare()
        row = load_workbench(self.output).review_rows[0]
        self.assertEqual(row["candidate_index"]["reviewer_verdict"], "major_revision")
        self.assertFalse(row["candidate_index"]["strict_gold_allowed"])
        self.assertEqual(row["weighted_case"]["verdict"], "weak")
        self.assertEqual(row["review_status"], "not_reviewed")
        self.assertEqual(row["effective_review_priority"], "high")
        self.assertIn("check_timing", row["candidate_index"]["reason_codes"])

    def test_draft_packet_and_writeback_use_only_local_copy(self):
        self.prepare()
        source = (self.run / "final_candidate_gold.jsonl").read_bytes()
        row = load_workbench(self.output).review_rows[0]
        draft = make_draft_from_original(row)
        draft["draft_reasoning_chain"][0]["claim"] = "The observed process opened the recorded file."
        self.assertTrue(save_draft(self.output, row, draft)["saved"])
        packet = export_review_packet_for_sample(workbench_dir=self.output, sample_id=row["sample_id"])
        self.assertTrue(packet["ok"])
        self.assertTrue(packet["packet"]["strict_blind_evidence"]["available"])
        check = run_regression_check(self.output, row["sample_id"], include_writeback_dry_run=True)
        self.assertTrue(check["passed"], check)
        result = write_single_sample_draft_to_final_candidate(
            workbench_dir=str(self.output), sample_id=row["sample_id"], dry_run=False, confirm_writeback=True)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["changed_sample_count"], 1)
        self.assertEqual((self.run / "final_candidate_gold.jsonl").read_bytes(), source)
        refreshed = load_workbench(self.output)
        self.assertEqual(refreshed.review_rows[0]["candidate"]["gold_reasoning_chain"][0]["claim"],
                         draft["draft_reasoning_chain"][0]["claim"])
        self.assertEqual(refreshed.review_rows[1]["candidate"], self.candidates[1])

    def test_duplicate_candidates_rejected(self):
        self.candidates.append(copy.deepcopy(self.candidates[0]))
        self.assert_rejected("duplicate sample_id")

    def test_incomplete_fixed_chain_rejected(self):
        self.candidates[0]["gold_reasoning_chain"].pop()
        self.assert_rejected("complete four-step")

    def test_extra_reference_fields_rejected(self):
        self.candidates[0]["gold_reasoning_chain"][0]["evidence_refs"][0]["extra"] = "not editable"
        self.assert_rejected("malformed evidence reference")

    def test_missing_prompt_rejected_before_output(self):
        self.evidence["prompt"].pop()
        self.assert_rejected("missing prompt")

    def test_stage_mismatch_rejected(self):
        self.evidence["index"][0]["stage"] = "result"
        self.assert_rejected("stages disagree")

    def test_reference_requires_matching_edge_and_seq(self):
        self.candidates[0]["gold_reasoning_chain"][0]["evidence_refs"][0]["seq"] = 2
        self.assert_rejected("absent from full evidence")

    def test_compact_edge_must_exist_in_same_window(self):
        self.evidence["prompt"][0]["prompt_input"]["primary_evidence"]["spine"][0]["edge_id"] = "missing"
        self.assert_rejected("compact evidence edges are absent")

    def test_incomplete_reasoning_is_flagged_not_approved(self):
        self.candidates[0]["gold_reasoning_chain"][0]["claim"] = ""
        self.persist_inputs()
        self.prepare()
        bundle = load_workbench(self.output)
        self.assertTrue(bundle.p5_35["sample_diagnostics"][0]["structural_findings"])
        self.assertEqual(bundle.review_rows[0]["review_status"], "not_reviewed")

    def test_count_mismatch_and_existing_output_rejected(self):
        with self.assertRaisesRegex(ValueError, "Expected 216"):
            self.prepare(expected_count=216)
        self.assertFalse(self.output.exists())
        self.prepare()
        with self.assertRaises(FileExistsError):
            self.prepare()

    def test_output_cannot_be_inside_inputs(self):
        with self.assertRaisesRegex(ValueError, "separate"):
            prepare_workbench(self.run, self.masked, self.run / "review")

    def test_cli_handles_missing_candidate_without_creating_output(self):
        result = subprocess.run([sys.executable, "-B", str(UI_ROOT / "prepare_workbench.py"),
                                 "--run-dir", str(self.root / "missing"), "--masked-workbench", str(self.masked),
                                 "--output-dir", str(self.output)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("final_candidate_gold.jsonl", result.stderr)
        self.assertFalse(self.output.exists())

    def test_cli_accepts_relative_paths(self):
        result = subprocess.run([sys.executable, "-B", str(UI_ROOT / "prepare_workbench.py"),
                                 "--run-dir", "annotation", "--masked-workbench", "compact",
                                 "--output-dir", "review", "--expected-count", "2"],
                                cwd=self.root, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["candidate_count"], 2)
        self.assertTrue(smoke_check(self.output)["passed"])


if __name__ == "__main__":
    unittest.main()
