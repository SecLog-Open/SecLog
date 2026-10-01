"""Tests for portable workbench loading and single-sample writeback."""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from data_loader import (
    REQUIRED_ROOT_FILES,
    get_sample_detail,
    load_workbench,
    make_draft_from_original,
    save_draft,
    smoke_check,
)
from validators import EXPECTED_CHAIN_STEPS
from writeback import resolve_workbench_path, write_single_sample_draft_to_final_candidate


@contextlib.contextmanager
def working_directory(path: Path):
    previous = Path.cwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(previous)


def write_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


class WorkbenchPathTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="seclog-workbench-paths-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.workbench = self.root / "workbench"
        self.unrelated = self.root / "unrelated"
        self.unrelated.mkdir()
        self.original = self.root / "original_candidates.jsonl"
        self.config = {
            "path_base": "workbench",
            "self_contained": True,
            "formal_candidate_gold": "final_candidate_gold.jsonl",
            "compact_evidence": {"reviewer_prompt_pack": "prompts/reviewer.jsonl"},
            "strict_blind_evidence": {
                "model_input": "evidence/model_input.jsonl",
                "sample_index": "evidence/sample_index.jsonl",
            },
        }
        self.candidates = [
            {
                "sample_id": sample_id,
                "label": {"stage": "Initial Access"},
                "gold_reasoning_chain": [
                    {
                        "step": step,
                        "claim": f"Observed evidence for {step}.",
                        "evidence_refs": [{"seq": 1, "edge_id": "edge_000001"}],
                    }
                    for step in EXPECTED_CHAIN_STEPS
                ],
                "auxiliary_vulnerability_note": {"claim": "", "not_for_scoring": True},
                "candidate_status": "manual_review_required",
                "clean_final": False,
            }
            for sample_id in ("sample_000001", "sample_000002")
        ]
        self.index = [
            {
                "sample_id": row["sample_id"],
                "masked_sample_id": row["sample_id"],
                "candidate_file": "final_candidate_gold.jsonl",
                "candidate_row_index": number,
                "run_dir_path": ".",
                "gold_stage": row["label"]["stage"],
            }
            for number, row in enumerate(self.candidates, 1)
        ]
        write_jsonl(self.original, self.candidates)
        self.workbench.mkdir()
        shutil.copyfile(self.original, self.workbench / "final_candidate_gold.jsonl")
        self._write_index()
        write_json(self.workbench / "review_ui_loader_config.json", self.config)
        write_json(self.workbench / REQUIRED_ROOT_FILES["summary"], {"candidate_count": 2})
        for name, key in (
            ("p5_35", "sample_diagnostics"),
            ("p5_37", "sample_dry_run_table"),
            ("p5_38", "review_sheet"),
        ):
            write_json(self.workbench / REQUIRED_ROOT_FILES[name], {key: []})
        evidence_rows = [{"sample_id": row["sample_id"], "evidence": []} for row in self.candidates]
        write_jsonl(self.workbench / "prompts/reviewer.jsonl", evidence_rows)
        write_jsonl(self.workbench / "evidence/model_input.jsonl", evidence_rows)
        write_jsonl(self.workbench / "evidence/sample_index.jsonl", evidence_rows)

    def _write_index(self):
        write_jsonl(self.workbench / REQUIRED_ROOT_FILES["candidate_index"], self.index)

    def _save_changed_draft(self):
        row = get_sample_detail(load_workbench(self.workbench), "sample_000001")
        self.assertIsNotNone(row)
        draft = make_draft_from_original(row)
        draft["draft_reasoning_chain"][0]["claim"] = "The observed process started a child process."
        result = save_draft(self.workbench, row, draft)
        self.assertTrue(result["saved"], result.get("errors"))
        return result["draft"]

    def _writeback(self, **kwargs):
        return write_single_sample_draft_to_final_candidate(
            workbench_dir=str(self.workbench), sample_id="sample_000001", **kwargs
        )

    def test_load_from_unrelated_directory_ignores_same_named_files(self):
        write_jsonl(self.unrelated / "final_candidate_gold.jsonl", [{"sample_id": "wrong"}])
        with working_directory(self.unrelated):
            result = smoke_check(self.workbench)
            self.assertTrue(result["passed"], result["failures"])
            self.assertEqual(result["strict_blind_input_loaded_count"], 2)
            bundle = load_workbench(self.workbench)
        self.assertEqual(bundle.final_candidates_by_sample_id["sample_000001"], self.candidates[0])
        self.assertEqual(bundle.review_rows[0]["run_dir_path"], ".")

    def test_single_writeback_changes_only_workbench_candidate(self):
        original_bytes = self.original.read_bytes()
        target = self.workbench / "final_candidate_gold.jsonl"
        other_line = target.read_bytes().splitlines(keepends=True)[1]
        decoy = self.unrelated / "final_candidate_gold.jsonl"
        decoy.write_bytes(original_bytes)
        with working_directory(self.unrelated):
            self._save_changed_draft()
            preview = self._writeback(dry_run=True)
            self.assertTrue(preview["ok"], preview)
            self.assertEqual(target.read_bytes(), original_bytes)
            result = self._writeback(dry_run=False, confirm_writeback=True)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["changed_sample_count"], 1)
        self.assertEqual(result["changed_line_count"], 1)
        self.assertEqual(target.read_bytes().splitlines(keepends=True)[1], other_line)
        self.assertEqual(self.original.read_bytes(), original_bytes)
        self.assertEqual(decoy.read_bytes(), original_bytes)
        self.assertEqual(result["target_final_candidate_gold_path"], "final_candidate_gold.jsonl")

    def test_saved_draft_moves_with_workbench(self):
        with working_directory(self.unrelated):
            draft = self._save_changed_draft()
        self.assertEqual(draft["source_run_dir"], ".")
        self.assertEqual(draft["source_final_candidate_gold_path"], "final_candidate_gold.jsonl")
        moved = self.root / "relocated"
        self.workbench.rename(moved)
        self.workbench = moved
        with working_directory(self.root):
            self.assertEqual(len(load_workbench(moved).latest_drafts_by_sample_id), 1)
            result = self._writeback(dry_run=False, confirm_writeback=True)
        self.assertTrue(result["ok"], result)

    def test_relative_run_directory_preserves_draft_identity(self):
        for row in self.index:
            row["run_dir_path"] = "multiagent_api_review"
        (self.workbench / "multiagent_api_review").mkdir()
        self._write_index()
        with working_directory(self.unrelated):
            draft = self._save_changed_draft()
            self.assertEqual(draft["source_run_dir"], "multiagent_api_review")
            self.assertTrue(self._writeback(dry_run=True)["ok"])

    def test_configured_missing_path_does_not_use_cwd_file(self):
        self.config["formal_candidate_gold"] = "missing.jsonl"
        write_json(self.workbench / "review_ui_loader_config.json", self.config)
        write_jsonl(self.unrelated / "missing.jsonl", [{"sample_id": "wrong"}])
        with working_directory(self.unrelated):
            bundle = load_workbench(self.workbench)
        self.assertNotIn("wrong", bundle.final_candidates_by_sample_id)
        self.assertEqual(bundle.resolved_loader_paths["formal_candidate_gold"], str(self.workbench / "missing.jsonl"))

    def test_parent_and_absolute_paths_are_rejected(self):
        for value in ("../original_candidates.jsonl", "..\\original_candidates.jsonl", str(self.original), "C:/outside.jsonl"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    resolve_workbench_path(self.workbench, value)
        self.config["formal_candidate_gold"] = "../original_candidates.jsonl"
        write_json(self.workbench / "review_ui_loader_config.json", self.config)
        with self.assertRaises(ValueError):
            load_workbench(self.workbench)

    def test_index_escape_is_rejected_before_writeback(self):
        self._save_changed_draft()
        self.index[0]["candidate_file"] = "../original_candidates.jsonl"
        self._write_index()
        original_bytes = self.original.read_bytes()
        with self.assertRaises(ValueError):
            self._writeback(dry_run=False, confirm_writeback=True)
        self.assertEqual(self.original.read_bytes(), original_bytes)

    def test_symlink_escape_is_rejected(self):
        link = self.workbench / "outside"
        try:
            link.symlink_to(self.unrelated, target_is_directory=True)
        except OSError as exc:
            self.skipTest(f"Directory symlink unavailable: {exc}")
        with self.assertRaises(ValueError):
            resolve_workbench_path(self.workbench, "outside/final_candidate_gold.jsonl")

    def test_candidate_symlink_escape_blocks_load_and_writeback(self):
        self._save_changed_draft()
        link = self.workbench / "linked_candidates.jsonl"
        try:
            link.symlink_to(self.original)
        except OSError as exc:
            self.skipTest(f"File symlink unavailable: {exc}")
        self.index[0]["candidate_file"] = "linked_candidates.jsonl"
        self._write_index()
        original_bytes = self.original.read_bytes()
        with self.assertRaises(ValueError):
            load_workbench(self.workbench)
        with self.assertRaises(ValueError):
            self._writeback(dry_run=False, confirm_writeback=True)
        self.assertEqual(self.original.read_bytes(), original_bytes)

    def test_backup_directory_symlink_blocks_real_writeback(self):
        self._save_changed_draft()
        link = self.workbench / ".backups"
        try:
            link.symlink_to(self.unrelated, target_is_directory=True)
        except OSError as exc:
            self.skipTest(f"Directory symlink unavailable: {exc}")
        target = self.workbench / "final_candidate_gold.jsonl"
        before = target.read_bytes()
        with self.assertRaises(ValueError):
            self._writeback(dry_run=False, confirm_writeback=True)
        self.assertEqual(target.read_bytes(), before)
        self.assertEqual(list(self.unrelated.iterdir()), [])

    def test_absolute_paths_remain_supported_without_new_mode(self):
        self.config.pop("path_base")
        self.config["formal_candidate_gold"] = str(self.workbench / "final_candidate_gold.jsonl")
        write_json(self.workbench / "review_ui_loader_config.json", self.config)
        for row in self.index:
            row["candidate_file"] = str(self.workbench / "final_candidate_gold.jsonl")
            row["run_dir_path"] = str(self.workbench)
        self._write_index()
        with working_directory(self.unrelated):
            self._save_changed_draft()
            result = self._writeback(dry_run=True)
        self.assertTrue(result["ok"], result)

    def test_explicit_diagnostics_load_without_discovering_batch_candidates(self):
        self.config["review_diagnostics"] = {
            "manual_review": "annotation_diagnostics/manual.jsonl",
            "weighted_cases": "annotation_diagnostics/weighted.jsonl",
            "weighted_report": "annotation_diagnostics/report.json",
        }
        write_json(self.workbench / "review_ui_loader_config.json", self.config)
        write_jsonl(self.workbench / "annotation_diagnostics/manual.jsonl", [
            {"sample_id": "sample_000001", "reason": "Review evidence support."}
        ])
        write_jsonl(self.workbench / "annotation_diagnostics/weighted.jsonl", [
            {"sample_id": "sample_000001", "verdict": "manual_review_required"}
        ])
        write_json(self.workbench / "annotation_diagnostics/report.json", {"case_count": 1})
        write_jsonl(self.workbench / "multiagent_api_other/final_candidate_gold.jsonl", [
            {"sample_id": "unexpected_extra_candidate"}
        ])
        with working_directory(self.unrelated):
            bundle = load_workbench(self.workbench)
        self.assertEqual(bundle.run_dirs, [])
        self.assertEqual(set(bundle.final_candidates_by_sample_id), {"sample_000001", "sample_000002"})
        self.assertEqual(bundle.batch_files["final_candidate_gold.jsonl"], [])
        self.assertEqual(bundle.manual_review_by_sample_id["sample_000001"]["reason"], "Review evidence support.")
        self.assertEqual(bundle.weighted_cases_by_sample_id["sample_000001"]["verdict"], "manual_review_required")
        self.assertEqual(bundle.weighted_reports, [{"case_count": 1}])
        self.assertFalse(any("Optional batch file missing" in warning for warning in bundle.warnings))

    def test_missing_optional_diagnostics_are_allowed_and_invalid_paths_warn(self):
        self.config["review_diagnostics"] = {"manual_review": None}
        write_json(self.workbench / "review_ui_loader_config.json", self.config)
        bundle = load_workbench(self.workbench)
        self.assertEqual(bundle.manual_review_by_sample_id, {})
        self.assertEqual(bundle.weighted_cases_by_sample_id, {})
        self.assertEqual(bundle.weighted_reports, [])
        self.assertFalse(any("diagnostic" in warning.lower() for warning in bundle.warnings))
        self.config["review_diagnostics"].update({
            "manual_review": "annotation_diagnostics/missing.jsonl",
            "weighted_cases": 3,
            "weighted_report": "annotation_diagnostics",
        })
        (self.workbench / "annotation_diagnostics").mkdir()
        write_json(self.workbench / "review_ui_loader_config.json", self.config)
        bundle = load_workbench(self.workbench)
        self.assertEqual(len(bundle.final_candidates_by_sample_id), 2)
        self.assertTrue(any("missing.jsonl" in warning for warning in bundle.warnings))
        self.assertTrue(any("review_diagnostics.weighted_cases" in warning for warning in bundle.warnings))
        self.assertTrue(any("not a file" in warning for warning in bundle.warnings))

    def test_explicit_diagnostics_reject_path_escape(self):
        self.config["review_diagnostics"] = {"manual_review": "../original_candidates.jsonl"}
        write_json(self.workbench / "review_ui_loader_config.json", self.config)
        with self.assertRaises(ValueError):
            load_workbench(self.workbench)


if __name__ == "__main__":
    unittest.main()
