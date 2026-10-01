"""Offline batch export and review import across working directories."""

from __future__ import annotations

import json
import os
import unittest
from pathlib import Path

import test_prepare_workbench as preparation

from batch_review import apply_gpt_jsonl, export_packets
from data_loader import load_workbench
from prepare_workbench import write_rows


class BatchWorkbenchHandoffTests(unittest.TestCase):
    def test_relative_workbench_export_imports_from_another_directory(self):
        fixture = preparation.PreparationTests(
            "test_missing_reviews_remain_pending_and_inputs_unchanged"
        )
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        previous_cwd = Path.cwd()
        self.addCleanup(os.chdir, previous_cwd)
        fixture.prepare()
        source_before = (fixture.run / "final_candidate_gold.jsonl").read_bytes()
        target = fixture.output / "final_candidate_gold.jsonl"
        target_before = target.read_bytes()
        os.chdir(fixture.root)
        rows = load_workbench(Path("review")).review_rows
        batch_dir, _ = export_packets(
            workbench_dir=Path("review"),
            rows=rows,
            skipped=[],
            selection_reasons={},
            ts="offline_handoff",
            export_gpt_batch_input=True,
        )
        self.assertTrue(batch_dir.is_absolute())
        outputs = [
            {
                "masked_sample_label": row["masked_sample_id"],
                "gold_stage": row["gold_stage"],
                "draft_claims": [
                    {
                        "step": step["step"],
                        "claim": "The observed process opened the recorded file.",
                    }
                    for step in row["candidate"]["gold_reasoning_chain"]
                ],
                "notes": "Observed file access is supported.",
                "review_status": "reviewed",
                "needs_later_patch_after_review": "no",
                "promotion_blocker_after_review": "yes",
            }
            for row in rows
        ]
        write_rows(batch_dir / "batch_review_outputs.jsonl", outputs)
        elsewhere = fixture.root / "another_directory"
        elsewhere.mkdir()
        os.chdir(elsewhere)
        results = apply_gpt_jsonl(
            workbench_dir=fixture.output,
            batch_dir=batch_dir,
            write=False,
            confirm_batch_writeback=False,
        )
        self.assertEqual(len(results), 2)
        self.assertEqual(
            [item["action"] for item in results],
            ["dry_run_ok", "dry_run_ok"],
            json.dumps(results, default=str),
        )
        self.assertTrue(all(item["batch_gate"]["valid"] for item in results))
        self.assertTrue(all(item["dry_run"]["changed_sample_count"] == 1 for item in results))
        self.assertTrue(all(item["writeback"] is None for item in results))
        self.assertEqual(target.read_bytes(), target_before)
        self.assertEqual((fixture.run / "final_candidate_gold.jsonl").read_bytes(), source_before)
        self.assertFalse((fixture.output / ".backups").exists())


if __name__ == "__main__":
    unittest.main()
