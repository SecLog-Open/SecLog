# Review UI Rollback Workflow

The writeback command creates a backup before modifying a target
`final_candidate_gold.jsonl`. Rollback restores that backup when a reviewer
decides that the writeback should be reverted. Each backup is a full-file
snapshot, not a single-sample patch; restoring it also removes any later
writebacks to that file.

## Steps

1. Find the target run directory from the writeback result or `ui_drafts/writeback_log.jsonl`.
2. Locate the backup under `.backups/`, named like:
   `final_candidate_gold.backup.<sample_id>.<YYYYMMDD_HHMMSS>.jsonl`.
3. Verify that no later accepted writebacks would be lost. Preserve the
   current file before replacing it with the selected snapshot. If later
   writebacks must be retained, restore only the reviewed sample's previous
   record and validate the resulting file instead of replacing the whole file.
4. For a whole-file restore, confirm that its SHA-256 matches the selected
   backup. Check that the restored sample and stage identifiers are unchanged.
5. Run the loader smoke check from `05_benchmark_annotation_review_evaluation/`:

   ```bash
   python review_ui/data_loader.py \
     --workbench-dir /path/to/review_workbench \
     --smoke-check
   ```

6. Record the rollback in `ui_drafts/writeback_log.jsonl` without deleting
   earlier log entries, and update the affected sample's review status in the UI.
7. Reload the workbench and inspect the restored candidate, its draft diff,
   evidence references, and status before further writeback.
