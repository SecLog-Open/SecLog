#!/usr/bin/env python3
"""Prepare a fresh human-review workbench from annotation candidates and evidence."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

try:
    from data_loader import REQUIRED_ROOT_FILES, smoke_check
    from validators import EXPECTED_CHAIN_STEPS, validate_candidate_record
except ImportError:
    from .data_loader import REQUIRED_ROOT_FILES, smoke_check
    from .validators import EXPECTED_CHAIN_STEPS, validate_candidate_record


STAGES = {"preparation", "execution", "result", "stage_unclosed"}
EVIDENCE_FILES = {
    "model": "masked_inputs/model_input.masked.jsonl",
    "gold": "masked_inputs/gold.masked.jsonl",
    "index": "masked_inputs/sample_index.masked.jsonl",
    "prompt": "prompt_packs/reviewer_annotation_prompts.weighted.masked.jsonl",
}


def read_json(path: Path) -> Any:
    with path.open(encoding="utf-8-sig") as handle:
        return json.load(handle)


def read_rows(path: Path, *, optional: bool = False) -> list[dict[str, Any]]:
    if optional and not path.exists():
        return []
    rows = []
    with path.open(encoding="utf-8-sig") as handle:
        for number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            row = json.loads(line)
            if not isinstance(row, dict):
                raise ValueError(f"{path.name}:{number}: expected a JSON object")
            rows.append(row)
    return rows


def index_rows(rows: list[dict[str, Any]], name: str) -> dict[str, dict[str, Any]]:
    indexed = {}
    for row in rows:
        sample_id = row.get("sample_id")
        if not isinstance(sample_id, str) or not sample_id.strip():
            raise ValueError(f"{name}: missing sample_id")
        if sample_id in indexed:
            raise ValueError(f"{name}: duplicate sample_id {sample_id}")
        indexed[sample_id] = row
    return indexed


def read_id_map(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    doc = read_json(path)
    items = doc.get("items") if isinstance(doc, dict) else None
    if not isinstance(items, list):
        raise ValueError(f"{path.name}: expected an items list")
    mapping: dict[str, str] = {}
    masked_ids: set[str] = set()
    for item in items:
        original = item.get("original") if isinstance(item, dict) else None
        masked = item.get("masked") if isinstance(item, dict) else None
        if not isinstance(original, str) or not original or not isinstance(masked, str) or not masked:
            raise ValueError(f"{path.name}: each item needs original and masked IDs")
        if original in mapping or masked in masked_ids:
            raise ValueError(f"{path.name}: mapping must be one-to-one")
        mapping[original] = masked
        masked_ids.add(masked)
    return mapping


def stage_of(row: dict[str, Any]) -> str:
    label = row.get("label")
    return str((label.get("stage") if isinstance(label, dict) else None)
               or row.get("gold_stage") or row.get("stage") or "")


def evidence_pairs(spine: Any, name: str) -> set[tuple[str, int]]:
    if not isinstance(spine, list) or not spine:
        raise ValueError(f"{name}: missing non-empty evidence spine")
    pairs = set()
    edges = set()
    seqs = set()
    for edge in spine:
        edge_id = edge.get("edge_id") if isinstance(edge, dict) else None
        seq = edge.get("seq") if isinstance(edge, dict) else None
        if not isinstance(edge_id, str) or not edge_id or type(seq) is not int:
            raise ValueError(f"{name}: every evidence edge needs edge_id and integer seq")
        if edge_id in edges or seq in seqs:
            raise ValueError(f"{name}: duplicate edge_id or seq")
        edges.add(edge_id)
        seqs.add(seq)
        pairs.add((edge_id, seq))
    return pairs


def candidate_findings(candidate: dict[str, Any], full_pairs: set, compact_pairs: set,
                       edge_map: dict[str, str]) -> list[str]:
    sample_id = candidate["sample_id"]
    findings = validate_candidate_record(candidate)
    chain = candidate.get("gold_reasoning_chain")
    if (not isinstance(chain, list) or len(chain) != len(EXPECTED_CHAIN_STEPS)
            or any(not isinstance(step, dict) for step in chain)
            or [step.get("step") for step in chain] != EXPECTED_CHAIN_STEPS):
        raise ValueError(f"{sample_id}: prepare a complete four-step candidate before human review")
    for step in chain:
        if set(step) - {"step", "claim", "evidence_refs"}:
            raise ValueError(f"{sample_id}: candidate steps may only contain step, claim and evidence_refs")
        refs = step.get("evidence_refs")
        if not isinstance(refs, list):
            raise ValueError(f"{sample_id}: candidate evidence_refs must be a list")
        if not refs:
            findings.append(f"{step.get('step', 'step')}: no evidence references")
        if not isinstance(step.get("claim"), str) or not step["claim"].strip():
            findings.append(f"{step['step']}: claim requires human revision")
        for ref in refs:
            if (not isinstance(ref, dict) or set(ref) != {"edge_id", "seq"}
                    or not isinstance(ref.get("edge_id"), str)
                    or type(ref.get("seq")) is not int):
                raise ValueError(f"{sample_id}: malformed evidence reference")
            edge_id = ref["edge_id"]
            pair = (edge_map.get(edge_id, edge_id), ref["seq"])
            if pair not in full_pairs:
                raise ValueError(f"{sample_id}: reference is absent from full evidence: {pair}")
            if pair not in compact_pairs:
                findings.append(f"reference outside compact evidence: {pair[0]} / seq {pair[1]}")
    return sorted(set(findings))


def review_priority(reviewer: dict, weighted: dict, reasons: list[str], findings: list[str]) -> str:
    if (findings or reasons or reviewer.get("verdict") in {"major_revision", "reject"}
            or reviewer.get("high_severity") is True
            or weighted.get("verdict") in {"weak", "risky", "invalid"}
            or weighted.get("strict_gold_allowed") is False):
        return "high"
    return "medium"


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_rows(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def prepare_workbench(run_dir: Path, masked_workbench: Path, output_dir: Path,
                      *, expected_count: int | None = None) -> dict[str, Any]:
    """Validate inputs, then create local candidate/evidence copies and empty review state."""
    run_dir, masked_workbench, output_dir = (
        Path(path).resolve() for path in (run_dir, masked_workbench, output_dir)
    )
    if output_dir.exists():
        raise FileExistsError(f"Refusing existing workbench: {output_dir}")
    for source in (run_dir, masked_workbench):
        if output_dir == source or source in output_dir.parents:
            raise ValueError("Output must be separate from the annotation and evidence inputs")
    frozen = Path(__file__).resolve().parents[2] / "SecLog-Bench-216"
    if output_dir == frozen or frozen in output_dir.parents:
        raise ValueError("The frozen benchmark is not a workbench output directory")
    candidates = read_rows(run_dir / "final_candidate_gold.jsonl")
    candidate_by_id = index_rows(candidates, "final_candidate_gold")
    if not candidates:
        raise ValueError("final_candidate_gold.jsonl is empty; prepare annotation candidates first")
    if expected_count is not None and (expected_count < 1 or len(candidates) != expected_count):
        raise ValueError(f"Expected {expected_count} candidates, found {len(candidates)}")
    evidence = {name: index_rows(read_rows(masked_workbench / filename), name)
                for name, filename in EVIDENCE_FILES.items()}
    sample_map = read_id_map(masked_workbench / "id_maps/sample_id_map.json")
    edge_map = read_id_map(masked_workbench / "id_maps/edge_id_map.json")
    selected_ids = {sid: sample_map.get(sid, sid) for sid in candidate_by_id}
    if len(set(selected_ids.values())) != len(selected_ids):
        raise ValueError("Candidate IDs do not map to distinct evidence samples")
    all_sample_ids = dict(sample_map)
    all_sample_ids.update(selected_ids)
    reverse_map = {masked: original for original, masked in all_sample_ids.items()}

    def diagnostic_rows(filename: str, *, grouped: bool = False) -> list[dict[str, Any]]:
        result = []
        for row in read_rows(run_dir / filename, optional=True):
            sid = row.get("sample_id")
            if not sid and grouped:
                result.append(dict(row, sample_id=""))
                continue
            if not isinstance(sid, str) or not sid:
                raise ValueError(f"{filename}: missing sample_id")
            original = sid if sid in candidate_by_id else reverse_map.get(sid, sid)
            if original in candidate_by_id:
                result.append(dict(row, sample_id=original))
        if not grouped:
            index_rows(result, filename)
        return result

    reviewer_rows = diagnostic_rows("reviewer_judge_outputs.jsonl")
    weighted_rows = diagnostic_rows("reviewer_weighted_grounding_cases.jsonl")
    manual_rows = diagnostic_rows("manual_review_required.jsonl", grouped=True)
    reviewer_by_id = index_rows(reviewer_rows, "reviewer judgments")
    weighted_by_id = index_rows(weighted_rows, "grounding cases")
    weighted_report_path = run_dir / "reviewer_weighted_grounding_report.json"
    weighted_report = read_json(weighted_report_path) if weighted_report_path.exists() else None
    if weighted_report is not None and not isinstance(weighted_report, dict):
        raise ValueError("reviewer_weighted_grounding_report.json must be an object")

    indexes, fidelity, selection, sheet = [], [], [], []
    for number, candidate in enumerate(candidates, 1):
        sid = candidate["sample_id"]
        masked_id = selected_ids[sid]
        for name, records in evidence.items():
            if masked_id not in records:
                raise ValueError(f"{sid}: missing {name} for evidence sample {masked_id}")
        model, gold, sample, prompt = (evidence[name][masked_id] for name in ("model", "gold", "index", "prompt"))
        stage = stage_of(candidate)
        if stage not in STAGES:
            raise ValueError(f"{sid}: unknown or missing stage {stage!r}")
        if any(stage_of(row) != stage for row in (gold, sample, prompt)):
            raise ValueError(f"{sid}: candidate, gold, sample index and prompt stages disagree")
        full_pairs = evidence_pairs(model.get("input", {}).get("spine"), f"{sid} model input")
        primary = prompt.get("prompt_input", {}).get("primary_evidence", {})
        compact_pairs = evidence_pairs(primary.get("spine"), f"{sid} reviewer prompt")
        if not compact_pairs <= full_pairs:
            raise ValueError(f"{sid}: compact evidence edges are absent from full evidence")
        findings = candidate_findings(candidate, full_pairs, compact_pairs, edge_map)
        reviewer = reviewer_by_id.get(sid, {})
        weighted = weighted_by_id.get(sid, {})
        reasons = [str(row.get("reason") or "manual_review_requested") for row in manual_rows
                   if row["sample_id"] in (sid, "")]
        if not reviewer:
            reasons.append("reviewer_judgment_missing")
        if not weighted or weighted_report is None:
            reasons.append("weighted_grounding_audit_missing")
        elif weighted_report.get("status") != "success":
            reasons.append("weighted_grounding_audit_not_successful")
        priority = review_priority(reviewer, weighted, reasons, findings)
        reason_codes = sorted(set(reasons + findings + [f"{stage}_boundary_check"]))
        weighted_permission = weighted.get("strict_gold_allowed")
        index = {
            "sample_id": sid, "masked_sample_id": masked_id, "gold_stage": stage,
            "candidate_index": number, "candidate_row_index": number,
            "candidate_file": "final_candidate_gold.jsonl",
            "final_candidate_gold_source": "final_candidate_gold.jsonl",
            "run_dir": ".", "run_dir_path": ".",
            "candidate_status": "candidate-with-manual-review", "manual_review_required": True,
            "manual_review_reason": "human_review_pending", "priority": priority,
            "review_priority": priority, "reason_codes": reason_codes,
            "reviewer_verdict": reviewer.get("verdict", "pending"),
            "grounding_verdict": weighted.get("verdict", "pending"),
            "strict_gold_allowed": weighted_permission if type(weighted_permission) is bool else None,
            "reasoning_chain_step_count": len(candidate.get("gold_reasoning_chain") or []),
        }
        indexes.append(index)
        shared = {
            "sample_id": sid, "gold_stage": stage, "human_review_priority": priority,
            "reason_codes": reason_codes, "grounding_verdict": index["grounding_verdict"],
            "generic_template_risk": "not_assessed", "stage_boundary_review_needed": "yes",
        }
        fidelity.append(dict(shared, structural_findings=findings, review_priority=priority,
                             evidence_linkage="valid", reviewer_judgment=reviewer,
                             recommended_action="human_review_pending"))
        selection.append(dict(shared, promotion_blocker="yes", needs_later_patch="yes",
                              recommended_next_action="human_review", weighted_verdict=index["grounding_verdict"]))
        sheet.append(dict(shared, reviewer_decision="", promotion_decision="",
                          recommended_next_action="not_reviewed"))

    summary = {
        "candidate_count": len(candidates), "candidate_index_count": len(indexes),
        "final_candidate_gold_count": len(candidates), "queue_count": len(indexes),
        "stage_count": dict(Counter(row["gold_stage"] for row in indexes)),
        "priority_counts": dict(Counter(row["priority"] for row in indexes)),
        "reviewed_count": 0, "written_back_count": 0,
        "samples_with_structural_findings": sum(bool(row["structural_findings"]) for row in fidelity),
    }
    # Keep one authoritative candidate file; all writeback paths point to this local copy.
    output_dir.mkdir(parents=True)
    write_rows(output_dir / "final_candidate_gold.jsonl", candidates)
    destinations = {"model": "strict_blind_model_input.jsonl", "gold": "strict_blind_gold.jsonl",
                    "index": "sample_index.jsonl", "prompt": EVIDENCE_FILES["prompt"]}
    for name, destination in destinations.items():
        write_rows(output_dir / destination, [evidence[name][mid] for mid in selected_ids.values()])
    diagnostics: dict[str, str | None] = {"manual_review": None, "weighted_cases": None, "weighted_report": None}
    for key, filename, rows in (
        ("manual_review", "manual_review_required.jsonl", manual_rows),
        ("weighted_cases", "reviewer_weighted_grounding_cases.jsonl", weighted_rows),
    ):
        if rows:
            diagnostics[key] = f"annotation_diagnostics/{filename}"
            write_rows(output_dir / diagnostics[key], rows)
    if weighted_report is not None:
        diagnostics["weighted_report"] = "annotation_diagnostics/reviewer_weighted_grounding_report.json"
        write_json(output_dir / diagnostics["weighted_report"], weighted_report)
    write_rows(output_dir / REQUIRED_ROOT_FILES["candidate_index"], indexes)
    write_json(output_dir / REQUIRED_ROOT_FILES["summary"], summary)
    for key, array_key, rows in (("p5_35", "sample_diagnostics", fidelity),
                                 ("p5_37", "sample_dry_run_table", selection),
                                 ("p5_38", "review_sheet", sheet)):
        write_json(output_dir / REQUIRED_ROOT_FILES[key], {"status": "pending_human_review", array_key: rows})
    write_json(output_dir / "review_ui_loader_config.json", {
        "path_base": "workbench", "expected_candidate_count": len(candidates),
        "formal_candidate_gold": "final_candidate_gold.jsonl",
        "initial_review_status": "not_reviewed", "initial_writeback_status": "not_written_back",
        "strict_blind_evidence": {"model_input": destinations["model"], "gold": destinations["gold"],
                                  "sample_index": destinations["index"]},
        "compact_evidence": {"reviewer_prompt_pack": destinations["prompt"]},
        "review_diagnostics": diagnostics,
        "writeback": {"default_dry_run": True, "requires_explicit_confirm": True},
    })
    for filename in ("reasoning_chain_drafts.jsonl", "human_review_status.jsonl", "writeback_log.jsonl"):
        write_rows(output_dir / "ui_drafts" / filename, [])
    for filename in ("reasoning_chain_drafts.latest.json", "human_review_status.latest.json"):
        write_json(output_dir / "ui_drafts" / filename, {})
    check = smoke_check(output_dir)
    if not check["passed"] or check["strict_blind_input_loaded_count"] != len(candidates):
        raise RuntimeError(f"Generated workbench failed its loader check: {check['failures']}")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", type=Path, required=True, help="Annotation run containing final_candidate_gold.jsonl")
    parser.add_argument("--masked-workbench", type=Path, required=True, help="Compact annotation workbench")
    parser.add_argument("--output-dir", type=Path, required=True, help="New human-review workbench directory")
    parser.add_argument("--expected-count", type=int, help="Require exactly this many candidates")
    args = parser.parse_args()
    try:
        result = prepare_workbench(args.run_dir, args.masked_workbench, args.output_dir,
                                   expected_count=args.expected_count)
    except (OSError, ValueError, RuntimeError) as exc:
        parser.exit(1, f"Workbench preparation failed: {exc}\n")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
