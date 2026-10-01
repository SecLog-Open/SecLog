#!/usr/bin/env python3
"""Stage-attached residual sidecar generator (Phase 1: standalone script).

Reads existing pipeline outputs to extract stage-attachable residuals
(stat / lstat / getcwd / chdir) and write them to an independent sidecar
file without touching any pipeline or main-schema files.

Outputs
-------
behavior_context_stage_residual.v0.jsonl  – one JSON record per residual

Field design (minimal 9-field set)
----------------------------------
Residual identity
  scenario_id         – relative path under results/
  chain_id            – from backbone / dataset
  orig_record_id      – from original_record.id
  raw_evt_type        – stat | lstat | getcwd | chdir
  timestamp           – from original_record.attrs.timestamp

Residual classification
  residual_class      – "stage_attachable"
  residual_subreason  – "fs_existence_check" | "working_directory_change"

Recommended target
  suggest_target_level – "substage"  (only level used in current data)
  suggest_target_id    – substage label, e.g. "Execution / Trigger"
  suggest_parent_stage – parent_stage field of the matched substage

Semantic role
  semantic_role       – "preparatory_context"
                        (describes what the call means in the attack chain)

Mapping evidence
  mapping_evidence
    nearest_seq        – backbone seq of the temporally nearest edge
    delta_seconds      – time difference in seconds (proxy for confidence)
    backbone_relation  – relation family of that nearest backbone edge
    parent_stage       – parent_stage of the backbone edge's containing substage

Original reference
  orig_ref            – minimal pointer back to the unmatched source record
    scenario_id / orig_record_id / evt_num / source_tier
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

# ── paths ──────────────────────────────────────────────────────────────────

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parents[1]
RESULTS_ROOT = PROJECT_ROOT / "results"
TIMESTAMP_DIR_RE = re.compile(r"^\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}$")

if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from utils.common import scenario_chain_dir as resolve_scenario_chain_dir


def scenario_chain_dir(scenario_dir: Path) -> Path:
    return resolve_scenario_chain_dir(scenario_dir)


# ── constants ───────────────────────────────────────────────────────────────

STAGE_ATTACHABLE_TYPES = frozenset({"stat", "lstat", "getcwd", "chdir"})

ROLE_MAP = {
    "stat":   "preparatory_context",
    "lstat":  "preparatory_context",
    "getcwd": "preparatory_context",
    "chdir":  "preparatory_context",
}

SUBREASON_MAP = {
    "stat":   "fs_existence_check",
    "lstat":  "fs_existence_check",
    "getcwd": "working_directory_change",
    "chdir":  "working_directory_change",
}


# ── helpers ─────────────────────────────────────────────────────────────────

def parse_ts(ts_str: str) -> Optional[datetime]:
    if not ts_str:
        return None
    try:
        return datetime.fromisoformat(ts_str)
    except ValueError:
        return None


def build_seq_to_seg(segments: list) -> dict:
    """Map every seq in [start_seq, end_seq] → segment dict."""
    mapping: dict = {}
    for seg in segments:
        start = seg.get("start_seq", 0)
        end   = seg.get("end_seq",   0)
        for seq in range(start, end + 1):
            mapping[seq] = seg
    return mapping


def load_backbone_edges(chain_dir: Path) -> list:
    path = chain_dir / "backbone_chain.v1.json"
    if not path.exists():
        return []
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    edges = data.get("edge_sequence", [])
    return [
        {
            "seq":    e.get("seq"),
            "ts":     parse_ts(e.get("attrs", {}).get("timestamp", "")),
            "rel":    e.get("relation", ""),
            "parent": None,   # filled below
        }
        for e in edges
    ]


def load_substage_mapping(chain_dir: Path):
    """Returns (seq_to_substage, seq_to_stage, chain_id, scenario_id)."""
    path = chain_dir / "behavior_chain_dataset.v2.json"
    if not path.exists():
        return {}, {}, None, None
    with open(path, encoding="utf-8") as fh:
        ds = json.load(fh)

    chain_id    = ds.get("chain_id")
    scenario_id = ds.get("scenario_id")

    seq_to_substage = build_seq_to_seg(ds.get("substage_segments", []))
    seq_to_stage    = build_seq_to_seg(ds.get("stage_segments",    []))

    return seq_to_substage, seq_to_stage, chain_id, scenario_id


def fill_parent_stage(edges: list, seq_to_substage: dict, seq_to_stage: dict):
    """Annotate each backbone edge with its parent_stage via substage/stage lookup."""
    for edge in edges:
        seg = seq_to_substage.get(edge["seq"]) or seq_to_stage.get(edge["seq"])
        edge["parent"] = seg.get("parent_stage") if seg else None


def find_nearest_backbone(
    rec_ts: datetime,
    backbone_edges: list,
) -> Optional[dict]:
    """Return the backbone edge closest in time to rec_ts."""
    best, best_delta = None, None
    for edge in backbone_edges:
        if edge["ts"] is None:
            continue
        delta = abs((rec_ts - edge["ts"]).total_seconds())
        if best_delta is None or delta < best_delta:
            best_delta = delta
            best = edge
    if best is None:
        return None
    return {"seq": best["seq"], "delta": best_delta, "parent": best["parent"], "rel": best["rel"]}


def build_orig_ref(rec: dict) -> dict:
    """Minimal pointer back to the unmatched source record."""
    orig = rec.get("original_record", {})
    return {
        "scenario_id":  rec.get("scenario_id"),
        "orig_record_id": orig.get("id"),
        "evt_num":       rec.get("evt_num"),
        "source_tier":  rec.get("source_tier"),
    }


def classify_residual(raw_evt_type: str) -> tuple[str, str]:
    return "stage_attachable", SUBREASON_MAP.get(raw_evt_type, "unknown")


def transform_record(
    rec: dict,
    nearest: dict,
    chain_id: str,
    scenario_id: str,
) -> dict:
    """Convert one unmatched record into one sidecar record."""
    orig     = rec.get("original_record", {})
    attrs    = orig.get("attrs", {})
    raw_type = rec.get("raw_evt_type", "")
    ts_str   = attrs.get("timestamp", "")

    residual_class, residual_subreason = classify_residual(raw_type)
    semantic_role = ROLE_MAP.get(raw_type, "preparatory_context")

    suggest_label = nearest.get("parent", "unknown")
    # prefer substage label over bare parent_stage
    suggest_id = suggest_label

    return {
        # residual identity
        "scenario_id":   scenario_id,
        "chain_id":      chain_id,
        "orig_record_id": orig.get("id"),
        "raw_evt_type":  raw_type,
        "timestamp":     ts_str,

        # residual classification
        "residual_class":   residual_class,
        "residual_subreason": residual_subreason,

        # recommended target
        "suggest_target_level": "substage",
        "suggest_target_id":    suggest_id,
        "suggest_parent_stage": suggest_label,

        # semantic role
        "semantic_role": semantic_role,

        # mapping evidence
        "mapping_evidence": {
            "nearest_seq":          nearest.get("seq"),
            "delta_seconds":        round(nearest.get("delta", -1), 6),
            "backbone_relation":    nearest.get("rel", "?"),
            "parent_stage":          nearest.get("parent", "?"),
        },

        # original reference
        "orig_ref": build_orig_ref(rec),
    }


# ── core logic ─────────────────────────────────────────────────────────────

def process_chain_dir(chain_dir: Path, verbose: bool = False) -> list:
    """Run the sidecar pipeline for one scenario. Returns list of sidecar records."""
    # 1. backbone edges (for temporal indexing)
    backbone_edges = load_backbone_edges(chain_dir)

    # 2. dataset v2 (for substage / stage structure + chain_id)
    seq_to_substage, seq_to_stage, chain_id, scenario_id = load_substage_mapping(chain_dir)

    # 3. annotate each backbone edge with parent_stage
    fill_parent_stage(backbone_edges, seq_to_substage, seq_to_stage)

    # 4. unmatched records
    unmat_path = chain_dir / "behavior_context_unmatched.v0.jsonl"
    if not unmat_path.exists():
        if verbose:
            print(f"  [SKIP] no unmatched file: {unmat_path}")
        return []

    stage_residual: list = []
    unmapped: list = []

    with open(unmat_path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            raw_type = rec.get("raw_evt_type", "")
            if raw_type not in STAGE_ATTACHABLE_TYPES:
                continue

            orig    = rec.get("original_record", {})
            attrs   = orig.get("attrs", {})
            ts_str  = attrs.get("timestamp", "")
            rec_ts  = parse_ts(ts_str)
            rec["scenario_id"] = scenario_id  # attach for orig_ref builder

            if rec_ts is None:
                unmapped.append(rec)
                continue

            nearest = find_nearest_backbone(rec_ts, backbone_edges)
            if nearest is None:
                unmapped.append(rec)
                continue

            sidecar_rec = transform_record(rec, nearest, chain_id, scenario_id)
            stage_residual.append(sidecar_rec)

    if verbose:
        print(
            f"  stage_attachable={len(stage_residual)}  "
            f"unmapped(no_ts_or_no_bb)={len(unmapped)}"
        )

    return stage_residual


def write_sidecar(chain_dir: Path, records: list, dry_run: bool = False):
    out_path = chain_dir / "behavior_context_stage_residual.v0.jsonl"
    if dry_run:
        print(f"  [DRY] would write {len(records)} records to {out_path}")
        return
    with open(out_path, "w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")


# ── CLI ─────────────────────────────────────────────────────────────────────

def build_argument_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Generate behavior_context_stage_residual.v0.jsonl "
                    "for one or all scenarios (Phase 1 standalone)."
    )
    p.add_argument(
        "--scenario",
        type=str,
        default=None,
        help="Absolute path to a single scenario dir. "
             "If omitted, processes all scenarios with chain/.",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be done without writing any file.",
    )
    p.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show per-scenario counts.",
    )
    return p


def discover_scenarios():
    """Yield (scenario_dir, name) for every scenario that has chain/."""
    for top in ["juice-shop", "multi-jump", "python-demo", "sandworm"]:
        top_path = RESULTS_ROOT / top
        if not top_path.exists():
            continue
        for ts_dir in sorted(top_path.iterdir()):
            if not (ts_dir.is_dir() and TIMESTAMP_DIR_RE.fullmatch(ts_dir.name)):
                continue
            chain_dir = scenario_chain_dir(ts_dir)
            if chain_dir.is_dir():
                name = str(ts_dir.relative_to(RESULTS_ROOT))
                yield ts_dir, name

    vulhub = RESULTS_ROOT / "vulhub"
    if vulhub.exists():
        for project in sorted(vulhub.iterdir()):
            if not project.is_dir():
                continue
            for cve_dir in sorted(project.iterdir()):
                if not cve_dir.is_dir():
                    continue
                for ts_dir in sorted(cve_dir.iterdir()):
                    if not (ts_dir.is_dir() and TIMESTAMP_DIR_RE.fullmatch(ts_dir.name)):
                        continue
                    chain_dir = scenario_chain_dir(ts_dir)
                    if chain_dir.is_dir():
                        name = str(ts_dir.relative_to(RESULTS_ROOT))
                        yield ts_dir, name


def _bar(done: int, total: int, width: int = 20) -> str:
    if total <= 0:
        return "-" * width
    ratio = max(0.0, min(1.0, done / total))
    fill = int(round(ratio * width))
    return "#" * fill + "-" * (width - fill)


def main():
    args = build_argument_parser().parse_args()

    if args.scenario:
        scenario_dir = Path(args.scenario)
        chain_dir    = scenario_chain_dir(scenario_dir)
        name         = str(scenario_dir.relative_to(RESULTS_ROOT))
        print(f"[1/1|100%] [{name}] progress=[{_bar(1, 1)}]")
        records = process_chain_dir(chain_dir, verbose=args.verbose)
        write_sidecar(chain_dir, records, dry_run=args.dry_run)
        return

    # batch mode
    total_records = 0
    scenario_count = 0

    scenarios = list(discover_scenarios())
    total = len(scenarios)

    for idx, (scenario_dir, name) in enumerate(scenarios, 1):
        chain_dir = scenario_chain_dir(scenario_dir)
        pct = int(round((idx / total) * 100)) if total > 0 else 100
        print(f"[{idx}/{total}|{pct:>3d}%] [{name}] progress=[{_bar(idx, total)}]")
        records = process_chain_dir(chain_dir, verbose=args.verbose)
        write_sidecar(chain_dir, records, dry_run=args.dry_run)
        total_records += len(records)
        scenario_count += 1

    print(f"\nDone — {scenario_count} scenarios, {total_records} sidecar records written.")


if __name__ == "__main__":
    main()
