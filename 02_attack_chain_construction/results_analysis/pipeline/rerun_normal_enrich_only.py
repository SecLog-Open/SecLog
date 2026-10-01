#!/usr/bin/env python3
"""Run normal enrich scenarios, excluding those skipped by the backbone guard."""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from utils.common import scenario_chain_dir
PROJECT_ROOT = Path(__file__).resolve().parents[2]
RESULTS_ROOT = PROJECT_ROOT / "results"
PIPELINE_SCRIPT = PROJECT_ROOT / "results_analysis" / "pipeline" / "run_chain_pipeline.py"
PROGRESS_FILE = PROJECT_ROOT / "results_analysis" / "pipeline" / "rerun_normal_progress.json"
LOG_DIR = PROJECT_ROOT / "results_analysis" / "pipeline" / "rerun_normal_logs"

# Scenario run directories and enrich status.
ALL_SCENARIOS = [
    ("python-demo/2026-03-21_09-40-30", "python-demo", "skipped"),
    ("sandworm/2026-03-21_12-51-50", "sandworm", "skipped"),
    ("vulhub/adminer/CVE-2021-43008/2026-03-21_10-00-04", "adminer", "normal"),
    ("vulhub/geoserver/CVE-2023-25157/2026-03-21_09-53-25", "geoserver-25157", "normal"),
    ("vulhub/geoserver/CVE-2024-36401/2026-03-21_09-56-49", "geoserver-36401", "normal"),
    ("vulhub/gitlist/CVE-2018-1000533/2026-03-21_09-47-27", "gitlist", "normal"),
    ("vulhub/kibana/CVE-2018-17246/2026-03-21_12-35-34", "kibana", "normal"),
    ("vulhub/metabase/CVE-2021-41277/2026-03-21_10-03-19", "metabase-41277", "normal"),
    ("vulhub/metabase/CVE-2023-38646/2026-03-21_10-18-30", "metabase-38646", "skipped"),
    ("vulhub/mongo-express/CVE-2019-10758/2026-03-21_12-25-24", "mongo-express", "skipped"),
    ("vulhub/ofbiz/CVE-2020-9496/2026-03-21_11-09-46", "ofbiz-9496", "skipped"),
    ("vulhub/ofbiz/CVE-2023-49070/2026-03-21_11-18-41", "ofbiz-49070", "skipped"),
    ("vulhub/ofbiz/CVE-2023-51467/2026-03-21_11-56-40", "ofbiz-51467", "skipped"),
    ("vulhub/ofbiz/CVE-2024-38856/2026-03-21_11-27-35", "ofbiz-38856", "skipped"),
    ("vulhub/ofbiz/CVE-2024-45195/2026-03-21_11-36-14", "ofbiz-45195", "skipped"),
    ("vulhub/ofbiz/CVE-2024-45507/2026-03-21_11-46-58", "ofbiz-45507", "skipped"),
    ("vulhub/solr/CVE-2017-12629-RCE/2026-03-21_10-35-59", "solr-RCE", "normal"),
    ("vulhub/solr/CVE-2017-12629-XXE/2026-03-21_10-39-56", "solr-XXE", "normal"),
    ("vulhub/solr/CVE-2019-0193/2026-03-21_10-43-52", "solr-0193", "normal"),
    ("vulhub/solr/CVE-2019-17558/2026-03-21_10-48-12", "solr-17558", "skipped"),
]

# Select scenario directories by the configured enrich status.
NORMAL_SCENARIOS = [
    (RESULTS_ROOT / rel, name, status)
    for rel, name, status in ALL_SCENARIOS
    if status == "normal"
]
SKIPPED_SCENARIOS = [
    (RESULTS_ROOT / rel, name, status)
    for rel, name, status in ALL_SCENARIOS
    if status == "skipped"
]


def _bar(done: int, total: int, width: int = 20) -> str:
    if total <= 0:
        return "-" * width
    ratio = max(0.0, min(1.0, done / total))
    fill = int(round(ratio * width))
    return "#" * fill + "-" * (width - fill)


def run_enrich_only(scenario_dir: Path, name: str) -> dict:
    """Run the pipeline for a selected normal enrich scenario."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    safe_name = name.replace("/", "_").replace("-", "_")
    log_file = LOG_DIR / f"{safe_name}.log"

    chain_dir = scenario_chain_dir(scenario_dir)
    backbone_file = chain_dir / "backbone_chain.v1.json"
    summary_file = chain_dir / "behavior_context_summary.v0.json"
    context_edges = chain_dir / "behavior_context_edges.v0.jsonl"
    context_unmatched = chain_dir / "behavior_context_unmatched.v0.jsonl"

    result = {
        "name": name,
        "path": str(scenario_dir),
        "rc": None,
        "enrich_status": "unknown",
        "backbone_edge_count": None,
        "guard_triggered": False,
        "weak_inferred_net": None,
        "matched_total": None,
        "unmatched_total": None,
        "elapsed_seconds": None,
        "error": None,
    }

    t0 = time.time()

    # Check that the backbone exists.
    if not backbone_file.exists():
        result["error"] = "backbone not found"
        result["elapsed_seconds"] = round(time.time() - t0, 1)
        return result

    # Read the backbone edge count.
    try:
        with open(backbone_file) as f:
            bb = json.load(f)
        edges = bb.get("edge_sequence", []) if isinstance(bb, dict) else []
        result["backbone_edge_count"] = len(edges) if isinstance(edges, list) else None
    except Exception as e:
        result["error"] = f"backbone load error: {e}"
        result["elapsed_seconds"] = round(time.time() - t0, 1)
        return result

    # Check whether the existing summary records an automatic guard skip.
    if summary_file.exists():
        try:
            with open(summary_file) as f:
                s = json.load(f)
            if s.get("skip_reason") == "backbone_guard_threshold_exceeded":
                result["enrich_status"] = "auto-skipped-by-guard"
                result["guard_triggered"] = True
                result["elapsed_seconds"] = round(time.time() - t0, 1)
                return result
        except Exception:
            pass

    # Run the pipeline.
    with open(log_file, "w") as lf:
        proc = subprocess.Popen(
            [sys.executable, str(PIPELINE_SCRIPT), "--scenario-dir", str(scenario_dir)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        for line in proc.stdout:
            lf.write(line)
        proc.wait()
        rc = proc.returncode

    result["rc"] = rc
    result["elapsed_seconds"] = round(time.time() - t0, 1)

    # Parse the summary.
    if summary_file.exists():
        try:
            with open(summary_file) as f:
                s = json.load(f)
            skip_reason = s.get("skip_reason", "")
            if skip_reason == "backbone_guard_threshold_exceeded":
                result["enrich_status"] = "auto-skipped-by-guard"
                result["guard_triggered"] = True
            elif s.get("status") == "skipped":
                result["enrich_status"] = "explicit-skip"
            else:
                result["enrich_status"] = "normal"
            result["weak_inferred_net"] = s.get("counts", {}).get("matched_by_weak_inferred_net", 0)
            result["matched_total"] = s.get("counts", {}).get("matched_malicious_non_core", 0)
            result["unmatched_total"] = s.get("counts", {}).get("unmatched_malicious_non_core", 0)
        except Exception as e:
            result["error"] = f"summary parse error: {e}"
    else:
        result["enrich_status"] = "no-summary"

    return result


def main():
    # Run only normal enrich scenarios.
    scenarios = NORMAL_SCENARIOS
    print(f"[normal_enrich_rerun] Found {len(scenarios)} normal enrich scenarios")

    LOG_DIR.mkdir(parents=True, exist_ok=True)

    all_results = []
    completed = 0
    failed = 0

    for idx, (scenario_dir, name, status) in enumerate(scenarios, 1):
        pct_before = int(round(((idx - 1) / len(scenarios)) * 100))
        print(
            f"[normal_enrich_rerun] [{idx}/{len(scenarios)}|{pct_before:>3d}%] "
            f"Running: {name}  progress=[{_bar(idx - 1, len(scenarios))}]"
        )
        result = run_enrich_only(scenario_dir, name)
        all_results.append(result)

        if result["rc"] == 0:
            completed += 1
            status_str = "OK"
        else:
            failed += 1
            status_str = f"FAIL (rc={result['rc']})"

        wi = result.get("weak_inferred_net", "?")
        matched = result.get("matched_total", "?")
        um = result.get("unmatched_total", "?")
        elapsed = result.get("elapsed_seconds", "?")
        guard = result.get("guard_triggered", False)
        err = result.get("error", "")
        pct_after = int(round((idx / len(scenarios)) * 100))

        print(f"  -> {status_str}  enrich={result['enrich_status']}  "
              f"guard={guard}  weak_inferred={wi}  "
              f"matched={matched}  unmatched={um}  elapsed={elapsed}s  {err}  "
              f"done=[{_bar(idx, len(scenarios))}] {pct_after:>3d}%")

        # Save progress.
        with open(PROGRESS_FILE, "w") as f:
            json.dump({
                "total": len(scenarios),
                "done": idx,
                "percent": pct_after,
                "completed": completed,
                "failed": failed,
                "scenarios": all_results,
            }, f, indent=2, ensure_ascii=False)

    print(f"\n[normal_enrich_rerun] Done. {completed}/{len(scenarios)} succeeded, {failed} failed")

    # Aggregate final totals.
    total_wi = sum(r.get("weak_inferred_net", 0) or 0 for r in all_results)
    total_matched = sum(r.get("matched_total", 0) or 0 for r in all_results)
    total_um = sum(r.get("unmatched_total", 0) or 0 for r in all_results)
    skipped_by_guard = sum(1 for r in all_results if r.get("guard_triggered"))

    print(f"\n=== Final Stats ===")
    print(f"  weak_inferred_net (including getpeername): {total_wi}")
    print(f"  matched_malicious_non_core: {total_matched}")
    print(f"  unmatched_malicious_non_core: {total_um}")
    print(f"  skipped_by_guard: {skipped_by_guard}")

    # Write the final summary.
    summary_out = PROJECT_ROOT / "results_analysis" / "pipeline" / "rerun_normal_summary.json"
    with open(summary_out, "w") as f:
        json.dump({
            "total": len(scenarios),
            "completed": completed,
            "failed": failed,
            "weak_inferred_net_total": total_wi,
            "matched_total": total_matched,
            "unmatched_total": total_um,
            "skipped_by_guard": skipped_by_guard,
            "scenarios": all_results,
        }, f, indent=2, ensure_ascii=False)
    print(f"\nSummary written to {summary_out}")


if __name__ == "__main__":
    main()
