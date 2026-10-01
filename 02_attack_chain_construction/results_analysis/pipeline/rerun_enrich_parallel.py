#!/usr/bin/env python3
"""Run the enrich stage for normal scenarios in parallel (four workers)."""

from __future__ import annotations

import json
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from utils.common import scenario_chain_dir
PROJECT_ROOT = Path(__file__).resolve().parents[2]
RESULTS_ROOT = PROJECT_ROOT / "results"
ENRICH_SCRIPT = PROJECT_ROOT / "results_analysis" / "enrich_behavior_context_v0.py"
PROGRESS_FILE = PROJECT_ROOT / "results_analysis" / "pipeline" / "rerun_enrich_progress.json"
SUMMARY_FILE = PROJECT_ROOT / "results_analysis" / "pipeline" / "rerun_enrich_summary.json"
LOG_DIR = PROJECT_ROOT / "results_analysis" / "pipeline" / "rerun_enrich_logs"

SCENARIOS = [
    ("python-demo/2026-03-21_09-40-30", "python-demo"),
    ("sandworm/2026-03-21_12-51-50", "sandworm"),
    ("vulhub/adminer/CVE-2021-43008/2026-03-21_10-00-04", "adminer"),
    ("vulhub/geoserver/CVE-2023-25157/2026-03-21_09-53-25", "geoserver-25157"),
    ("vulhub/geoserver/CVE-2024-36401/2026-03-21_09-56-49", "geoserver-36401"),
    ("vulhub/gitlist/CVE-2018-1000533/2026-03-21_09-47-27", "gitlist"),
    ("vulhub/kibana/CVE-2018-17246/2026-03-21_12-35-34", "kibana"),
    ("vulhub/metabase/CVE-2021-41277/2026-03-21_10-03-19", "metabase-41277"),
    ("vulhub/metabase/CVE-2023-38646/2026-03-21_10-18-30", "metabase-38646"),
    ("vulhub/mongo-express/CVE-2019-10758/2026-03-21_12-25-24", "mongo-express"),
    ("vulhub/ofbiz/CVE-2020-9496/2026-03-21_11-09-46", "ofbiz-9496"),
    ("vulhub/ofbiz/CVE-2023-49070/2026-03-21_11-18-41", "ofbiz-49070"),
    ("vulhub/ofbiz/CVE-2023-51467/2026-03-21_11-56-40", "ofbiz-51467"),
    ("vulhub/ofbiz/CVE-2024-38856/2026-03-21_11-27-35", "ofbiz-38856"),
    ("vulhub/ofbiz/CVE-2024-45195/2026-03-21_11-36-14", "ofbiz-45195"),
    ("vulhub/ofbiz/CVE-2024-45507/2026-03-21_11-46-58", "ofbiz-45507"),
    ("vulhub/solr/CVE-2017-12629-RCE/2026-03-21_10-35-59", "solr-RCE"),
    ("vulhub/solr/CVE-2017-12629-XXE/2026-03-21_10-39-56", "solr-XXE"),
    ("vulhub/solr/CVE-2019-0193/2026-03-21_10-43-52", "solr-0193"),
    ("vulhub/solr/CVE-2019-17558/2026-03-21_10-48-12", "solr-17558"),
]

SCENARIO_DIRS = [(RESULTS_ROOT / rel, name) for rel, name in SCENARIOS]


def _bar(done: int, total: int, width: int = 20) -> str:
    if total <= 0:
        return "-" * width
    ratio = max(0.0, min(1.0, done / total))
    fill = int(round(ratio * width))
    return "#" * fill + "-" * (width - fill)


def run_enrich(scenario_dir: Path, name: str) -> dict:
    """Invoke enrich_behavior_context_v0.py directly."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    safe_name = name.replace("/", "_").replace("-", "_")
    log_file = LOG_DIR / f"{safe_name}.log"

    chain_dir = scenario_chain_dir(scenario_dir)
    backbone_file = chain_dir / "backbone_chain.v1.json"
    summary_file = chain_dir / "behavior_context_summary.v0.json"
    edges_file = chain_dir / "behavior_context_edges.v0.jsonl"
    unmatched_file = chain_dir / "behavior_context_unmatched.v0.jsonl"

    result = {
        "name": name,
        "path": str(scenario_dir),
        "rc": None,
        "backbone_edge_count": None,
        "enrich_status": "unknown",
        "weak_inferred_net": 0,
        "matched_total": 0,
        "unmatched_total": 0,
        "elapsed_seconds": None,
        "error": None,
    }

    t0 = time.time()

    # Read the backbone edge count.
    if backbone_file.exists():
        try:
            with open(backbone_file) as f:
                bb = json.load(f)
            result["backbone_edge_count"] = len(bb.get("edge_sequence", []))
        except Exception as e:
            result["error"] = f"backbone load error: {e}"
            result["elapsed_seconds"] = round(time.time() - t0, 1)
            return result
    else:
        result["error"] = "backbone not found"
        result["elapsed_seconds"] = round(time.time() - t0, 1)
        return result

    # Apply the backbone guard used by the enrich script.
    bb_edges = result["backbone_edge_count"] or 0
    GUARD_THRESHOLD = 5000
    if bb_edges > GUARD_THRESHOLD:
        # Generate a skip summary consistent with the enrich script.
        result["enrich_status"] = "auto-skipped-by-guard"
        result["elapsed_seconds"] = round(time.time() - t0, 1)
        summary_data = {
            "schema_version": "behavior_context_summary.v1",
            "status": "skipped",
            "skip_reason": "backbone_guard_threshold_exceeded",
            "backbone_edge_count": bb_edges,
            "backbone_guard_threshold": GUARD_THRESHOLD,
        }
        with open(summary_file, "w") as f:
            json.dump(summary_data, f, indent=2)
        return result

    # Run enrich.
    with open(log_file, "w") as lf:
        proc = subprocess.Popen(
            [sys.executable, str(ENRICH_SCRIPT), "--scenario-dir", str(scenario_dir)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        for line in proc.stdout:
            lf.write(line)
        proc.wait()
        result["rc"] = proc.returncode

    result["elapsed_seconds"] = round(time.time() - t0, 1)

    # Parse the summary.
    if summary_file.exists():
        try:
            with open(summary_file) as f:
                s = json.load(f)
            skip_reason = s.get("skip_reason", "")
            status = s.get("status", "")
            if skip_reason == "backbone_guard_threshold_exceeded":
                result["enrich_status"] = "auto-skipped-by-guard"
            elif status == "skipped":
                result["enrich_status"] = "explicit-skip"
            else:
                result["enrich_status"] = "normal"
            result["weak_inferred_net"] = s.get("counts", {}).get("matched_by_weak_inferred_net", 0)
            result["matched_total"] = s.get("counts", {}).get("matched_malicious_non_core", 0)
            result["unmatched_total"] = s.get("counts", {}).get("unmatched_malicious_non_core", 0)
        except Exception as e:
            result["error"] = f"summary parse error: {e}"

    return result


def main():
    print(f"[parallel_enrich] Starting {len(SCENARIO_DIRS)} scenarios (4 workers)")
    t0 = time.time()

    all_results = []
    completed = 0
    failed = 0

    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {
            executor.submit(run_enrich, scenario_dir, name): (idx, name)
            for idx, (scenario_dir, name) in enumerate(SCENARIO_DIRS, 1)
        }

        for future in as_completed(futures):
            idx, name = futures[future]
            try:
                result = future.result()
            except Exception as e:
                result = {"name": name, "error": str(e), "rc": -1}

            all_results.append(result)
            done = len(all_results)
            pct = int(round((done / len(SCENARIO_DIRS)) * 100))

            if result.get("rc", -1) == 0:
                completed += 1
                status_str = "OK"
            else:
                failed += 1
                status_str = f"FAIL (rc={result.get('rc')})"

            wi = result.get("weak_inferred_net", "?")
            matched = result.get("matched_total", "?")
            um = result.get("unmatched_total", "?")
            elapsed = result.get("elapsed_seconds", "?")
            guard = result.get("enrich_status", "?")
            err = result.get("error", "")
            bb = result.get("backbone_edge_count", "?")

            print(f"  [{done}/{len(SCENARIO_DIRS)}|{pct:>3d}%] {name:<20} -> {status_str}  "
                  f"guard={guard}  bb={bb}  weak_net={wi}  matched={matched}  um={um}  "
                  f"{elapsed}s  {err}  progress=[{_bar(done, len(SCENARIO_DIRS))}]")

            # Save progress after each completed scenario.
            with open(PROGRESS_FILE, "w") as f:
                json.dump({
                    "total": len(SCENARIO_DIRS),
                    "done": done,
                    "percent": pct,
                    "completed": completed,
                    "failed": failed,
                    "scenarios": all_results,
                }, f, indent=2, ensure_ascii=False)

    elapsed_total = round(time.time() - t0, 1)
    print(f"\n[parallel_enrich] Done. {completed}/{len(SCENARIO_DIRS)} succeeded, {failed} failed "
          f"in {elapsed_total}s")

    # Aggregate totals.
    total_wi = sum(r.get("weak_inferred_net", 0) or 0 for r in all_results)
    total_matched = sum(r.get("matched_total", 0) or 0 for r in all_results)
    total_um = sum(r.get("unmatched_total", 0) or 0 for r in all_results)
    skipped = sum(1 for r in all_results if r.get("enrich_status") == "auto-skipped-by-guard")

    print(f"\n=== getsockname|getpeername -> NET_* weak_inferred ===")
    print(f"  weak_inferred_net (getsockname + getpeername): {total_wi}")
    print(f"  matched_malicious_non_core: {total_matched}")
    print(f"  unmatched_malicious_non_core: {total_um}")
    print(f"  auto-skipped by guard: {skipped}")

    summary = {
        "total": len(SCENARIO_DIRS),
        "completed": completed,
        "failed": failed,
        "weak_inferred_net_total": total_wi,
        "matched_total": total_matched,
        "unmatched_total": total_um,
        "skipped_by_guard": skipped,
        "elapsed_seconds_total": elapsed_total,
        "scenarios": all_results,
    }
    with open(SUMMARY_FILE, "w") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    print(f"\nSummary: {SUMMARY_FILE}")


if __name__ == "__main__":
    main()
