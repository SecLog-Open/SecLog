# -*- coding: utf-8 -*-
"""
audit_evt_type_stats.py
Collect sysdig JSONL audit log event-type statistics.

Adaptive sampling to handle very large files (some > 7 GB):
  <  50 MB :  read every line  (rate=1)
  50-500 MB:  read every 5th line
  500MB-2GB:  read every 20th line
  > 2 GB   :  read every 50th line

All counts are scaled back to estimated totals for comparability.
"""

import json
import csv
import os
from pathlib import Path
from collections import defaultdict, Counter
from datetime import datetime


def find_repo_root(start: Path) -> Path:
    current = start.resolve()
    for candidate in (current.parent, *current.parents):
        if (candidate / "pyproject.toml").exists() and (candidate / "example").exists():
            return candidate
    raise RuntimeError(f"Repo root not found from {start}")


REPO_ROOT = find_repo_root(Path(__file__))

# ---- config -----------------------------------------------------------------
RESULTS_ROOT = REPO_ROOT / "results"
OUTPUT_DIR = REPO_ROOT / "results_analysis" / "audit_stats"

SYSDIG_SIGNATURE_FIELDS = {"evt.type", "evt.category", "evt.datetime"}
SYSDIG_REQUIRED_FIELDS  = 2

# Adaptive sampling thresholds (bytes)
THRESHOLDS = [
    (50  * 1024 * 1024,  1),   # < 50 MB  -> every line
    (500 * 1024 * 1024,  5),   # < 500 MB -> every 5th
    (2   * 1024 * 1024 * 1024, 20),  # < 2 GB -> every 20th
]
DEFAULT_SAMPLE_RATE = 50  # >= 2 GB
# -----------------------------------------------------------------------------


def sample_rate_for(path: Path) -> int:
    size = path.stat().st_size
    for threshold, rate in THRESHOLDS:
        if size < threshold:
            return rate
    return DEFAULT_SAMPLE_RATE


def is_sysdig_log(path: Path) -> bool:
    if path.suffix.lower() != ".log":
        return False
    norm = path.as_posix().lower()
    if "raw/sysdig" not in norm:
        return False
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                obj = json.loads(line)
                hits = sum(1 for k in SYSDIG_SIGNATURE_FIELDS if k in obj)
                return hits >= SYSDIG_REQUIRED_FIELDS
    except Exception:
        pass
    return False


def extract_scenario(log_path: Path, root: Path) -> str:
    try:
        parts = list(log_path.relative_to(root).parts)
        raw_idx = next(i for i, p in enumerate(parts) if p.lower() == "raw")
        return "/".join(parts[:raw_idx])
    except (ValueError, StopIteration):
        return str(log_path.parent)


def parse_log_file(path: Path, rate: int):
    """Yield (evt_type, evt_category); read only 1-in-rate lines."""
    bad = 0; total = 0; sampled = 0
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for i, raw in enumerate(f):
            raw = raw.strip()
            if not raw:
                continue
            total += 1
            if (i % rate) != 0:
                continue
            sampled += 1
            try:
                obj = json.loads(raw)
            except json.JSONDecodeError:
                bad += 1
                continue
            yield (
                obj.get("evt.type")     or "<unknown_type>",
                obj.get("evt.category") or "<unknown_category>",
            )
    if bad:
        print(f"    [warn] {path.name}: {bad} bad JSON lines (of {sampled} sampled/{total} total)")


def collect_stats(root: Path):
    global_ctr    = Counter()
    scenario_ctr  = defaultdict(Counter)
    cat_type_ctr  = defaultdict(Counter)
    type_file_map = defaultdict(set)
    file_meta     = []   # list of dicts for reporting

    print(f"Scanning: {root}\n")
    for log_path in sorted(root.rglob("*.log")):
        if not is_sysdig_log(log_path):
            continue
        scenario = extract_scenario(log_path, root)
        fname    = log_path.name
        size_mb  = log_path.stat().st_size / 1024 / 1024
        rate     = sample_rate_for(log_path)
        print(f"  [{scenario}] {fname}  ({size_mb:.1f} MB, rate=1/{rate})")

        local_ctr = Counter()
        for evt_type, evt_category in parse_log_file(log_path, rate):
            local_ctr[(evt_type, evt_category)] += 1

        # scale counts by sample rate
        for (evt_type, evt_category), cnt in local_ctr.items():
            scaled = cnt * rate
            global_ctr[evt_type]                    += scaled
            scenario_ctr[scenario][evt_type]        += scaled
            cat_type_ctr[evt_category][evt_type]    += scaled
            type_file_map[evt_type].add((scenario, fname))

        file_meta.append({
            "scenario": scenario,
            "filename": fname,
            "size_mb": f"{size_mb:.1f}",
            "sample_rate": f"1/{rate}",
            "est_events": sum(local_ctr.values()) * rate,
        })

    print(f"\nProcessed {len(file_meta)} sysdig log file(s)")
    return global_ctr, scenario_ctr, cat_type_ctr, type_file_map, file_meta


# ---- writers ----------------------------------------------------------------

def write_global_stats(ctr, out_dir):
    total = sum(ctr.values())
    rows = [
        {"rank": r, "evt.type": et, "count": cnt,
         "percentage(%)": f"{cnt/total*100:.4f}" if total else "0"}
        for r, (et, cnt) in enumerate(ctr.most_common(), 1)
    ]
    p = out_dir / "evt_type_global_stats.csv"
    with open(p, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=["rank","evt.type","count","percentage(%)"])
        w.writeheader(); w.writerows(rows)
    print(f"  wrote {p.name}  ({len(rows)} rows)")
    return rows


def write_by_scenario(scenario_ctr, out_dir):
    p = out_dir / "evt_type_by_scenario.csv"
    rows = []
    for sc in sorted(scenario_ctr):
        ctr = scenario_ctr[sc]; total = sum(ctr.values())
        for et, cnt in ctr.most_common():
            rows.append({"scenario":sc,"evt.type":et,"count":cnt,
                         "pct_in_scenario(%)":f"{cnt/total*100:.4f}" if total else "0"})
    with open(p, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=["scenario","evt.type","count","pct_in_scenario(%)"])
        w.writeheader(); w.writerows(rows)
    print(f"  wrote {p.name}  ({len(rows)} rows)")


def write_by_category(cat_ctr, out_dir):
    p = out_dir / "evt_type_by_category.csv"
    rows = []
    for cat in sorted(cat_ctr):
        ctr = cat_ctr[cat]; total = sum(ctr.values())
        for et, cnt in ctr.most_common():
            rows.append({"evt.category":cat,"evt.type":et,"count":cnt,
                         "pct_in_category(%)":f"{cnt/total*100:.4f}" if total else "0"})
    with open(p, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=["evt.category","evt.type","count","pct_in_category(%)"])
        w.writeheader(); w.writerows(rows)
    print(f"  wrote {p.name}  ({len(rows)} rows)")


def write_file_xref(type_file_map, out_dir):
    p = out_dir / "evt_type_file_xref.csv"
    rows = []
    for et in sorted(type_file_map):
        for sc, fn in sorted(type_file_map[et]):
            rows.append({"evt.type":et,"scenario":sc,"filename":fn})
    with open(p, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=["evt.type","scenario","filename"])
        w.writeheader(); w.writerows(rows)
    print(f"  wrote {p.name}  ({len(rows)} rows)")


def write_file_meta(file_meta, out_dir):
    p = out_dir / "file_processing_meta.csv"
    with open(p, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=["scenario","filename","size_mb","sample_rate","est_events"])
        w.writeheader(); w.writerows(file_meta)
    print(f"  wrote {p.name}  ({len(file_meta)} rows)")


def write_summary_md(global_rows, scenario_ctr, cat_ctr, type_file_map, file_meta, out_dir):
    total_events = sum(int(r["count"]) for r in global_rows)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    B = []
    B.append("# sysdig Audit Log evt.type Statistics Report")
    B.append(f"\n> Generated: {now}")
    B.append(f"> Root: `{RESULTS_ROOT}`")
    B.append(f"> Note: large files are sampled (counts are estimated totals)\n")

    B.append("## Overview\n")
    B.append("| Item | Value |")
    B.append("|---|---|")
    B.append(f"| Total estimated events | {total_events:,} |")
    B.append(f"| Distinct evt.type | {len(global_rows)} |")
    B.append(f"| Scenarios | {len(scenario_ctr)} |")
    B.append(f"| evt.category | {len(cat_ctr)} |")
    B.append(f"| Log files processed | {len(file_meta)} |")

    B.append("\n## Files Processed\n")
    B.append("| scenario | filename | size(MB) | sample_rate | est_events |")
    B.append("|---|---|---|---|---|")
    for m in file_meta:
        B.append(f"| {m['scenario']} | `{m['filename']}` | {m['size_mb']} | {m['sample_rate']} | {m['est_events']:,} |")

    B.append("\n## Global evt.type Top 30\n")
    B.append("| rank | evt.type | est_count | percentage(%) |")
    B.append("|---|---|---|---|")
    for r in global_rows[:30]:
        B.append(f"| {r['rank']} | `{r['evt.type']}` | {int(r['count']):,} | {r['percentage(%)']} |")

    B.append("\n## Top-5 evt.type per Scenario\n")
    for sc in sorted(scenario_ctr):
        ctr = scenario_ctr[sc]; total_s = sum(ctr.values())
        B.append(f"### {sc}  (est. {total_s:,} events)\n")
        B.append("| evt.type | est_count | pct |")
        B.append("|---|---|---|")
        for et, cnt in ctr.most_common(5):
            B.append(f"| `{et}` | {cnt:,} | {cnt/total_s*100:.2f}% |")
        B.append("")

    B.append("\n## evt.category Summary\n")
    B.append("| evt.category | est_total | distinct types | top evt.type |")
    B.append("|---|---|---|---|")
    for cat in sorted(cat_ctr):
        ctr = cat_ctr[cat]
        top = ctr.most_common(1)[0][0] if ctr else "-"
        B.append(f"| `{cat}` | {sum(ctr.values()):,} | {len(ctr)} | `{top}` |")

    B.append("\n## evt.type x Scenario (Top 20 types)\n")
    B.append("| evt.type | #scenarios | scenarios |")
    B.append("|---|---|---|")
    for r in global_rows[:20]:
        et = r["evt.type"]
        scs = sorted({s for s,_ in type_file_map.get(et,set())})
        B.append(f"| `{et}` | {len(scs)} | {', '.join(f'`{s}`' for s in scs)} |")

    p = out_dir / "evt_type_summary.md"
    p.write_text("\n".join(B), encoding="utf-8")
    print(f"  wrote {p.name}")


# ---- main -------------------------------------------------------------------
def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    t0 = datetime.now()
    print("=" * 60)
    print("  sysdig Audit Log Statistics  (adaptive sampling)")
    print("=" * 60)
    global_ctr, scenario_ctr, cat_ctr, type_file_map, file_meta = collect_stats(RESULTS_ROOT)
    if not global_ctr:
        print("[ERROR] No events found.")
        return
    total = sum(global_ctr.values())
    elapsed = (datetime.now() - t0).total_seconds()
    print(f"\nTotal est. {total:,} events, {len(global_ctr)} distinct evt.type  "
          f"({elapsed:.1f}s)")
    print(f"Writing to {OUTPUT_DIR} ...\n")
    global_rows = write_global_stats(global_ctr, OUTPUT_DIR)
    write_by_scenario(scenario_ctr, OUTPUT_DIR)
    write_by_category(cat_ctr, OUTPUT_DIR)
    write_file_xref(type_file_map, OUTPUT_DIR)
    write_file_meta(file_meta, OUTPUT_DIR)
    write_summary_md(global_rows, scenario_ctr, cat_ctr, type_file_map, file_meta, OUTPUT_DIR)
    print(f"\nDone in {(datetime.now()-t0).total_seconds():.1f}s")

if __name__ == "__main__":
    main()
