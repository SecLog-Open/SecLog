#!/bin/bash

# --------------------------------------------------------------------------
# Default build path (SecLog — Mode B)
# --------------------------------------------------------------------------
# This script leaves the optional behaviour switches unset. Each switch below
# defaults to OFF (the same behaviour as an unset variable) for the standard
# build path:
#
#   SECLOG_THIRD_CUT_OFF           (default 0 = write-gated applog labeling ON)
#                                   Set to 1 to disable write-gated applog
#                                   labelling for a compatibility run.
#
#   SECLOG_DATAFLOW_UNIT_REFINE    (default 0 = paper-strict Unit Partition
#                                   refinement for read_from_tainted_file is
#                                   OFF).
#
#   SECLOG_ANCHOR_BEHAVIORAL       (default 0 = A5/A6 behavioural anchor
#                                   supplement rules OFF). Set to 1 to include
#                                   the optional behavioural anchors.
#
# These defaults define the release build policy.
# --------------------------------------------------------------------------

set -Eeuo pipefail
[[ "${BUILD_XTRACE:-0}" == "1" ]] && set -x

trap 'status=$?; echo "[ERROR] build.sh failed at line ${LINENO}: ${BASH_COMMAND} (exit=${status})" >&2' ERR

log_obs() {
  local prefix="$1"
  shift
  echo "${prefix} $*"
}

# --- human-readable banner helpers -------------------------------------------
# The structured `log_obs` key=value lines above stay in place for log
# parsers. The banner helpers below defer to console_observability.py so that
# the visual style (colours, uppercase status labels, boxed banners, emoji)
# is identical to the Python entry scripts further down the chain.
#
# All heavy visuals are produced by a single poetry-run python helper:
# cheap (one interpreter start per banner call, which is negligible next
# to the scene runtime) and keeps the bash side tiny.

_build_banner() {
  # $1: emitter name in console_observability (banner_box|stage_banner|progress_line)
  # remaining args: forwarded as a single JSON-encoded argv array.
  # We always fall through on any failure so a banner glitch never blocks
  # the build.
  local kind="$1"; shift
  poetry run python - "$kind" "$@" <<'PY' 2>/dev/null || true
import sys
from console_observability import (
    banner_box, progress_line, stage_banner,
)
kind = sys.argv[1]
args = sys.argv[2:]
if kind == "build_start":
    total = args[0]
    run_times = args[1] if len(args) > 1 else "1"
    banner_box(
        f"[build][START] total_scenes={total} run_times={run_times}",
        [f"entry         : bash build.sh",
         f"target_level  : raw/index (plus pipeline/release via pipeline entries)"],
        status="start",
    )
elif kind == "scene_progress":
    idx, total, scene = args
    progress_line("build", int(idx), int(total), current=scene)
elif kind == "scene_start":
    idx, total, scene = args
    stage_banner(
        "scene", "start",
        scope="build", scenario=scene,
        processed=int(idx), total=int(total),
        extra={"output": f"results/{scene}"},
    )
elif kind == "scene_ok":
    scene, elapsed = args
    stage_banner(
        "scene", "ok",
        scope="build", scenario=scene, emoji=True,
        extra={"elapsed": f"{elapsed}s", "exit": 0},
    )
elif kind == "scene_fail":
    scene, elapsed, exit_code, reason = args
    from console_observability import (
        failure_summary_block, highest_level_reached,
    )
    from pathlib import Path as _P
    # Best-effort level report for the scene (newest timestamp dir under
    # results/<scene>) so the failure block also shows how far it got.
    root = _P("results") / scene
    ts_dir = None
    try:
        cands = [p for p in root.iterdir() if p.is_dir()]
        if cands:
            ts_dir = sorted(cands, key=lambda p: p.name, reverse=True)[0]
    except Exception:
        pass
    level = highest_level_reached(ts_dir) if ts_dir else "unknown"
    missing = []
    if ts_dir is None:
        missing.append(f"results/{scene}/<timestamp>/ not created")
    failure_summary_block(
        "build",
        scenario=scene,
        stage="scene_build",
        reason=(reason or f"poetry_run_main exited with code {exit_code}"),
        highest_level=level,
        missing=missing,
    )
    stage_banner(
        "scene", "fail",
        scope="build", scenario=scene, emoji=True,
        extra={
            "elapsed": f"{elapsed}s",
            "exit": exit_code,
            "failing_step": "poetry_run_main (analyze/build)",
        },
    )
elif kind == "build_done":
    ok, total, elapsed = args
    status = "success" if int(ok) == int(total) else "failed"
    banner_box(
        f"[build][DONE] scenes_ok={ok}/{total}",
        [f"elapsed       : {elapsed}s",
         f"target_level  : raw/index"],
        status=status,
    )
elif kind == "level_report":
    scene = args[0]
    from pathlib import Path as _P
    from console_observability import (
        artifact_report, highest_level_reached,
    )
    root = _P("results") / scene
    if not root.exists():
        print(f"[build][scene][INFO] scene={scene} level=unknown (results/{scene} missing)")
        sys.exit(0)
    cands = [p for p in root.iterdir() if p.is_dir()]
    if not cands:
        print(f"[build][scene][INFO] scene={scene} level=unknown (no timestamp dir)")
        sys.exit(0)
    ts_dir = sorted(cands, key=lambda p: p.name, reverse=True)[0]
    level = highest_level_reached(ts_dir)
    stage_banner(
        "level", "info",
        scope="build", scenario=scene,
        extra={"timestamp_dir": ts_dir.name, "highest_level": level},
    )
    artifact_report(
        "build", "artifacts",
        [
            {"path": ts_dir / "raw", "label": "raw/"},
            {"path": ts_dir / "index", "label": "index/"},
            {
                "path": ts_dir / "index" / "write_event_context_index.v0.jsonl",
                "label": "index/write_event_context_index.v0.jsonl",
            },
            {
                "path": ts_dir / "index" / "applog_backbone_candidate_index.v0.jsonl",
                "label": "index/applog_backbone_candidate_index.v0.jsonl",
                "optional": True,
                "note": "disabled by default; enable via --export-applog-backbone-candidates",
            },
            {
                "path": ts_dir / "index" / "applog_write_level_labels.v0.jsonl",
                "label": "index/applog_write_level_labels.v0.jsonl",
                "optional": True,
                "note": "disabled by default; enable via --export-applog-write-level-labels",
            },
        ],
    )
PY
}

banner_build_start() {
  echo
  _build_banner build_start "$1" "${RUN_TIMES}"
  echo
}

banner_scene_start() {
  local idx="$1" total="$2" scene="$3"
  echo
  _build_banner scene_progress "$idx" "$total" "$scene"
  _build_banner scene_start "$idx" "$total" "$scene"
}

banner_scene_ok() {
  local scene="$1" elapsed="$2"
  _build_banner scene_ok "$scene" "$elapsed"
  _build_banner level_report "$scene"
}

banner_scene_fail() {
  local scene="$1" elapsed="$2" exit_code="$3" reason="$4"
  echo
  _build_banner scene_fail "$scene" "$elapsed" "$exit_code" "$reason"
}

banner_build_done() {
  local ok="$1" total="$2" elapsed="$3"
  echo
  _build_banner build_done "$ok" "$total" "$elapsed"
}

declare -a scene_names=(
    # python-demoo: python
    "python-demo"

    # juice-shop: node.js
    "juice-shop"

    # gitlist: php
    "vulhub/gitlist/CVE-2018-1000533"

    # geoserver: java
    "vulhub/geoserver/CVE-2023-25157"
    "vulhub/geoserver/CVE-2024-36401"

    # adminer
    "vulhub/adminer/CVE-2021-43008"

    # metabase: java + Clojure
    "vulhub/metabase/CVE-2021-41277"
    "vulhub/metabase/CVE-2023-38646"

    # solr: java
    "vulhub/solr/CVE-2017-12629-RCE"
    "vulhub/solr/CVE-2017-12629-XXE"
    "vulhub/solr/CVE-2019-0193"
    "vulhub/solr/CVE-2019-17558"

    # cmsms: php
    "vulhub/cmsms/CVE-2019-9053"
    "vulhub/cmsms/CVE-2021-26120-lab"

    # ofbiz: java
    "vulhub/ofbiz/CVE-2020-9496"
    "vulhub/ofbiz/CVE-2023-49070"
    "vulhub/ofbiz/CVE-2024-38856"
    "vulhub/ofbiz/CVE-2024-45195"
    "vulhub/ofbiz/CVE-2024-45507"
    "vulhub/ofbiz/CVE-2023-51467"

    # joomla: php
    "vulhub/joomla/CVE-2015-8562"
    "vulhub/joomla/CVE-2017-8917"
    "vulhub/joomla/CVE-2023-23752"

    # mongo-express: node.js
    "vulhub/mongo-express/CVE-2019-10758"

    # kibana: node.js
    "vulhub/kibana/CVE-2018-17246"

    # pgadmin: python
    "vulhub/pgadmin/CVE-2022-4223"
    "vulhub/pgadmin/CVE-2023-5002"

    # sandworm
    "sandworm"

    # multi-jump
    "multi-jump"
)

RUN_TIMES=1
SCENE_TOTAL=${#scene_names[@]}
build_started_epoch=$(date +%s)
build_scene_ok=0

banner_build_start "$SCENE_TOTAL"

for TIMES in $(seq 1 $RUN_TIMES); do
  log_obs "[build.sh][stage]" "stage=run_loop status=start run=${TIMES} total_runs=${RUN_TIMES} scene_total=${SCENE_TOTAL}"
  scene_idx=0
  for scene_name in "${scene_names[@]}"; do
      scene_idx=$((scene_idx + 1))
      scene_percent=$(awk "BEGIN { printf \"%.2f\", (${scene_idx}/${SCENE_TOTAL}) * 100 }")
      banner_scene_start "${scene_idx}" "${SCENE_TOTAL}" "${scene_name}"
      log_obs "[build.sh][stage]" \
        "stage=scene_build status=start processed=${scene_idx} total=${SCENE_TOTAL} percent=${scene_percent} scenario_dir=example/${scene_name} output_path=results/${scene_name} config_exists=$(test -e "example/${scene_name}" && echo true || echo false)"
      # Run the construction entry point through Poetry so that all scenes use
      # the declared project environment. Mode B is the default dataset path;
      # optional diagnostic sidecars are written only when explicitly enabled.
      scene_start_epoch=$(date +%s)
      if time env BATCH=1 poetry run python main.py --config-path example/${scene_name} --output-path results/${scene_name}; then
        scene_end_epoch=$(date +%s)
        scene_elapsed=$((scene_end_epoch - scene_start_epoch))
        log_obs "[build.sh][stage]" \
          "stage=scene_build status=done processed=${scene_idx} total=${SCENE_TOTAL} percent=${scene_percent} scenario_dir=example/${scene_name} output_path=results/${scene_name} elapsed=${scene_elapsed}s result_dir_exists=$(test -e "results/${scene_name}" && echo true || echo false) exit=0"
        banner_scene_ok "${scene_name}" "${scene_elapsed}"
        build_scene_ok=$((build_scene_ok + 1))
      else
        status=$?
        scene_end_epoch=$(date +%s)
        scene_elapsed=$((scene_end_epoch - scene_start_epoch))
        reason_text=""
        if [ "$status" -eq 137 ]; then
          reason_text="likely_oom_killed (exit=137)"
          log_obs "[build.sh][stage]" \
            "stage=scene_build status=failed failing_step=poetry_run_main processed=${scene_idx} total=${SCENE_TOTAL} percent=${scene_percent} scenario_dir=example/${scene_name} output_path=results/${scene_name} elapsed=${scene_elapsed}s exit=${status} reason=likely_oom_killed" >&2
        else
          log_obs "[build.sh][stage]" \
            "stage=scene_build status=failed failing_step=poetry_run_main processed=${scene_idx} total=${SCENE_TOTAL} percent=${scene_percent} scenario_dir=example/${scene_name} output_path=results/${scene_name} elapsed=${scene_elapsed}s exit=${status}" >&2
        fi
        banner_scene_fail "${scene_name}" "${scene_elapsed}" "${status}" "${reason_text}" >&2
        exit "$status"
      fi
      log_obs "[build.sh][stage]" "stage=scene_build substep=next_scene processed=${scene_idx} total=${SCENE_TOTAL} percent=${scene_percent} scenario_dir=example/${scene_name}"
  done
  log_obs "[build.sh][stage]" "stage=run_loop status=done run=${TIMES} total_runs=${RUN_TIMES} scene_total=${SCENE_TOTAL}"
done

build_end_epoch=$(date +%s)
build_total_elapsed=$((build_end_epoch - build_started_epoch))
banner_build_done "${build_scene_ok}" "${SCENE_TOTAL}" "${build_total_elapsed}"
