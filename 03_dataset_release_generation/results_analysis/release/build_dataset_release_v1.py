#!/usr/bin/env python3
"""Assemble ``dataset_release_v1/`` from existing ``chain/`` products.

Release layout (per repo)::

    dataset_release_v1/
    ├── manifest.json
    ├── README.md
    ├── schemas/
    │   ├── main_sample.v0.schema.json
    │   ├── narrative_roles.v0.schema.json
    │   └── stage_labels.v0.schema.json
    ├── shared/
    │   └── scenarios/
    │       └── <scenario_slug>/
    │           ├── main_sample.json
    │           ├── main_sample.meta.json
    │           ├── narrative_roles.v0.json
    │           ├── stage_labels.v0.json
    │           └── legacy_stage_segments.v0.json
    └── settings/
        ├── setting_1_real_input/
        ├── setting_2_anchor_hint/
        └── setting_3_multitask/

This exporter is pure: it only reads ``chain/`` products and writes
into the release tree. It does not mutate any upstream artefact and
does not write any new sidecar back into ``chain/``.

Narrative-role computation is self-contained: when the source backbone
predates the narrative-role patch (no ``chain_summary.narrative_roles``
block), the exporter computes per-edge roles from first/last malicious
seq plus preparation_shell_trial.kept_edge_ids using the same
structural rules documented in ``build_attack_chain_v1.py``
(``_annotate_backbone_narrative_roles``).
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Optional

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from results_analysis.pipeline.utils.common import CHAIN_DIR_NAME, LEGACY_CHAIN_DIR_NAME
# Generated release trees default outside the code unit. Pass --release-root
# to select a different location.
DEFAULT_RELEASE_ROOT = REPO_ROOT.parents[1] / "seclog_work" / "dataset_release_v1"
DEFAULT_RELEASE_ROOT_DISPLAY = "../seclog_work/dataset_release_v1"

MAIN_SAMPLE_SCHEMA_VERSION = "dataset_release.v1.main_sample"
MAIN_SAMPLE_META_SCHEMA_VERSION = "dataset_release.v1.main_sample.meta"
NARRATIVE_ROLES_SCHEMA_VERSION = "dataset_release.v1.narrative_roles"
STAGE_LABELS_SCHEMA_VERSION = "dataset_release.v1.stage_labels"
LEGACY_STAGE_SEGMENTS_SCHEMA_VERSION = "dataset_release.v1.legacy_stage_segments"
MANIFEST_SCHEMA_VERSION = "dataset_release.v1.manifest"

# Per-edge attrs kept in main_sample (matches the current on-disk
# behavior_chain_dataset.v2 whitelist exactly; do not widen without
# reviewing label-leakage risk).
MAIN_SAMPLE_ATTR_WHITELIST = (
    "evt_num",
    "timestamp",
    "raw_evt_type",
    "container_id",
    "fd_name",
    "malicious",
)

# Roles drawn from the existing backbone narrative-role vocabulary.
# Kept in sync with ``build_attack_chain_v1.BACKBONE_NARRATIVE_ROLE_VOCABULARY``
# so the release consumes a stable schema.
NARRATIVE_ROLE_VOCABULARY = (
    "preparation_boundary_start",
    "preparation_boundary_end",
    "startup_handoff_exec",
    "entry_bridge_pre",
    "mid_span_representative",
    "semantic_entry_anchor",
    "result_anchor",
    "result_tail_context",
)

# Result-tail window (seq steps) -- matches build_attack_chain_v1
# BACKBONE_NARRATIVE_RESULT_TAIL_SEQ_WINDOW = 3.
NARRATIVE_RESULT_TAIL_SEQ_WINDOW = 3

# Relations considered "result-like" when picking a result_tail_context
# (matches build_attack_chain_v1.BACKBONE_RESULT_RELATIONS).
BACKBONE_RESULT_RELATIONS = frozenset(
    {"FILE_WRITE", "NET_SEND", "NET_CONNECT", "PROCESS_EXEC", "FILE_READ"}
)

# v0.4.2 tier-B extension: post-result "shell" relations on the anchor
# subject. These are accepted by the result walker ONLY after at least
# one tier-A edge has been accepted OR when the very first post-last_mal
# edge on the anchor subject is a tier-B edge (pgadmin-style tails).
# Intent: capture the "attacker subject keeps forking / accepting new
# work" tail so it isn't silently dropped into `stage_unclosed`. Bounded by
# STAGE_RESULT_TIER_B_CAP to avoid pulling runaway PROCESS_FORK tails
# (e.g. pgadmin/CVE-2022-4223 has 1191 PROCESS_FORK edges after
# last_mal) fully into the result span.
STAGE_RESULT_TIER_B_RELATIONS = frozenset(
    {"PROCESS_FORK", "PROCESS_CLONE", "NET_ACCEPT"}
)
STAGE_RESULT_TIER_B_CAP = 16

# v0.4.2 inferred-preparation rule: when narrative_roles carries no
# prep_end markers (25/29 scenarios in the current release) but the
# entry edge is preceded by a short run of same-subject non-malicious
# edges, treat that run as preparation. Bounded by
# STAGE_PREP_INFERRED_K so we never claim a long runtime tail as
# preparation (e.g. pgadmin has 1185 same-subject pre-entry edges).
STAGE_PREP_INFERRED_K = 5

# v0.4.3 same-exe-in-container subject relaxation. Subject strings in
# the spine take the shape ``proc:<container_id>:<pid>:<exe_path>``. A
# fresh-forked worker process (e.g. apache2 child) keeps the same
# container_id and same exe_path but gets a new pid, so a strict
# subject-equality test drops it. When the strict anchor-subject match
# fails the walkers fall back to "same container_id AND same exe_path"
# so a worker-fork continuation is still recognised as the same
# attacker process family. Cross-container or cross-binary matches are
# never accepted. The preparation fallback uses a tighter cap to stay
# conservative.
STAGE_PREP_INFERRED_K_EXE_RELAXED = 3

# H2: applog model-facing relevance tier. Pure derived field added to
# each applog entry under main_sample.spine[*].multisource_context.applog.
# Does not mutate any other field, does not change the attach algorithm,
# does not affect cap/weak_cap/promotion stats. Vocabulary:
#   * attack_related  -- is_attack_related is True (pipeline-assigned)
#   * error_or_hv     -- high-value semantic types (exceptions, db,
#                        generic runtime logs) not flagged attack-related
#   * background      -- everything else (mostly request_access noise)
APPLOG_TIER_VOCABULARY = ("attack_related", "error_or_hv", "background")
APPLOG_HIGH_VALUE_SEMANTIC_TYPES = frozenset(
    {"error_exception", "db_query", "generic_runtime_log"}
)

# Confidence tier lookup: role_source -> tier.
ROLE_SOURCE_TO_TIER = {
    "first_malicious_edge": "high",
    "last_malicious_edge": "high",
    "trial_d.kept_anchor_roles.preparation_boundary_start": "mid",
    "trial_d.kept_anchor_roles.preparation_boundary_end": "mid",
    "trial_d.kept_anchor_roles.startup_handoff_exec": "mid",
    "trial_d.kept_anchor_roles.entry_bridge_pre": "mid",
    "trial_d.kept_edge_ids_fallback.preparation_boundary_start": "mid",
    "trial_d.kept_edge_ids_fallback.preparation_boundary_end": "mid",
    "subject_same_result_tail_window": "mid",
    "trial_d.kept_anchor_roles.mid_span_representative": "low",
    "trial_d.kept_edge_ids_fallback.mid_span_representative": "low",
}

# Stage-derivation tail window fallback (when narrative_roles provides
# no explicit result_tail). K = max(DEFAULT_K_MIN, round(ratio * len)).
STAGE_DERIVATION_K_MIN = 3
STAGE_DERIVATION_K_RATIO = 0.05


# ---------------------------------------------------------------------------
# IO helpers
# ---------------------------------------------------------------------------

def _read_json(path: Path) -> Any:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, ensure_ascii=False, indent=2)
        fh.write("\n")


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


# ---------------------------------------------------------------------------
# Scenario discovery
# ---------------------------------------------------------------------------

def _scenario_slug(scenario_id: str) -> str:
    """Stable filesystem-safe slug for a scenario_id.

    Example: ``vulhub/solr/CVE-2019-17558`` -> ``vulhub__solr__CVE-2019-17558``.
    """
    return (
        scenario_id.replace("/", "__")
        .replace(":", "_")
        .replace(" ", "_")
    )


def _resolve_chain_dir(scenario_dir: Path) -> Path:
    """Resolve the chain directory for a scenario run."""
    if scenario_dir.name in {CHAIN_DIR_NAME, LEGACY_CHAIN_DIR_NAME}:
        return scenario_dir
    chain_dir = scenario_dir / CHAIN_DIR_NAME
    if chain_dir.is_dir():
        return chain_dir
    legacy_chain_dir = scenario_dir / LEGACY_CHAIN_DIR_NAME
    if legacy_chain_dir.is_dir():
        return legacy_chain_dir
    raise FileNotFoundError(
        f"no {CHAIN_DIR_NAME}/ under {scenario_dir}; pass --chain-dir directly"
    )


_TIMESTAMP_RE_CHARS = set("0123456789-_")


def _looks_like_timestamp(name: str) -> bool:
    """Heuristic: run-directory names are like ``2026-04-14_05-04-15``."""
    if not name or len(name) < 10:
        return False
    if not all(c in _TIMESTAMP_RE_CHARS for c in name):
        return False
    # Must contain at least one '-' and one '_' to avoid false positives
    # on CVE-ids (which only have '-').
    return "-" in name and "_" in name


def _derive_scenario_id_from_path(chain_dir: Path) -> Optional[str]:
    """Derive a stable scenario_id from the chain directory path.

    Walks up from ``chain`` and collects parts up to (but excluding)
    the ``results`` segment. Trailing timestamp-looking segments are
    dropped so that different runs of the same scenario yield the same
    id. Falls back to ``None`` when the layout is unfamiliar.

    Example::

        results/vulhub/solr/CVE-2019-17558/2026-04-14_05-04-15/chain
        -> "vulhub/solr/CVE-2019-17558"
    """
    parts = list(chain_dir.resolve().parts)
    if "results" not in parts:
        return None
    anchor = len(parts) - 1 - list(reversed(parts)).index("results")
    tail = parts[anchor + 1:]
    if tail and tail[-1] in {CHAIN_DIR_NAME, LEGACY_CHAIN_DIR_NAME}:
        tail = tail[:-1]
    while tail and _looks_like_timestamp(tail[-1]):
        tail = tail[:-1]
    if not tail:
        return None
    return "/".join(tail)


# ---------------------------------------------------------------------------
# main_sample.json / main_sample.meta.json builders
# ---------------------------------------------------------------------------

def _build_seq_to_edge_id(backbone: dict[str, Any]) -> dict[int, str]:
    out: dict[int, str] = {}
    for edge in backbone.get("edge_sequence") or []:
        try:
            seq = int(edge.get("seq"))
        except (TypeError, ValueError):
            continue
        eid = str(edge.get("edge_id") or "")
        if not eid:
            continue
        out[seq] = eid
    return out


def _build_evt_num_to_edge_id(backbone: dict[str, Any]) -> dict[int, str]:
    """Map evt_num -> edge_id from backbone.edge_sequence.

    ``evt_num`` is globally unique in the audit triples stream, so this
    map gives a join key that survives pipeline drift (dataset run on
    older backbone vs. a newer narrower backbone). Seq-based joins
    break when spine_len != backbone.edge_count, but evt_num-based
    joins stay correct for the shared subset.
    """
    out: dict[int, str] = {}
    for edge in backbone.get("edge_sequence") or []:
        attrs = edge.get("attrs") or {}
        try:
            evt = int(attrs.get("evt_num"))
        except (TypeError, ValueError):
            continue
        eid = str(edge.get("edge_id") or "")
        if eid:
            out[evt] = eid
    return out


# ---------------------------------------------------------------------------
# Slim / dedup helpers for audit_context and traffic (M1 / M2 / M3 patches)
# ---------------------------------------------------------------------------
#
# These helpers are applied at release-build time only. They never mutate
# the source chain artefacts; they just drop bookkeeping/duplicate
# fields from the main_sample.spine[*].audit_context and
# multisource_context.traffic lists so the model-facing view is smaller
# and easier to read.
#
# All removals are documented in `main_sample.v0.schema.json` under the
# `audit_context_entry_slim_policy` and `traffic_entry_slim_policy`
# blocks. The top-level `schema_version` string is unchanged: none of
# these drops alter labels / supervision / attach judgements; they are
# strictly information-preserving w.r.t. what the model needs to see
# (all dropped fields are either duplicates already present under a
# different path, or pure diagnostic/pcap-bookkeeping flags).

# M2: link_features is a pure attachment-judgement feature used by the
# builder's candidate scoring. It is never read by the model-facing
# consumption pipeline and has no label value on its own. Strip it.
_AUDIT_CONTEXT_DROPPED_TOP_FIELDS = ("link_features",)

# M1 dedup: inner `event.record_mode` is always a tag describing the
# event's own record type (e.g. "structured_event"). Outer `record_mode`
# already carries the attach-level record-mode ("triple"/"structured").
# They are two different axes but both are set at attach time and the
# inner one is strictly redundant for consumption — the outer one
# already tells the consumer how to parse the entry.
_AUDIT_CONTEXT_INNER_EVENT_DROP_IF_PRESENT = ("record_mode",)

# M1 dedup: `event.proc` and `event.fd` are convenience mirrors of
# fields already inside `event.attrs`. They are dropped only when the
# mirror is fully consistent with `event.attrs` (no value ever
# disagrees). If any value differs we keep the block intact so we
# never silently lose information.
def _event_proc_is_redundant(proc: dict[str, Any], attrs: dict[str, Any]) -> bool:
    if not isinstance(proc, dict) or not isinstance(attrs, dict):
        return False
    # Accepted proc keys and their expected attrs counterpart.
    mapping = {
        "container_id": "container_id",
        "pid": "proc_pid",
        "name": "proc_name",
        "exepath": "proc_exepath",
    }
    for proc_key, attr_key in mapping.items():
        if proc_key not in proc:
            continue
        if attrs.get(attr_key) != proc.get(proc_key):
            return False
    # Must not carry unknown keys; if it does, keep it (conservative).
    for k in proc.keys():
        if k not in mapping:
            return False
    return True


def _event_fd_is_redundant(fd: dict[str, Any], attrs: dict[str, Any]) -> bool:
    if not isinstance(fd, dict) or not isinstance(attrs, dict):
        return False
    mapping = {"name": "fd_name", "type": "fd_type"}
    for fd_key, attr_key in mapping.items():
        if fd_key not in fd:
            continue
        if attrs.get(attr_key) != fd.get(fd_key):
            return False
    for k in fd.keys():
        if k not in mapping:
            return False
    return True


def _slim_audit_context_entry(entry: dict[str, Any]) -> dict[str, Any]:
    """Return a shallow-copy audit_context entry with M1+M2 slimming applied.

    Guarantees:
      * `link_features` is removed (M2).
      * Inside `event`: `record_mode` is removed (M1).
      * Inside `event`: `proc` is removed iff all its fields match
        `event.attrs.{container_id, proc_pid, proc_name, proc_exepath}`.
      * Inside `event`: `fd` is removed iff all its fields match
        `event.attrs.{fd_name, fd_type}`.
      * No other field is touched.
    """
    if not isinstance(entry, dict):
        return entry
    new_entry = {k: v for k, v in entry.items()
                 if k not in _AUDIT_CONTEXT_DROPPED_TOP_FIELDS}
    ev = new_entry.get("event")
    if isinstance(ev, dict):
        new_ev = dict(ev)
        for drop_key in _AUDIT_CONTEXT_INNER_EVENT_DROP_IF_PRESENT:
            new_ev.pop(drop_key, None)
        attrs = new_ev.get("attrs") or {}
        proc = new_ev.get("proc")
        if isinstance(proc, dict) and _event_proc_is_redundant(proc, attrs):
            new_ev.pop("proc", None)
        fd = new_ev.get("fd")
        if isinstance(fd, dict) and _event_fd_is_redundant(fd, attrs):
            new_ev.pop("fd", None)
        new_entry["event"] = new_ev
    return new_entry


def _slim_audit_context(
    audit_context: Any,
) -> list[dict[str, Any]]:
    if not isinstance(audit_context, list):
        return []
    out: list[dict[str, Any]] = []
    for entry in audit_context:
        if isinstance(entry, dict):
            out.append(_slim_audit_context_entry(entry))
        else:
            out.append(entry)
    return out


# M3 traffic slim: drop attach_basis, frame_range, network_node_ids,
# nat_alias_used, and the reverse=0 half of direction_counts. These are
# all pcap/builder-internal bookkeeping fields; attach decisions
# (attach_reason, attach_strength, attach_to_backbone_edge_id) remain
# intact so the model can still see "why this flow was attached".
_TRAFFIC_DROPPED_TOP_FIELDS = (
    "attach_basis",
    "frame_range",
    "network_node_ids",
    "nat_alias_used",
)


def _slim_direction_counts(dc: Any) -> Any:
    """Drop `reverse` when it is 0; return the compacted dict.

    Semantics preserved: reverse=0 is the default interpretation for a
    unidirectional flow summary. Keeping `forward` alone is equivalent
    when `reverse` is absent-or-zero.
    """
    if not isinstance(dc, dict):
        return dc
    out = dict(dc)
    rev = out.get("reverse")
    if rev == 0:
        out.pop("reverse", None)
    return out


def _slim_traffic_entry(entry: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(entry, dict):
        return entry
    new_entry = {k: v for k, v in entry.items()
                 if k not in _TRAFFIC_DROPPED_TOP_FIELDS}
    if "direction_counts" in new_entry:
        new_entry["direction_counts"] = _slim_direction_counts(
            new_entry["direction_counts"]
        )
    return new_entry


def _slim_traffic_list(traffic: Any) -> list[dict[str, Any]]:
    if not isinstance(traffic, list):
        return []
    out: list[dict[str, Any]] = []
    for entry in traffic:
        if isinstance(entry, dict):
            out.append(_slim_traffic_entry(entry))
        else:
            out.append(entry)
    return out


def _derive_applog_attack_relevance_tier(entry: dict[str, Any]) -> str:
    """Derive the H2 per-applog `attack_relevance_tier`.

    Rules (checked in order; first match wins):
      1. `is_attack_related` is truthy -> "attack_related"
      2. `semantic_type` in APPLOG_HIGH_VALUE_SEMANTIC_TYPES -> "error_or_hv"
      3. otherwise -> "background"
    """
    if bool(entry.get("is_attack_related")):
        return "attack_related"
    sem = str(entry.get("semantic_type") or "")
    if sem in APPLOG_HIGH_VALUE_SEMANTIC_TYPES:
        return "error_or_hv"
    return "background"


def _annotate_applog_with_relevance_tier(
    multisource: dict[str, Any] | None,
) -> dict[str, Any]:
    """Return a new multisource_context dict with the H2 tier injected
    and the M3 traffic slimming applied.

    Pure function: builds a new `applog` list of shallow copies, each
    with `attack_relevance_tier` set. `traffic` is run through
    ``_slim_traffic_list`` to strip pcap/builder bookkeeping fields
    (M3). Any other keys are passed through without modification.
    Original input is not mutated.
    """
    if not isinstance(multisource, dict):
        return {"traffic": [], "applog": []}
    out: dict[str, Any] = dict(multisource)
    applog = out.get("applog") or []
    if isinstance(applog, list) and applog:
        annotated: list[dict[str, Any]] = []
        for entry in applog:
            if isinstance(entry, dict):
                new_entry = dict(entry)
                new_entry["attack_relevance_tier"] = (
                    _derive_applog_attack_relevance_tier(entry)
                )
                annotated.append(new_entry)
            else:
                annotated.append(entry)
        out["applog"] = annotated
    else:
        out["applog"] = []
    # M3: slim traffic entries (attach_basis / frame_range /
    # network_node_ids / nat_alias_used / direction_counts.reverse=0).
    out["traffic"] = _slim_traffic_list(out.get("traffic"))
    return out


def _assert_no_narrative_leak_in_spine(spine: list[dict[str, Any]]) -> None:
    """Hard assertion: main_sample spine must never carry narrative_role.

    Current builder uses a whitelist so this holds, but the assertion
    protects the release against future accidental regressions.
    """
    forbidden_top = {"narrative_role", "narrative_role_alt"}
    forbidden_attrs = {"narrative_role", "narrative_role_alt"}
    for idx, edge in enumerate(spine):
        bad = forbidden_top.intersection(edge.keys())
        if bad:
            raise RuntimeError(
                f"main_sample spine entry #{idx} carries forbidden fields "
                f"{sorted(bad)}; narrative roles must not enter main sample"
            )
        attrs = edge.get("attrs") or {}
        bad_a = forbidden_attrs.intersection(attrs.keys())
        if bad_a:
            raise RuntimeError(
                f"main_sample spine entry #{idx} attrs carries forbidden "
                f"fields {sorted(bad_a)}; narrative roles must not enter "
                "main sample"
            )


def _build_main_sample(
    dataset: dict[str, Any],
    backbone: dict[str, Any],
    scenario_id: str,
) -> dict[str, Any]:
    """Assemble main_sample.json.

    Join strategy for ``edge_id``: primary by ``evt_num`` (robust to
    pipeline drift, since evt_num is globally unique). Fallback by
    ``seq`` when both sides have identical spine_len (typical freshly
    built scenario). If both fail, the spine entry's ``edge_id`` is
    left None and the stats block records the miss count.
    """
    evt_to_eid = _build_evt_num_to_edge_id(backbone)
    seq_to_eid = _build_seq_to_edge_id(backbone)
    backbone_len = len(backbone.get("edge_sequence") or [])
    spine_len = len(dataset.get("spine") or [])
    use_seq_fallback = (spine_len == backbone_len) and spine_len > 0

    joined_by_evt = 0
    joined_by_seq_fallback = 0
    new_spine: list[dict[str, Any]] = []
    for edge in dataset.get("spine") or []:
        seq_val = edge.get("seq")
        try:
            seq_int = int(seq_val)
        except (TypeError, ValueError):
            seq_int = None

        raw_attrs = edge.get("attrs") or {}
        try:
            evt_int = int(raw_attrs.get("evt_num"))
        except (TypeError, ValueError):
            evt_int = None

        edge_id: Optional[str] = None
        if evt_int is not None:
            edge_id = evt_to_eid.get(evt_int)
            if edge_id:
                joined_by_evt += 1
        if edge_id is None and use_seq_fallback and seq_int is not None:
            edge_id = seq_to_eid.get(seq_int)
            if edge_id:
                joined_by_seq_fallback += 1

        slim_attrs = {
            key: raw_attrs[key] for key in MAIN_SAMPLE_ATTR_WHITELIST
            if key in raw_attrs
        }

        new_spine.append({
            "seq": seq_int if seq_int is not None else seq_val,
            "edge_id": edge_id,
            "subject": edge.get("subject"),
            "relation": edge.get("relation"),
            "object": edge.get("object"),
            "attrs": slim_attrs,
            # M1 + M2: strip link_features and lossless-dedup inner
            # event.{record_mode, proc, fd}. No attach decision field
            # is touched.
            "audit_context": _slim_audit_context(edge.get("audit_context")),
            # H2: inject `attack_relevance_tier` on each applog entry.
            # Pure derived field; no existing key is removed or mutated.
            # M3: also slims traffic entries (attach_basis, frame_range,
            # network_node_ids, nat_alias_used, direction_counts.reverse=0).
            "multisource_context": _annotate_applog_with_relevance_tier(
                edge.get("multisource_context")
            ),
        })

    _assert_no_narrative_leak_in_spine(new_spine)

    joined_total = joined_by_evt + joined_by_seq_fallback
    main_sample = {
        "schema_version": MAIN_SAMPLE_SCHEMA_VERSION,
        "scenario_id": scenario_id,
        "chain_id": dataset.get("chain_id"),
        "spine": new_spine,
        "_join_stats": {
            "total_spine_edges": len(new_spine),
            "backbone_edge_count": backbone_len,
            "edges_with_edge_id": joined_total,
            "edges_without_edge_id": len(new_spine) - joined_total,
            "joined_by_evt_num": joined_by_evt,
            "joined_by_seq_fallback": joined_by_seq_fallback,
            "pipeline_drift_detected": spine_len != backbone_len,
        },
    }
    return main_sample


def _select_meta_fields(meta: dict[str, Any]) -> dict[str, Any]:
    """Filter the source meta file into a label-leakage-safe *small* view.

    Release meta holds small, non-answer summary information. We drop:

    * Per-attachment / per-edge bookkeeping (``context_attach_details``,
      ``edge_applog_context_view``) -- these mirror or aggregate what is
      already inside ``main_sample.spine[*].audit_context`` and can
      balloon to hundreds of MB on dense scenarios.
    * Answer-side coordinates: ``expression_clarity``,
      ``semantic_narrative_summary``, stage/substage segmentation
      notes. These belong in sidecars, not in release meta.
    * ``instance_summary.semantic_readiness`` (nested) -- story gaps
      echo answer coordinates.
    """
    keep = {
        "scenario_id": meta.get("scenario_id"),
        "chain_id": meta.get("chain_id"),
        "backbone_ref": meta.get("backbone_ref"),
        "time_span": meta.get("time_span"),
        "instance_summary": _strip_semantic_readiness(meta.get("instance_summary")),
        "necessary_context_config": meta.get("necessary_context_config"),
        "applog_writeback_stats": meta.get("applog_writeback_stats"),
        "applog_evidence_alignment_stats": meta.get(
            "applog_evidence_alignment_stats"
        ),
        "backbone_broad_warning": meta.get("backbone_broad_warning"),
    }
    return {k: v for k, v in keep.items() if v is not None}


def _strip_semantic_readiness(obj: Any) -> Any:
    """Return a copy of ``obj`` with ``semantic_readiness`` removed."""
    if not isinstance(obj, dict):
        return obj
    out = dict(obj)
    out.pop("semantic_readiness", None)
    return out


def _build_main_sample_meta(
    meta: dict[str, Any],
    scenario_id: str,
    chain_dir: Path,
    release_paths: dict[str, str],
    main_sample: dict[str, Any],
) -> dict[str, Any]:
    filtered = _select_meta_fields(meta)
    filtered["schema_version"] = MAIN_SAMPLE_META_SCHEMA_VERSION
    filtered["scenario_id"] = scenario_id
    filtered["source_chain_dir"] = str(chain_dir)
    filtered["sidecar_registry"] = {
        "narrative_roles_v0": release_paths["narrative_roles"],
        "stage_labels_v0": release_paths["stage_labels"],
        "legacy_stage_segments_v0": release_paths["legacy_stage_segments"],
    }
    # The flag is a self-describing observation of the just-built main
    # sample: it should reflect what actually lives under
    # ``spine[*].multisource_context`` rather than relying on an
    # upstream meta counter that may lag (or never populate, as seen
    # under the slim baseline). We walk the built spine and mark each
    # channel as populated iff at least one spine edge carries a
    # non-empty list.
    filtered["multisource_context_populated"] = (
        _derive_multisource_context_populated(main_sample)
    )
    return filtered


def _derive_multisource_context_populated(
    main_sample: dict[str, Any],
) -> dict[str, bool]:
    """Return ``{"applog": bool, "traffic": bool}`` by scanning the
    just-built ``main_sample.spine[*].multisource_context``.

    True iff at least one spine edge has a non-empty list for the
    channel. This matches the downstream consumer's intuition: "is
    there any applog/traffic actually attached on this scenario's
    release main_sample?".
    """
    applog_has = False
    traffic_has = False
    for edge in main_sample.get("spine") or []:
        mc = edge.get("multisource_context") or {}
        if not applog_has and mc.get("applog"):
            applog_has = True
        if not traffic_has and mc.get("traffic"):
            traffic_has = True
        if applog_has and traffic_has:
            break
    return {"applog": applog_has, "traffic": traffic_has}


# ---------------------------------------------------------------------------
# narrative_roles.v0.json builder (self-contained computation)
# ---------------------------------------------------------------------------

def _edge_is_malicious(edge: dict[str, Any]) -> bool:
    return bool((edge.get("attrs") or {}).get("malicious", False))


def _compute_narrative_roles(
    backbone: dict[str, Any],
) -> dict[str, Any]:
    """Derive per-edge narrative roles from backbone edge_sequence.

    Preferred source: ``chain_summary.narrative_roles.annotated_edges``
    (present on backbones produced by the post-patch ``derive_backbone_chain``).

    Fallback source (for backbones generated before the patch): compute
    the same set of roles from ``expression_clarity`` +
    ``preparation_shell_trial.kept_edge_ids`` using structural rules
    matching ``_annotate_backbone_narrative_roles``.
    """
    edge_sequence: list[dict[str, Any]] = list(
        backbone.get("edge_sequence") or []
    )
    chain_summary = backbone.get("chain_summary") or {}
    expression_clarity = chain_summary.get("expression_clarity") or {}
    prep_stats = chain_summary.get("preparation_shell_trial") or {}

    roles: list[dict[str, Any]] = []
    anchors: dict[str, Any] = {
        "entry_anchor": None,
        "result_anchor": None,
        "handoff_exec": None,
        "result_tail_context": None,
    }
    role_sources_used = Counter()

    edge_by_id: dict[str, dict[str, Any]] = {
        str(e.get("edge_id") or ""): e for e in edge_sequence
    }

    def _add_role(
        edge: Optional[dict[str, Any]],
        role: str,
        role_source: str,
    ) -> Optional[dict[str, Any]]:
        if edge is None:
            return None
        eid = str(edge.get("edge_id") or "")
        if not eid:
            return None
        # Deduplicate: if same edge already has this role as primary, skip.
        for existing in roles:
            if existing["edge_id"] == eid and existing["role"] == role:
                return existing
        entry = {
            "edge_id": eid,
            "seq": int(edge.get("seq") or 0),
            "relation": str(edge.get("relation") or ""),
            "evt_num": (
                int((edge.get("attrs") or {}).get("evt_num"))
                if (edge.get("attrs") or {}).get("evt_num") is not None
                else None
            ),
            "subject": str(edge.get("subject") or ""),
            "object": str(edge.get("object") or ""),
            "malicious": _edge_is_malicious(edge),
            "role": role,
            "role_alt": [],
            "role_source": role_source,
            "confidence_tier": ROLE_SOURCE_TO_TIER.get(role_source, "low"),
        }
        roles.append(entry)
        role_sources_used[role_source] += 1
        return entry

    # -------- Preferred path: prebuilt annotated_edges --------
    prebuilt = (chain_summary.get("narrative_roles") or {}).get("annotated_edges")
    if isinstance(prebuilt, list) and prebuilt:
        for row in prebuilt:
            role = str(row.get("role") or "")
            eid = str(row.get("edge_id") or "")
            if not eid or role not in NARRATIVE_ROLE_VOCABULARY:
                continue
            edge = edge_by_id.get(eid)
            if edge is None:
                continue
            src = _classify_role_source_from_prebuilt(role, prep_stats)
            _add_role(edge, role, src)

    # -------- Fallback path: compute from scratch when needed --------
    if not roles:
        # 1) Preparation-side (Trial D) via kept_edge_ids.
        kept_ids = [
            str(x)
            for x in (prep_stats.get("kept_edge_ids") or [])
            if str(x)
        ]
        prep_edges = [edge_by_id.get(eid) for eid in kept_ids]
        prep_edges = [e for e in prep_edges if e is not None]
        if prep_edges:
            # Sort by seq to get deterministic boundary assignment.
            prep_edges.sort(key=lambda e: int(e.get("seq") or 0))
            _add_role(
                prep_edges[0],
                "preparation_boundary_start",
                "trial_d.kept_edge_ids_fallback.preparation_boundary_start",
            )
            if len(prep_edges) >= 2:
                _add_role(
                    prep_edges[-1],
                    "preparation_boundary_end",
                    "trial_d.kept_edge_ids_fallback.preparation_boundary_end",
                )
            for mid_edge in prep_edges[1:-1]:
                _add_role(
                    mid_edge,
                    "mid_span_representative",
                    "trial_d.kept_edge_ids_fallback.mid_span_representative",
                )
        # Also honour the explicit handoff_exec_edge_id if the post-patch
        # block is present (harmless when absent).
        handoff_eid = prep_stats.get("handoff_exec_edge_id")
        if isinstance(handoff_eid, str) and handoff_eid:
            _add_role(
                edge_by_id.get(handoff_eid),
                "startup_handoff_exec",
                "trial_d.kept_anchor_roles.startup_handoff_exec",
            )

        # 2) Entry / result anchors from malicious seq boundaries.
        first_seq = expression_clarity.get("first_malicious_seq")
        last_seq = expression_clarity.get("last_malicious_seq")
        entry_edge = (
            edge_sequence[first_seq - 1]
            if isinstance(first_seq, int) and 1 <= first_seq <= len(edge_sequence)
            else None
        )
        result_edge = (
            edge_sequence[last_seq - 1]
            if isinstance(last_seq, int) and 1 <= last_seq <= len(edge_sequence)
            else None
        )
        if result_edge is not None:
            _add_role(result_edge, "result_anchor", "last_malicious_edge")
        if entry_edge is not None and entry_edge is not result_edge:
            _add_role(entry_edge, "semantic_entry_anchor", "first_malicious_edge")
        elif entry_edge is not None and entry_edge is result_edge:
            # Single malicious edge: record entry as alt on result_anchor.
            for existing in roles:
                if existing["edge_id"] == str(entry_edge.get("edge_id") or ""):
                    if "semantic_entry_anchor" not in existing["role_alt"]:
                        existing["role_alt"].append("semantic_entry_anchor")
                    break

        # 3) result_tail_context: first non-malicious same-subject
        #    result-like edge within seq window after result_anchor.
        if result_edge is not None:
            anchor_subj = str(result_edge.get("subject") or "")
            anchor_seq = int(result_edge.get("seq") or 0)
            limit = anchor_seq + NARRATIVE_RESULT_TAIL_SEQ_WINDOW
            for candidate in edge_sequence[anchor_seq:]:
                cseq = int(candidate.get("seq") or 0)
                if cseq <= anchor_seq:
                    continue
                if cseq > limit:
                    break
                if _edge_is_malicious(candidate):
                    continue
                rel = str(candidate.get("relation") or "").upper()
                if rel not in BACKBONE_RESULT_RELATIONS:
                    continue
                if str(candidate.get("subject") or "") != anchor_subj:
                    continue
                _add_role(
                    candidate,
                    "result_tail_context",
                    "subject_same_result_tail_window",
                )
                break

    # ---- Fill anchors block (regardless of which path produced roles) ----
    for r in roles:
        if r["role"] == "semantic_entry_anchor":
            anchors["entry_anchor"] = _anchor_view(r)
        elif r["role"] == "result_anchor":
            anchors["result_anchor"] = _anchor_view(r)
            # If the single-edge-attack alt exists, surface it too.
            if "semantic_entry_anchor" in (r.get("role_alt") or []):
                anchors["entry_anchor"] = _anchor_view(r)
        elif r["role"] == "startup_handoff_exec":
            anchors["handoff_exec"] = _anchor_view(r)
        elif r["role"] == "result_tail_context":
            anchors["result_tail_context"] = _anchor_view(r)

    # Degenerate anchor cases (no malicious edges etc.) are expressed by
    # leaving ``anchors.*`` as None and surfacing the reason.
    result_tail_reason = (
        "matched" if anchors["result_tail_context"] is not None
        else ("no_matching_tail_edge_in_window"
              if anchors["result_anchor"] is not None
              else "no_result_anchor")
    )

    role_counts = Counter(r["role"] for r in roles)
    roles_any: set[str] = set(role_counts.keys())
    for r in roles:
        for alt in r.get("role_alt") or []:
            roles_any.add(alt)

    story_phase_coverage = {
        "preparation": any(
            r["role"] in (
                "preparation_boundary_start",
                "preparation_boundary_end",
                "mid_span_representative",
                "entry_bridge_pre",
            )
            for r in roles
        ),
        "handoff": "startup_handoff_exec" in roles_any,
        "execution_entry": "semantic_entry_anchor" in roles_any,
        "result": "result_anchor" in roles_any,
    }

    return {
        "vocabulary": list(NARRATIVE_ROLE_VOCABULARY),
        "result_tail_seq_window": NARRATIVE_RESULT_TAIL_SEQ_WINDOW,
        "anchors": anchors,
        "result_tail_reason": result_tail_reason,
        "roles": sorted(roles, key=lambda r: (r["seq"], r["role"])),
        "role_counts": dict(sorted(role_counts.items())),
        "roles_present": sorted(roles_any),
        "story_phase_coverage": story_phase_coverage,
        "role_source_counts": dict(sorted(role_sources_used.items())),
        "computed_from": (
            "backbone.chain_summary.narrative_roles.annotated_edges"
            if prebuilt else "release_exporter_fallback_rules"
        ),
    }


def _classify_role_source_from_prebuilt(
    role: str,
    prep_stats: dict[str, Any],
) -> str:
    """Map a pre-built role to its role_source label.

    Rule set matches ``_annotate_backbone_narrative_roles``:
      * semantic_entry_anchor -> first_malicious_edge
      * result_anchor         -> last_malicious_edge
      * result_tail_context   -> subject_same_result_tail_window
      * all others come from Trial D's kept_anchor_roles.
    """
    if role == "semantic_entry_anchor":
        return "first_malicious_edge"
    if role == "result_anchor":
        return "last_malicious_edge"
    if role == "result_tail_context":
        return "subject_same_result_tail_window"
    return f"trial_d.kept_anchor_roles.{role}"


def _anchor_view(role_entry: dict[str, Any]) -> dict[str, Any]:
    return {
        "edge_id": role_entry["edge_id"],
        "seq": role_entry["seq"],
        "relation": role_entry["relation"],
        "evt_num": role_entry.get("evt_num"),
    }


def _build_narrative_roles_sidecar(
    backbone: dict[str, Any],
    scenario_id: str,
    chain_id: Optional[str],
) -> dict[str, Any]:
    computed = _compute_narrative_roles(backbone)
    return {
        "schema_version": NARRATIVE_ROLES_SCHEMA_VERSION,
        "scenario_id": scenario_id,
        "chain_id": chain_id,
        "produced_by": "results_analysis.release.build_dataset_release_v1",
        **computed,
    }


# ---------------------------------------------------------------------------
# stage_labels.v0.json builder
# ---------------------------------------------------------------------------

def _build_edge_id_by_seq(spine_or_backbone: list[dict[str, Any]]) -> dict[int, str]:
    out: dict[int, str] = {}
    for edge in spine_or_backbone:
        try:
            seq = int(edge.get("seq"))
        except (TypeError, ValueError):
            continue
        eid = str(edge.get("edge_id") or "")
        if eid:
            out[seq] = eid
    return out


def _parse_proc_subject(subject: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    """Return (container_id, exe_path) parsed from a ``proc:...`` subject.

    Subjects in the release have the shape
    ``proc:<container_id>:<pid>:<exe_path>``. ``exe_path`` may contain
    ``:`` so we split with a bounded maxsplit. Non-``proc:`` subjects
    (or anything that fails the shape) yield ``(None, None)`` and the
    caller falls back to the strict equality check.
    """
    if not isinstance(subject, str) or not subject.startswith("proc:"):
        return (None, None)
    parts = subject.split(":", 3)
    if len(parts) < 4:
        return (None, None)
    return (parts[1] or None, parts[3] or None)


def _classify_subject_match(
    edge_subject: Optional[str],
    anchor_subject: Optional[str],
    anchor_ctnr: Optional[str],
    anchor_exe: Optional[str],
) -> Optional[str]:
    """Return the match kind for a subject continuation test.

    One of: ``"exact"``, ``"same_exe_in_container"``, or ``None``.
    ``None`` means the walker / preparation fallback MUST stop: subject
    continuity is broken. Cross-container matches are never accepted
    and neither are cross-binary matches. This is the single place
    where the v0.4.3 subject relaxation is decided.
    """
    if anchor_subject is None:
        return None
    if edge_subject == anchor_subject:
        return "exact"
    if anchor_ctnr is None or anchor_exe is None:
        return None
    e_ctnr, e_exe = _parse_proc_subject(edge_subject)
    if e_ctnr is None or e_exe is None:
        return None
    if e_ctnr == anchor_ctnr and e_exe == anchor_exe:
        return "same_exe_in_container"
    return None


def _edge_has_context(edge: dict[str, Any]) -> bool:
    multisource = edge.get("multisource_context") or {}
    return bool(multisource.get("applog") or multisource.get("traffic"))


def _edge_has_response_artifact(edge: dict[str, Any]) -> bool:
    multisource = edge.get("multisource_context") or {}
    for traffic in multisource.get("traffic") or []:
        if not isinstance(traffic, dict):
            continue
        if (
            traffic.get("status") is not None
            or traffic.get("status_code") is not None
            or traffic.get("response_status") is not None
        ):
            return True
    for applog in multisource.get("applog") or []:
        if not isinstance(applog, dict):
            continue
        message = str(
            applog.get("message")
            or applog.get("normalized_message")
            or ""
        ).upper()
        if any(
            token in message
            for token in (
                " LOGIN ",
                " SESSION ",
                " TOKEN ",
                " SUCCESS",
                " CREATED",
                " UPDATED",
                " BALANCE",
                " IMPORT",
                " CONFIG",
                " WRITE ",
                " UPLOAD",
            )
        ):
            return True
    return False


def _result_edge_has_self_evidence(edge: dict[str, Any]) -> bool:
    rel = str(edge.get("relation") or "").upper()
    if rel in BACKBONE_RESULT_RELATIONS:
        return True
    if rel in STAGE_RESULT_TIER_B_RELATIONS:
        return False
    return _edge_has_response_artifact(edge)


def _prep_edge_has_self_evidence(edge: dict[str, Any]) -> bool:
    rel = str(edge.get("relation") or "").upper()
    if rel in {"NET_CONNECT", "NET_RECV", "NET_SEND", "PROCESS_EXEC"}:
        return True
    if rel in {"PROCESS_FORK", "PROCESS_CLONE", "NET_ACCEPT"}:
        return _edge_has_context(edge)
    return _edge_has_context(edge)


def _gap_edge_explainable_as_entry_bridge(
    edge: dict[str, Any],
    entry_container_id: Optional[str],
) -> bool:
    rel = str(edge.get("relation") or "").upper()
    if rel not in {"NET_CONNECT", "NET_SEND", "NET_RECV", "PROCESS_EXEC"}:
        return False
    gap_ctnr, _ = _parse_proc_subject(str(edge.get("subject") or ""))
    return bool(entry_container_id and gap_ctnr and gap_ctnr == entry_container_id)


def _prep_rule_family(rule_used: str) -> str:
    if rule_used == "prep_end_marker_latest":
        return "marker_based"
    if rule_used.startswith("inferred_prep_pre_entry_same_subject_window"):
        return "same_subject_window"
    if rule_used.startswith("inferred_prep_pre_entry_same_exe_in_container_window"):
        return "same_exe_in_container"
    if rule_used == "no_prep_end_marker_preparation_empty":
        return "preparation_empty"
    return "unknown"


def _is_stage_derivation_v0_4_5_family(rule_version: str) -> bool:
    return rule_version == "stage_derivation_v0.4.5"


def _build_stage_labels_sidecar(
    main_sample: dict[str, Any],
    narrative_roles: dict[str, Any],
    scenario_id: str,
    chain_id: Optional[str],
    *,
    rule_version: str = "stage_derivation_v0.4.5",
) -> dict[str, Any]:
    """Derive stage labels from the main_sample spine.

    Preparation uses structural tail markers from ``narrative_roles``.
    Execution covers the span between preparation and result boundaries.
    Result is anchored on ``result_anchor`` and extends while local structural
    continuity holds (same subject and a relation in
    ``BACKBONE_RESULT_RELATIONS``), with ``result_tail_context`` as a seed.
    The span stops at a subject switch, a non-result relation, or the spine
    boundary. Regions outside the concrete spans are labeled
    ``stage_unclosed``. Projection and statistics are derived from the final
    spans.
    """
    spine = list(main_sample.get("spine") or [])
    n = len(spine)
    eid_by_seq: dict[int, str] = {}
    seq_by_eid: dict[str, int] = {}
    for entry in spine:
        try:
            seq = int(entry.get("seq"))
        except (TypeError, ValueError):
            continue
        eid = entry.get("edge_id")
        if isinstance(eid, str) and eid:
            eid_by_seq[seq] = eid
            seq_by_eid[eid] = seq

    # first / last malicious seq computed directly from spine.
    first_mal_seq: Optional[int] = None
    last_mal_seq: Optional[int] = None
    for entry in spine:
        try:
            seq = int(entry.get("seq"))
        except (TypeError, ValueError):
            continue
        is_mal = bool((entry.get("attrs") or {}).get("malicious", False))
        if is_mal:
            if first_mal_seq is None:
                first_mal_seq = seq
            last_mal_seq = seq

    # Map narrative_role result_tail_context (backbone seq space) onto
    # spine seq space by edge_id. Ignored when the edge_id isn't present
    # in main_sample.
    result_tail = (narrative_roles.get("anchors") or {}).get("result_tail_context")
    result_tail_seq: Optional[int] = None
    result_tail_edge_id: Optional[str] = None
    if result_tail and isinstance(result_tail.get("edge_id"), str):
        result_tail_edge_id = result_tail["edge_id"]
        tail_seq = seq_by_eid.get(result_tail_edge_id)
        if isinstance(tail_seq, int):
            result_tail_seq = tail_seq

    # Resolve anchor subject from spine (not from narrative_roles which
    # carries the backbone-side subject string; both should match since
    # edge_id is the same, but we trust spine as the release's source
    # of truth).
    result_anchor_obj = (narrative_roles.get("anchors") or {}).get("result_anchor")
    result_anchor_edge_id: Optional[str] = None
    anchor_subject: Optional[str] = None
    if result_anchor_obj and isinstance(result_anchor_obj.get("edge_id"), str):
        result_anchor_edge_id = result_anchor_obj["edge_id"]
    anchor_seq_for_subj = seq_by_eid.get(result_anchor_edge_id or "") or last_mal_seq
    if isinstance(anchor_seq_for_subj, int) and 1 <= anchor_seq_for_subj <= n:
        anchor_subject = str(
            spine[anchor_seq_for_subj - 1].get("subject") or ""
        ) or None

    # ---- preparation-start rule (v0.3) ----
    # prep_end markers denote "server setup has just finished; attack
    # is about to happen". Using the LATEST such marker (max) keeps the
    # preparation window tight -- typically 1-7 edges on D-triggering
    # scenarios -- so pre-attack server runtime is not mis-labeled
    # as preparation.
    PREP_END_MARKER_ROLES = {
        "preparation_boundary_end",
        "startup_handoff_exec",
        "entry_bridge_pre",
    }
    prep_end_candidate_seqs: list[int] = []
    prep_end_candidate_edges: list[dict[str, Any]] = []
    if isinstance(first_mal_seq, int):
        for role_entry in narrative_roles.get("roles") or []:
            role_name = str(role_entry.get("role") or "")
            if role_name not in PREP_END_MARKER_ROLES:
                continue
            eid = str(role_entry.get("edge_id") or "")
            sseq = seq_by_eid.get(eid)
            if sseq is None:
                continue
            if sseq >= first_mal_seq:
                continue
            prep_end_candidate_seqs.append(sseq)
            prep_end_candidate_edges.append({
                "edge_id": eid,
                "role": role_name,
                "spine_seq": sseq,
            })

    prep_start_seq: Optional[int] = None
    prep_rule_used: str
    prep_inferred_walked_seqs: list[int] = []
    prep_inferred_used_exe_relaxation: bool = False
    # v0.4.4: gap tolerance is computed only inside the inferred
    # fallback. Initialise upfront so the sidecar fields exist on
    # every branch (including prep_end_marker_latest and the
    # preparation-empty branch).
    prep_inferred_used_gap_tolerance: bool = False
    prep_inferred_gap_seq: Optional[int] = None
    entry_subject: str = ""
    entry_ctnr: Optional[str] = None
    entry_exe: Optional[str] = None
    if prep_end_candidate_seqs:
        prep_start_seq = max(prep_end_candidate_seqs)
        prep_rule_used = "prep_end_marker_latest"
    else:
        # v0.4.2 fallback: if narrative_roles gave us no structural
        # prep-end marker, try a tight same-subject walk backward from
        # the entry edge. Picks up the attacker subject's immediate
        # setup activity (e.g. accept / fork / connect on the same
        # process) without claiming long runtime tails. Capped at
        # STAGE_PREP_INFERRED_K to stay conservative.
        #
        # v0.4.3 extension: if the strict same-subject walker admits
        # zero edges (apache worker-fork layout: entry is one worker
        # pid, pre-entry is another worker pid inside the same
        # container with the same exe_path), fall through to a
        # same-exe-in-container walker with a tighter cap
        # (STAGE_PREP_INFERRED_K_EXE_RELAXED). Cross-container or
        # cross-binary pre-entry edges are still never accepted.
        #
        # v0.4.4 extension: both pre-entry walks tolerate at most one
        # non-matching edge (single-gap) within the window, provided
        # the gap is immediately preceded by at least one accepted
        # match (i.e. the gap bridges two runs of the attacker
        # process/family, e.g. an interleaved outbound-connect by an
        # adjacent shell on the attacker's boot sequence -- see
        # sandworm / joomla/CVE-2023-23752). The gap edge itself is
        # absorbed into the resulting preparation span so the span
        # stays contiguous; the skipped seq is recorded in
        # ``prep_inferred_gap_seq`` for auditability. Caps
        # (STAGE_PREP_INFERRED_K / STAGE_PREP_INFERRED_K_EXE_RELAXED)
        # are unchanged and count only accepted matches (the gap
        # does not consume cap budget). A malicious edge always stops
        # the walk immediately and is never treated as a gap.
        if (
            isinstance(first_mal_seq, int)
            and first_mal_seq > 1
            and 1 <= first_mal_seq <= n
        ):
            entry_edge = spine[first_mal_seq - 1]
            entry_subject = str(entry_edge.get("subject") or "")
            entry_ctnr, entry_exe = _parse_proc_subject(entry_subject)
            if entry_subject:
                walked = 0
                cursor = first_mal_seq - 1
                strict_gap_seq: Optional[int] = None
                gap_used = False
                while cursor >= 1 and walked < STAGE_PREP_INFERRED_K:
                    edge = spine[cursor - 1]
                    subj = str(edge.get("subject") or "")
                    is_mal = bool(
                        (edge.get("attrs") or {}).get("malicious", False)
                    )
                    if is_mal:
                        break
                    if subj == entry_subject:
                        prep_inferred_walked_seqs.append(cursor)
                        walked += 1
                    else:
                        if gap_used:
                            break
                        gap_used = True
                        strict_gap_seq = cursor
                    cursor -= 1
                # Keep the gap only if something was accepted AFTER
                # it (i.e. the skipped seq sits between matches).
                if (
                    strict_gap_seq is not None
                    and any(s < strict_gap_seq for s in prep_inferred_walked_seqs)
                ):
                    prep_inferred_gap_seq = strict_gap_seq
                    prep_inferred_used_gap_tolerance = True
        if prep_inferred_walked_seqs:
            if prep_inferred_used_gap_tolerance:
                # Absorb the gap edge into the contiguous prep span.
                prep_start_seq = min(
                    min(prep_inferred_walked_seqs),
                    prep_inferred_gap_seq or (first_mal_seq - 1),
                )
                prep_rule_used = (
                    "inferred_prep_pre_entry_same_subject_window_gap_tolerant"
                )
            else:
                prep_start_seq = min(prep_inferred_walked_seqs)
                prep_rule_used = "inferred_prep_pre_entry_same_subject_window"
        elif (
            isinstance(first_mal_seq, int)
            and first_mal_seq > 1
            and 1 <= first_mal_seq <= n
            and entry_ctnr is not None
            and entry_exe is not None
        ):
            walked = 0
            cursor = first_mal_seq - 1
            relaxed_seqs: list[int] = []
            relaxed_gap_seq: Optional[int] = None
            gap_used = False
            while cursor >= 1 and walked < STAGE_PREP_INFERRED_K_EXE_RELAXED:
                edge = spine[cursor - 1]
                subj = str(edge.get("subject") or "")
                is_mal = bool(
                    (edge.get("attrs") or {}).get("malicious", False)
                )
                if is_mal:
                    break
                match_kind = _classify_subject_match(
                    subj, entry_subject, entry_ctnr, entry_exe
                )
                if match_kind is not None:
                    relaxed_seqs.append(cursor)
                    walked += 1
                else:
                    if gap_used:
                        break
                    gap_used = True
                    relaxed_gap_seq = cursor
                cursor -= 1
            # Keep the gap only if something was accepted AFTER it.
            gap_useful = (
                relaxed_gap_seq is not None
                and any(s < relaxed_gap_seq for s in relaxed_seqs)
            )
            if relaxed_seqs:
                prep_inferred_walked_seqs = relaxed_seqs
                if gap_useful:
                    prep_inferred_gap_seq = relaxed_gap_seq
                    prep_inferred_used_gap_tolerance = True
                    prep_start_seq = min(
                        min(relaxed_seqs),
                        relaxed_gap_seq or (first_mal_seq - 1),
                    )
                    prep_rule_used = (
                        "inferred_prep_pre_entry_same_exe_in_container_window"
                        "_gap_tolerant"
                    )
                else:
                    prep_start_seq = min(relaxed_seqs)
                    prep_rule_used = "inferred_prep_pre_entry_same_exe_in_container_window"
                prep_inferred_used_exe_relaxation = True
            else:
                prep_rule_used = "no_prep_end_marker_preparation_empty"
        else:
            prep_rule_used = "no_prep_end_marker_preparation_empty"

    prep_rule_family = _prep_rule_family(prep_rule_used)
    prep_entry_self_evidence_in_window = False
    prep_gap_explainable_as_entry_bridge: Optional[bool] = None
    prep_demoted_reasons: list[str] = []
    prep_demoted_to_stage_unclosed = False
    if (
        isinstance(prep_start_seq, int)
        and isinstance(first_mal_seq, int)
        and prep_start_seq < first_mal_seq
    ):
        prep_edges = spine[prep_start_seq - 1:first_mal_seq - 1]
        prep_entry_self_evidence_in_window = any(
            _prep_edge_has_self_evidence(edge) for edge in prep_edges
        )
        if (
            isinstance(prep_inferred_gap_seq, int)
            and 1 <= prep_inferred_gap_seq <= n
        ):
            prep_gap_explainable_as_entry_bridge = (
                _gap_edge_explainable_as_entry_bridge(
                    spine[prep_inferred_gap_seq - 1],
                    entry_ctnr,
                )
            )

    if _is_stage_derivation_v0_4_5_family(rule_version):
        if (
            prep_rule_used.endswith("_gap_tolerant")
            and prep_start_seq is not None
        ):
            if prep_gap_explainable_as_entry_bridge is not True:
                prep_demoted_to_stage_unclosed = True
                prep_demoted_reasons.append("demoted_prep_gap_tolerant")
                if not prep_entry_self_evidence_in_window:
                    prep_demoted_reasons.append("no_pre_entry_self_evidence")
        elif prep_rule_family == "same_exe_in_container":
            near_first_mal = bool(
                isinstance(prep_start_seq, int)
                and isinstance(first_mal_seq, int)
                and (first_mal_seq - prep_start_seq)
                <= STAGE_PREP_INFERRED_K_EXE_RELAXED
            )
            if not near_first_mal or not prep_entry_self_evidence_in_window:
                prep_demoted_to_stage_unclosed = True
                prep_demoted_reasons.append(
                    "demoted_prep_same_exe_background"
                )
                if not prep_entry_self_evidence_in_window:
                    prep_demoted_reasons.append(
                        "no_pre_entry_self_evidence"
                    )

    # ---- result span rule (v0.4) ---------------------------------------
    # Anchor + local structural continuity + explicit stop, replacing
    # the v0.3 length-K window. Walker starts at last_mal_seq + 1 and
    # extends forward while:
    #   1. edge.subject == anchor_subject, AND
    #   2. edge.relation is in BACKBONE_RESULT_RELATIONS OR the edge is
    #      the narrative_roles.anchors.result_tail_context seed.
    # Any violation stops the walker. Result may legitimately be empty
    # when the attack effect collapses into last_mal and nothing
    # observable follows.
    result_end_seq: Optional[int] = None
    result_start_seq: Optional[int] = None
    result_rule_used: str = "no_result_anchor_no_result"
    result_stop_reason: str = "no_result_anchor"
    result_walk_accepted: list[dict[str, Any]] = []
    # v0.4.1 H1 patch: when the result_anchor resolves to the very last
    # spine edge (last_mal_seq == n), the v0.4 walker never runs because
    # its gate requires last_mal_seq < n. That leaves stage_labels with
    # no `result` span even though narrative_roles carries a real
    # result_anchor. This branch recognises exactly that case and emits
    # a single-edge result on the anchor itself, peeled off the tail of
    # execution. The rest of the result rule (walker-based) is untouched.
    result_anchor_at_tail = (
        isinstance(last_mal_seq, int)
        and isinstance(first_mal_seq, int)
        and last_mal_seq == n
        and first_mal_seq < last_mal_seq
        and result_anchor_edge_id is not None
        and seq_by_eid.get(result_anchor_edge_id) == last_mal_seq
    )
    tier_b_accepted_count = 0
    tier_b_cap_hit = False
    walker_used_exe_relaxation = False
    anchor_ctnr, anchor_exe = _parse_proc_subject(anchor_subject)
    if (
        isinstance(last_mal_seq, int)
        and last_mal_seq < n
        and anchor_subject is not None
    ):
        cursor = last_mal_seq + 1
        stopped = False
        while cursor <= n:
            edge = spine[cursor - 1]
            rel = str(edge.get("relation") or "").upper()
            subj = str(edge.get("subject") or "")
            eid = str(edge.get("edge_id") or "")
            is_tail_seed = bool(
                result_tail_edge_id is not None and eid == result_tail_edge_id
            )
            # Stop condition 1: subject continuity broken. v0.4.3
            # allows a same-container + same-exe match (worker-fork
            # continuation) in addition to strict subject equality.
            match_kind = _classify_subject_match(
                subj, anchor_subject, anchor_ctnr, anchor_exe
            )
            if match_kind is None:
                result_stop_reason = "subject_switch_from_anchor"
                stopped = True
                break
            subject_relaxed = match_kind == "same_exe_in_container"
            if subject_relaxed:
                walker_used_exe_relaxation = True
            # v0.4.2 tier classification for the current edge.
            is_tier_a = rel in BACKBONE_RESULT_RELATIONS
            is_tier_b = rel in STAGE_RESULT_TIER_B_RELATIONS
            if not is_tier_a and not is_tail_seed and is_tier_b:
                # Tier-B edge: accept only while under cap. When the
                # cap is reached we stop the walker with an explicit
                # reason so the cap is auditable in the sidecar.
                if tier_b_accepted_count >= STAGE_RESULT_TIER_B_CAP:
                    tier_b_cap_hit = True
                    result_stop_reason = "tier_b_cap_reached"
                    stopped = True
                    break
                accepted_as = (
                    "post_result_shell_same_exe_in_container"
                    if subject_relaxed
                    else "post_result_shell_same_subject"
                )
                tier_b_accepted_count += 1
            elif is_tier_a:
                accepted_as = (
                    "result_like_same_exe_in_container"
                    if subject_relaxed
                    else "result_like_same_subject"
                )
            elif is_tail_seed:
                accepted_as = "tail_context_seed"
            else:
                # Stop condition 2: unclassifiable relation (not tier-A,
                # not tail seed, not tier-B).
                result_stop_reason = (
                    "non_result_like_relation_without_tail_seed"
                )
                stopped = True
                break
            # Accept edge into result.
            result_end_seq = cursor
            if result_start_seq is None:
                result_start_seq = cursor
            result_walk_accepted.append({
                "seq": cursor,
                "edge_id": eid,
                "relation": rel,
                "accepted_as": accepted_as,
            })
            cursor += 1
        if not stopped and result_end_seq is not None:
            result_stop_reason = "reached_spine_end"
        if result_end_seq is None:
            # Walker produced 0 edges: result is empty.
            result_rule_used = "anchor_continuity_walker_empty"
        elif tier_b_accepted_count > 0:
            # Walker had to rely on tier-B (post-result shell) at least
            # once. Surface that explicitly so the consumer can bucket
            # these scenarios separately from pure tier-A walks.
            result_rule_used = "anchor_continuity_walker_tier_b_extended"
        elif walker_used_exe_relaxation:
            # Tier-A walker but had to use the v0.4.3 same-exe-in-
            # container subject relaxation at least once. Kept as a
            # separate bucket so consumers can distinguish from pure
            # strict-subject tier-A walks.
            result_rule_used = "anchor_continuity_walker_exe_relaxation"
        else:
            result_rule_used = "anchor_continuity_walker"
    elif result_anchor_at_tail:
        # v0.4.1 H1: single-edge result on the tail anchor.
        result_start_seq = last_mal_seq
        result_end_seq = last_mal_seq
        result_rule_used = "anchor_at_spine_tail_single_edge_result"
        result_stop_reason = "anchor_at_spine_tail"
        tail_edge = spine[last_mal_seq - 1]
        result_walk_accepted.append({
            "seq": last_mal_seq,
            "edge_id": str(tail_edge.get("edge_id") or ""),
            "relation": str(tail_edge.get("relation") or "").upper(),
            "accepted_as": "anchor_at_spine_tail",
        })
    elif anchor_subject is None:
        result_rule_used = "no_anchor_subject_no_result"
        result_stop_reason = "no_anchor_subject"

    result_anchor_in_window: Optional[bool] = None
    result_self_evidence_in_window = False
    result_tier_b_only_candidate = False
    result_demoted_reasons: list[str] = []
    result_demoted_to_stage_unclosed = False
    if (
        isinstance(result_start_seq, int)
        and isinstance(result_end_seq, int)
        and 1 <= result_start_seq <= result_end_seq <= n
    ):
        anchor_seq = seq_by_eid.get(result_anchor_edge_id or "")
        if isinstance(anchor_seq, int):
            result_anchor_in_window = bool(
                result_start_seq <= anchor_seq <= result_end_seq
            )
        result_edges = spine[result_start_seq - 1:result_end_seq]
        result_self_evidence_in_window = any(
            _result_edge_has_self_evidence(edge) for edge in result_edges
        )
        rels = {
            str(edge.get("relation") or "").upper()
            for edge in result_edges
        }
        result_tier_b_only_candidate = bool(
            result_edges and rels and rels.issubset(STAGE_RESULT_TIER_B_RELATIONS)
        )

    if _is_stage_derivation_v0_4_5_family(rule_version):
        if result_tier_b_only_candidate:
            result_demoted_reasons.append("demoted_result_tier_b_only")
        if result_anchor_in_window is False:
            result_demoted_reasons.append("result_anchor_out_of_window")
        if (
            isinstance(result_start_seq, int)
            and isinstance(result_end_seq, int)
            and not result_self_evidence_in_window
        ):
            result_demoted_reasons.append("no_result_self_evidence_in_window")
        if (
            result_rule_used != "anchor_at_spine_tail_single_edge_result"
            and isinstance(result_start_seq, int)
            and isinstance(result_end_seq, int)
            and not (
                result_anchor_in_window is True
                or result_self_evidence_in_window
            )
        ):
            result_demoted_to_stage_unclosed = True
        if (
            result_tier_b_only_candidate
            and result_anchor_in_window is not True
        ):
            result_demoted_to_stage_unclosed = True

    stage_spans: list[dict[str, Any]] = []

    def _span(stage: str, start: int, end: int) -> None:
        if start > end:
            return
        stage_spans.append({
            "stage": stage,
            "start_seq": start,
            "end_seq": end,
            "start_edge_id": eid_by_seq.get(start),
            "end_edge_id": eid_by_seq.get(end),
            "source": "derived",
        })

    if (
        isinstance(first_mal_seq, int)
        and isinstance(last_mal_seq, int)
        and 1 <= first_mal_seq <= last_mal_seq <= n
    ):
        # v0.3 rule: preparation begins at the LATEST prep-end marker
        # from narrative_roles (structural anchor), not at spine seq 1.
        if prep_start_seq is not None and prep_start_seq < first_mal_seq:
            # Pre-preparation runtime (server startup + background
            # request cycles that happened before the structural
            # "setup finished" marker) is stage_unclosed, not preparation.
            _span("stage_unclosed", 1, prep_start_seq - 1)
            if prep_demoted_to_stage_unclosed:
                _span("stage_unclosed", prep_start_seq, first_mal_seq - 1)
            else:
                _span("preparation", prep_start_seq, first_mal_seq - 1)
        else:
            # No structural prep-end marker: be honest. The whole
            # pre-attack window is stage_unclosed; preparation span is absent.
            _span("stage_unclosed", 1, first_mal_seq - 1)
        # v0.4.1 H1: when the result_anchor is the very last spine edge
        # (tail-anchor mode), peel it off execution and emit it as a
        # single-edge result span. All other modes behave exactly like
        # v0.4 (execution = [first_mal .. last_mal], result from walker).
        if (
            result_rule_used == "anchor_at_spine_tail_single_edge_result"
            and isinstance(result_start_seq, int)
            and result_start_seq == last_mal_seq
        ):
            _span("execution", first_mal_seq, last_mal_seq - 1)
            _span("result", last_mal_seq, last_mal_seq)
            # Tail anchor mode: result_end_seq == n, nothing after.
        else:
            # execution:   [first_mal_seq .. last_mal_seq]
            _span("execution", first_mal_seq, last_mal_seq)
            # result: v0.4 walker output. Span only if walker accepted
            # at least one edge; otherwise result is absent (honest).
            if isinstance(result_end_seq, int) and result_end_seq > last_mal_seq:
                if result_demoted_to_stage_unclosed:
                    _span("stage_unclosed", last_mal_seq + 1, result_end_seq)
                else:
                    _span("result", last_mal_seq + 1, result_end_seq)
                # post-result stage_unclosed
                _span("stage_unclosed", result_end_seq + 1, n)
            else:
                # No result span. Everything after last_mal is post-attack
                # runtime: labelled stage_unclosed.
                _span("stage_unclosed", last_mal_seq + 1, n)
    elif n > 0:
        _span("stage_unclosed", 1, n)

    # Edge-level projection (spans -> per-edge stage)
    projection: list[dict[str, Any]] = []
    stage_by_seq: dict[int, str] = {}
    for span in stage_spans:
        for seq in range(span["start_seq"], span["end_seq"] + 1):
            stage_by_seq[seq] = span["stage"]
    for seq in range(1, n + 1):
        projection.append({
            "edge_id": eid_by_seq.get(seq),
            "seq": seq,
            "stage": stage_by_seq.get(seq, "stage_unclosed"),
        })

    per_stage_counts = Counter(row["stage"] for row in projection)

    # ───────────────────────────────────────────────────────────────────
    # H3: compact span-only view (attack-stage spans only)
    # ───────────────────────────────────────────────────────────────────
    # Pure derived view over ``stage_spans``: keeps only the attack
    # stages (preparation / execution / result) in their spine-seq
    # order, each reduced to {stage, start_seq, end_seq, edge_count}.
    # Background ``stage_unclosed`` spans are omitted because they are the
    # overwhelmingly dominant class and can always be recovered as the
    # complement of these ranges.
    #
    # Designed so a consumer that only needs "where does each stage
    # sit on spine?" can read a single short list without scanning the
    # full ``edge_stage_projection`` or filtering ``stage_spans`` for
    # ``stage != 'stage_unclosed'``. ``edge_stage_projection`` remains untouched
    # and is still the canonical per-edge view.
    _ATTACK_STAGE_VOCAB = ("preparation", "execution", "result")
    compact_view_spans: list[dict[str, Any]] = []
    for span in stage_spans:
        st = span.get("stage")
        if st not in _ATTACK_STAGE_VOCAB:
            continue
        try:
            s_start = int(span.get("start_seq"))
            s_end = int(span.get("end_seq"))
        except (TypeError, ValueError):
            continue
        compact_view_spans.append({
            "stage": st,
            "start_seq": s_start,
            "end_seq": s_end,
            "edge_count": max(0, s_end - s_start + 1),
        })
    compact_view_stages_present = sorted({
        s["stage"] for s in compact_view_spans
    })
    compact_view_edge_count = sum(
        s["edge_count"] for s in compact_view_spans
    )
    compact_view = {
        "schema": "compact_span_view_v0",
        "authority": "derived_from_stage_spans",
        "supervision": "not_used",
        "purpose": (
            "Compact attack-stage span view over spine. Lists "
            "preparation / execution / result spans only, each with "
            "start_seq, end_seq, edge_count. Background (`stage_unclosed`) is "
            "the complement of these ranges and is intentionally "
            "omitted. Does not replace edge_stage_projection; provided "
            "as a smaller secondary view for consumers that only need "
            "stage boundaries."
        ),
        "stage_vocabulary": list(_ATTACK_STAGE_VOCAB),
        "spans": compact_view_spans,
        "stages_present": compact_view_stages_present,
        "total_spine_edges": n,
        "covered_edge_count": compact_view_edge_count,
        "uncovered_edge_count": max(0, n - compact_view_edge_count),
    }

    # ───────────────────────────────────────────────────────────────────
    # M4: non-authoritative substage_hints view
    # ───────────────────────────────────────────────────────────────────
    # Pure derived view. Source: narrative_roles.v0.json/anchors. Exposes
    # entry / result / handoff anchor positions in spine-seq space so a
    # Setting-1 model can attend to anchor locations inside execution
    # without reading the narrative_roles sidecar. Each hint is None
    # when the backing anchor is absent or its edge_id cannot be
    # resolved onto spine; hints are never fabricated.
    #
    # MUST NOT be used as a supervision target. This view does not
    # modify stage_spans, edge_stage_projection, per_stage_edge_counts,
    # stage_vocabulary, or derivation.inputs.
    hint_anchors = narrative_roles.get("anchors") or {}
    _HINT_SOURCE_ROLE = {
        "entry_anchor": "semantic_entry_anchor",
        "result_anchor": "result_anchor",
        "handoff_exec": "startup_handoff_exec",
    }

    def _resolve_substage_hint(anchor_key: str) -> Optional[dict[str, Any]]:
        anchor = hint_anchors.get(anchor_key)
        if not isinstance(anchor, dict):
            return None
        eid = anchor.get("edge_id")
        if not isinstance(eid, str) or not eid:
            return None
        sseq = seq_by_eid.get(eid)
        if not isinstance(sseq, int):
            return None
        rel = anchor.get("relation")
        rel_upper: Optional[str] = None
        if isinstance(rel, str) and rel:
            rel_upper = rel.upper()
        return {
            "name": anchor_key,
            "seq": sseq,
            "edge_id": eid,
            "relation": rel_upper,
            "source_role": _HINT_SOURCE_ROLE[anchor_key],
            "in_stage": stage_by_seq.get(sseq, "stage_unclosed"),
        }

    entry_hint = _resolve_substage_hint("entry_anchor")
    result_hint = _resolve_substage_hint("result_anchor")
    handoff_hint = _resolve_substage_hint("handoff_exec")
    hints_detail = [h for h in (entry_hint, result_hint, handoff_hint)
                    if h is not None]

    substage_hints = {
        "schema": "non_authoritative_hint_view_v0",
        "source": "narrative_roles.v0.json/anchors",
        "authority": "non_authoritative",
        "supervision": "not_used",
        "purpose": (
            "attention/ordering hint inside execution; not a stage "
            "label. Safe to read at inference time. MUST NOT be used "
            "as a training target. Values are in spine-seq space and "
            "are null when the backing narrative-role anchor is absent "
            "or cannot be resolved onto spine."
        ),
        "hints": {
            "entry_anchor_seq": (
                entry_hint["seq"] if entry_hint is not None else None
            ),
            "result_anchor_seq": (
                result_hint["seq"] if result_hint is not None else None
            ),
            "handoff_exec_seq": (
                handoff_hint["seq"] if handoff_hint is not None else None
            ),
        },
        "hints_detail": hints_detail,
    }

    return {
        "schema_version": STAGE_LABELS_SCHEMA_VERSION,
        "scenario_id": scenario_id,
        "chain_id": chain_id,
        "stage_vocabulary": ["preparation", "execution", "result", "stage_unclosed"],
        "gap_label": "stage_unclosed",
        "derivation": {
            "rule_version": rule_version,
            "source": "anchor_plus_local_continuity",
            "rules": [
                "first/last_malicious_seq scanned from main_sample.spine[*].attrs.malicious",
                "--- preparation ---",
                "prep_end_markers = narrative_roles.roles in {preparation_boundary_end, "
                "startup_handoff_exec, entry_bridge_pre} whose edge_id resolves to "
                "spine seq < first_malicious_seq",
                "if prep_end_markers present: prep_start_seq = max(their spine seqs); "
                "preparation = spine[prep_start_seq .. first_malicious_seq - 1]; "
                "spine[1 .. prep_start_seq - 1] folds into `stage_unclosed` (pre-attack runtime)",
                "--- preparation (v0.4.2 inferred fallback) ---",
                "if no prep_end_markers AND first_malicious_seq > 1: walk backward "
                "from spine[first_malicious_seq - 1] while edge.subject == "
                "spine[first_malicious_seq].subject AND not malicious, bounded by "
                "STAGE_PREP_INFERRED_K (currently 5). When the walker accepts >= 1 "
                "edge, prep_start_seq = earliest accepted seq and "
                "prep_rule_used = 'inferred_prep_pre_entry_same_subject_window'.",
                "--- preparation (v0.4.3 same-exe-in-container fallback) ---",
                "if the v0.4.2 strict same-subject walker admits zero edges, "
                "fall through to a same-exe-in-container walker: subject strings "
                "are parsed as 'proc:<container_id>:<pid>:<exe_path>' and pre-entry "
                "edges are accepted when container_id AND exe_path match the entry, "
                "bounded by STAGE_PREP_INFERRED_K_EXE_RELAXED (currently 3). When "
                "that fallback accepts >= 1 edge, prep_rule_used = "
                "'inferred_prep_pre_entry_same_exe_in_container_window'. Otherwise "
                "preparation is absent and spine[1 .. first_mal - 1] = stage_unclosed.",
                "--- preparation (v0.4.4 single-gap tolerance) ---",
                "both pre-entry inferred walks (strict same-subject and exe-"
                "relaxation) tolerate at most one non-matching edge in the "
                "backward walk. The gap is only kept when at least one match "
                "is accepted AFTER it (i.e. the skipped seq bridges two runs "
                "of the attacker subject/family -- e.g. an interleaved peer "
                "connect sandwiched between attacker setup edges on "
                "sandworm / joomla/CVE-2023-23752). Accepted matches still "
                "respect the existing caps (the gap does not consume cap "
                "budget); the gap edge is absorbed into the contiguous "
                "preparation span and prep_inferred_gap_seq is recorded. A "
                "malicious edge always stops the walk immediately and is "
                "never treated as a gap. When the gap is kept, "
                "prep_rule_used is suffixed with '_gap_tolerant' so "
                "consumers can bucket these scenarios separately.",
                "--- execution ---",
                "execution = spine[first_malicious_seq .. last_malicious_seq] "
                "(shrunk by 1 when tail-anchor mode applies; see below)",
                "--- result (v0.4) ---",
                "anchor_subject = spine[result_anchor.seq].subject (from narrative_roles; "
                "fallback: spine[last_malicious_seq].subject)",
                "walker starts at last_mal_seq + 1 and advances one seq at a time",
                "accept edge if edge.subject == anchor_subject AND "
                "(edge.relation in BACKBONE_RESULT_RELATIONS OR edge is the "
                "narrative_roles.anchors.result_tail_context seed)",
                "stop on subject switch, non-result-like relation without tail seed, "
                "or spine end",
                "result = spine[last_mal_seq + 1 .. result_end_seq] if walker accepted "
                "at least one edge; otherwise fall through to the v0.4.1 tail-anchor rule",
                "--- result (v0.4.2 tier-B post-result shell extension) ---",
                "additionally accept edges where edge.subject == anchor_subject AND "
                "edge.relation in STAGE_RESULT_TIER_B_RELATIONS "
                "({PROCESS_FORK, PROCESS_CLONE, NET_ACCEPT}). Such edges carry "
                "accepted_as = 'post_result_shell_same_subject' in result_walk_accepted "
                "and are bounded by STAGE_RESULT_TIER_B_CAP (currently 16). When the "
                "cap is hit the walker stops with result_stop_reason = "
                "'tier_b_cap_reached'; scenarios that rely on at least one tier-B "
                "edge are tagged result_rule_used = 'anchor_continuity_walker_tier_b_extended' "
                "so consumers can bucket them separately from pure tier-A walks. "
                "Cap + tier-B scope keeps long PROCESS_FORK runtime tails "
                "(e.g. pgadmin) from being pulled wholesale into the result span.",
                "--- result (v0.4.3 same-exe-in-container subject relaxation) ---",
                "the walker's subject-continuity test accepts, in addition to "
                "strict equality, subjects that share container_id AND exe_path "
                "with the anchor (parsed from 'proc:<container_id>:<pid>:"
                "<exe_path>'). This captures worker-fork continuations (apache2 "
                "child pid inheriting from the anchor pid) without pulling in "
                "cross-container or cross-binary edges. Edges accepted via the "
                "relaxation carry accepted_as = 'result_like_same_exe_in_container' "
                "(tier-A) or 'post_result_shell_same_exe_in_container' (tier-B). "
                "A relaxation-only tier-A walk surfaces as "
                "result_rule_used = 'anchor_continuity_walker_exe_relaxation'; "
                "tier-B walks that also used the relaxation stay tagged as "
                "'anchor_continuity_walker_tier_b_extended' and set "
                "inputs.result_walker_used_exe_relaxation = true.",
                "--- result (v0.4.1 tail-anchor H1) ---",
                "tail-anchor mode activates iff narrative_roles.anchors.result_anchor "
                "resolves to spine seq == last_malicious_seq == spine_len AND "
                "first_malicious_seq < last_malicious_seq (execution stays non-empty)",
                "when active: execution = spine[first_mal .. last_mal - 1]; "
                "result = spine[last_mal .. last_mal] (single edge on the tail anchor); "
                "post-result is empty",
                "--- post-result ---",
                "spine[result_end_seq + 1 .. n] = stage_unclosed (or spine[last_mal_seq + 1 .. n] "
                "when result is absent; empty when tail-anchor mode applies)",
                "--- substage_hints (M4, non-authoritative) ---",
                "substage_hints.hints.{entry_anchor_seq, result_anchor_seq, "
                "handoff_exec_seq} are derived solely from "
                "narrative_roles.v0.json.anchors.{entry_anchor, result_anchor, "
                "handoff_exec}.edge_id by spine-seq lookup; any anchor that is "
                "absent or whose edge_id cannot be resolved onto spine yields "
                "null. These hints are NEVER used as supervision targets and "
                "do not alter stage_spans / edge_stage_projection / "
                "per_stage_edge_counts / stage_vocabulary in any way.",
                "--- compact_view (H3, derived secondary view) ---",
                "compact_view.spans is the subsequence of stage_spans whose "
                "stage is in {preparation, execution, result}, reduced to "
                "{stage, start_seq, end_seq, edge_count}. Background `stage_unclosed` "
                "spans are intentionally omitted; they are the complement of "
                "compact_view.spans on [1 .. spine_len]. compact_view is a "
                "pure secondary view: it does not change stage_spans, "
                "edge_stage_projection, per_stage_edge_counts, or "
                "stage_vocabulary, and is never used as a supervision target.",
                *(
                    [
                        "--- tightening (stage_derivation_v0.4.5) ---",
                        "result windows produced only by tier-B continuity "
                        "({PROCESS_FORK, PROCESS_CLONE, NET_ACCEPT}) are demoted "
                        "to `stage_unclosed` when the result anchor is out of window and no "
                        "result self-evidence exists in-window. Demotion reasons "
                        "are recorded in inputs.result_demoted_reasons.",
                        "marker-based preparation stays unchanged. Inferred "
                        "same-subject preparation may remain, but gap-tolerant "
                        "fallbacks whose absorbed gap cannot be explained as an "
                        "entry bridge are demoted to `stage_unclosed`. Same-exe-in-container "
                        "preparation is kept only when the pre-entry window stays "
                        "tight to first_malicious_seq and has entry-side self-"
                        "evidence; otherwise it is demoted to `stage_unclosed`. Demotion "
                        "reasons are recorded in inputs.prep_demoted_reasons.",
                    ]
                    if _is_stage_derivation_v0_4_5_family(rule_version)
                    else []
                ),
            ],
            "result_relations": sorted(BACKBONE_RESULT_RELATIONS),
            "result_tier_b_relations": sorted(STAGE_RESULT_TIER_B_RELATIONS),
            "result_tier_b_cap": STAGE_RESULT_TIER_B_CAP,
            "prep_inferred_k": STAGE_PREP_INFERRED_K,
            "prep_inferred_k_exe_relaxed": STAGE_PREP_INFERRED_K_EXE_RELAXED,
            "inputs": {
                "first_malicious_seq": first_mal_seq,
                "last_malicious_seq": last_mal_seq,
                "spine_len": n,
                # preparation
                "prep_start_seq": prep_start_seq,
                "prep_rule_used": prep_rule_used,
                "prep_rule_family": prep_rule_family,
                "prep_end_candidates": prep_end_candidate_edges,
                "prep_inferred_walked_seqs": sorted(prep_inferred_walked_seqs),
                "prep_inferred_used_exe_relaxation": (
                    prep_inferred_used_exe_relaxation
                ),
                "prep_inferred_used_gap_tolerance": (
                    prep_inferred_used_gap_tolerance
                ),
                "prep_inferred_gap_seq": prep_inferred_gap_seq,
                "prep_entry_self_evidence_in_window": (
                    prep_entry_self_evidence_in_window
                ),
                "prep_gap_explainable_as_entry_bridge": (
                    prep_gap_explainable_as_entry_bridge
                ),
                "prep_demoted_to_stage_unclosed": prep_demoted_to_stage_unclosed,
                "prep_demoted_reasons": prep_demoted_reasons,
                # result
                "result_anchor_edge_id": result_anchor_edge_id,
                "anchor_subject": anchor_subject,
                "result_tail_edge_id": result_tail_edge_id,
                "result_tail_seq": result_tail_seq,
                "result_start_seq": result_start_seq,
                "result_end_seq": result_end_seq,
                "result_rule_used": result_rule_used,
                "result_stop_reason": result_stop_reason,
                "result_walk_accepted": result_walk_accepted,
                "result_tier_b_accepted_count": tier_b_accepted_count,
                "result_tier_b_cap_hit": tier_b_cap_hit,
                "result_walker_used_exe_relaxation": walker_used_exe_relaxation,
                "result_anchor_in_window": result_anchor_in_window,
                "result_self_evidence_in_window": (
                    result_self_evidence_in_window
                ),
                "result_tier_b_only_candidate": (
                    result_tier_b_only_candidate
                ),
                "result_demoted_to_stage_unclosed": result_demoted_to_stage_unclosed,
                "result_demoted_reasons": result_demoted_reasons,
            },
            "may_be_overridden_by": "optional per-scenario override file (not shipped in v1)",
        },
        "stage_spans": stage_spans,
        "edge_stage_projection": projection,
        "compact_view": compact_view,
        "substage_hints": substage_hints,
        "stats": {
            "total_spine_edges": n,
            "per_stage_edge_counts": dict(sorted(per_stage_counts.items())),
            "span_count": len(stage_spans),
            "gap_ratio": round(
                per_stage_counts.get("stage_unclosed", 0) / n, 6
            ) if n else 0.0,
        },
    }


# ---------------------------------------------------------------------------
# legacy_stage_segments.v0.json builder
# ---------------------------------------------------------------------------

def _build_legacy_stage_segments_archive(
    dataset: dict[str, Any],
    scenario_id: str,
    chain_id: Optional[str],
) -> dict[str, Any]:
    return {
        "schema_version": LEGACY_STAGE_SEGMENTS_SCHEMA_VERSION,
        "scenario_id": scenario_id,
        "chain_id": chain_id,
        "deprecated": True,
        "note": (
            "Archived from behavior_chain_dataset.v2.json. Kept for "
            "Auxiliary stage-segment fields. Use stage_labels.v0.json for "
            "authoritative training/evaluation stage labels."
        ),
        "stage_segments": list(dataset.get("stage_segments") or []),
        "substage_segments": list(dataset.get("substage_segments") or []),
    }


# ---------------------------------------------------------------------------
# Per-scenario export
# ---------------------------------------------------------------------------

def export_scenario(
    chain_dir: Path,
    release_root: Path,
    scenario_id_override: Optional[str] = None,
) -> dict[str, Any]:
    """Export one scenario into the release tree. Returns a manifest row."""
    dataset_path = chain_dir / "behavior_chain_dataset.v2.json"
    dataset_meta_path = chain_dir / "behavior_chain_dataset.v2.meta.json"
    backbone_path = chain_dir / "backbone_chain.v1.json"
    for p in (dataset_path, dataset_meta_path, backbone_path):
        if not p.exists():
            raise FileNotFoundError(f"missing source file: {p}")

    dataset = _read_json(dataset_path)
    dataset_meta = _read_json(dataset_meta_path)
    backbone = _read_json(backbone_path)

    # Scenario identity: prefer a stable path-derived id so that two runs
    # of the same scenario slug to the same release folder. The
    # pipeline's dataset.scenario_id is unfortunately the run timestamp
    # on current builds, so we only fall back to it when the path cannot
    # be interpreted.
    path_derived = _derive_scenario_id_from_path(chain_dir)
    scenario_id = (
        scenario_id_override
        or path_derived
        or dataset.get("scenario_id")
        or backbone.get("scenario_id")
        or chain_dir.parent.name
    )
    run_id_fallback = dataset.get("scenario_id") or backbone.get("scenario_id")
    chain_id = dataset.get("chain_id") or backbone.get("chain_id")

    slug = _scenario_slug(str(scenario_id))
    out_dir = release_root / "shared" / "scenarios" / slug
    out_dir.mkdir(parents=True, exist_ok=True)

    relative_paths = {
        "main_sample": f"shared/scenarios/{slug}/main_sample.json",
        "main_sample_meta": f"shared/scenarios/{slug}/main_sample.meta.json",
        "narrative_roles": f"shared/scenarios/{slug}/narrative_roles.v0.json",
        "stage_labels": f"shared/scenarios/{slug}/stage_labels.v0.json",
        "legacy_stage_segments": (
            f"shared/scenarios/{slug}/legacy_stage_segments.v0.json"
        ),
    }

    main_sample = _build_main_sample(dataset, backbone, scenario_id)
    narrative_roles = _build_narrative_roles_sidecar(
        backbone, scenario_id, chain_id
    )
    # Audit narrative-role alignment with main_sample spine.
    spine_edge_ids = {
        str(e.get("edge_id")) for e in main_sample.get("spine") or []
        if isinstance(e.get("edge_id"), str)
    }
    nroles_total = len(narrative_roles.get("roles") or [])
    nroles_hit = sum(
        1 for r in narrative_roles.get("roles") or []
        if r.get("edge_id") in spine_edge_ids
    )
    narrative_roles["main_sample_alignment"] = {
        "spine_edges_total": len(main_sample.get("spine") or []),
        "spine_edges_with_edge_id": len(spine_edge_ids),
        "roles_total": nroles_total,
        "roles_aligned_to_spine": nroles_hit,
        "roles_unaligned_to_spine": nroles_total - nroles_hit,
    }
    stage_labels = _build_stage_labels_sidecar(
        main_sample, narrative_roles, scenario_id, chain_id
    )
    legacy_archive = _build_legacy_stage_segments_archive(
        dataset, scenario_id, chain_id
    )
    main_sample_meta = _build_main_sample_meta(
        dataset_meta, scenario_id, chain_dir, relative_paths, main_sample
    )

    _write_json(out_dir / "main_sample.json", main_sample)
    _write_json(out_dir / "main_sample.meta.json", main_sample_meta)
    _write_json(out_dir / "narrative_roles.v0.json", narrative_roles)
    _write_json(out_dir / "stage_labels.v0.json", stage_labels)
    _write_json(out_dir / "legacy_stage_segments.v0.json", legacy_archive)

    return {
        "scenario_id": scenario_id,
        "scenario_slug": slug,
        "run_id": run_id_fallback,
        "chain_id": chain_id,
        "spine_edge_count": len(main_sample["spine"]),
        "source_chain_dir": str(chain_dir),
        "paths": relative_paths,
        "narrative_roles_computed_from": narrative_roles["computed_from"],
        "narrative_roles_alignment": narrative_roles["main_sample_alignment"],
        "main_sample_join_stats": main_sample["_join_stats"],
        "stage_inputs": stage_labels["derivation"]["inputs"],
        "per_stage_edge_counts": stage_labels["stats"]["per_stage_edge_counts"],
    }


# ---------------------------------------------------------------------------
# Settings + top-level scaffolding
# ---------------------------------------------------------------------------

_SETTING_CORE_MASK = {
    "sources": ["shared/scenarios/<scenario_slug>/main_sample.json"],
    "spine_fields_allowed": [
        "seq", "edge_id", "subject", "relation", "object",
        "attrs.evt_num", "attrs.timestamp", "attrs.raw_evt_type",
        "attrs.container_id", "attrs.fd_name",
        "audit_context[*]",
        "multisource_context.traffic[*]",
        "multisource_context.applog[*]",
    ],
    "spine_fields_masked": ["attrs.malicious"],
}

_SETTING_PRIMARY_SUPERVISION = {
    "source": "shared/scenarios/<scenario_slug>/stage_labels.v0.json",
    "target_view": "edge_stage_projection",
    "vocabulary": ["preparation", "execution", "result", "stage_unclosed"],
}


def _write_settings(release_root: Path) -> list[dict[str, Any]]:
    settings_dir = release_root / "settings"

    # --- Setting 1 ---
    s1_dir = settings_dir / "setting_1_real_input"
    _write_json(s1_dir / "feature_mask.json", dict(_SETTING_CORE_MASK))
    _write_json(s1_dir / "supervision.json", {
        "primary": dict(_SETTING_PRIMARY_SUPERVISION),
        "auxiliary": [],
    })
    _write_text(s1_dir / "README.md", _setting_1_readme())

    # --- Setting 2 ---
    s2_dir = settings_dir / "setting_2_anchor_hint"
    s2_mask = dict(_SETTING_CORE_MASK)
    s2_mask["sources"] = list(_SETTING_CORE_MASK["sources"]) + [
        "shared/scenarios/<scenario_slug>/narrative_roles.v0.json",
    ]
    s2_mask["narrative_role_fields_allowed"] = [
        "anchors.entry_anchor.edge_id",
        "anchors.result_anchor.edge_id",
        "anchors.handoff_exec.edge_id",
    ]
    s2_mask["narrative_role_fields_forbidden"] = [
        "roles[*]", "role_counts", "roles_present", "story_phase_coverage",
    ]
    s2_mask["derived_input_features"] = [
        {"name": "is_entry_anchor",  "rule": "edge_id == anchors.entry_anchor.edge_id"},
        {"name": "is_result_anchor", "rule": "edge_id == anchors.result_anchor.edge_id"},
        {"name": "is_handoff_exec",  "rule": "edge_id == anchors.handoff_exec.edge_id"},
    ]
    _write_json(s2_dir / "feature_mask.json", s2_mask)
    _write_json(s2_dir / "supervision.json", {
        "primary": dict(_SETTING_PRIMARY_SUPERVISION),
        "auxiliary": [],
    })
    _write_text(s2_dir / "README.md", _setting_2_readme())

    # --- Setting 3 ---
    s3_dir = settings_dir / "setting_3_multitask"
    _write_json(s3_dir / "feature_mask.json", dict(_SETTING_CORE_MASK))
    _write_json(s3_dir / "supervision.json", {
        "primary": dict(_SETTING_PRIMARY_SUPERVISION),
        "auxiliary": [
            {
                "name": "narrative_role_aux",
                "source": (
                    "shared/scenarios/<scenario_slug>/narrative_roles.v0.json"
                ),
                "target_view": "roles",
                "vocabulary": list(NARRATIVE_ROLE_VOCABULARY),
                "gap_label": "no_role",
            }
        ],
    })
    _write_json(s3_dir / "aux_loss_config.json", {
        "narrative_role_aux": {
            "loss_mask_by_confidence_tier": ["high", "mid"],
            "loss_mask_excluded_tiers": ["low"],
            "loss_weight": 0.3,
            "notes": (
                "Auxiliary head predicts narrative_role per spine edge. "
                "Only edges whose sidecar role carries confidence_tier in "
                "{high, mid} contribute to the auxiliary loss; low-tier "
                "roles (mid_span_representative) and edges without any "
                "role are masked out."
            ),
        },
    })
    _write_text(s3_dir / "README.md", _setting_3_readme())

    return [
        {"id": "setting_1_real_input",   "dir": "settings/setting_1_real_input"},
        {"id": "setting_2_anchor_hint",  "dir": "settings/setting_2_anchor_hint"},
        {"id": "setting_3_multitask",    "dir": "settings/setting_3_multitask"},
    ]


def _setting_1_readme() -> str:
    return (
        "# Setting 1 — real input only\n\n"
        "Input: `main_sample.json` spine + context. `attrs.malicious` is\n"
        "masked. No narrative_roles sidecar. Supervision comes from\n"
        "`stage_labels.v0.json` (edge_stage_projection).\n\n"
        "Training and inference read exactly the same field set.\n"
    )


def _setting_2_readme() -> str:
    return (
        "# Setting 2 — anchor-hint augmentation\n\n"
        "Input: main_sample (same mask as Setting 1) plus three per-edge\n"
        "boolean features derived from the narrative_roles sidecar's\n"
        "`anchors.{entry_anchor, result_anchor, handoff_exec}.edge_id`.\n"
        "The full `roles[*]` list is NOT readable — that would be label\n"
        "leakage since every role is derived from the malicious flag.\n\n"
        "Supervision: identical to Setting 1.\n"
    )


def _setting_3_readme() -> str:
    return (
        "# Setting 3 — multi-task supervision\n\n"
        "Input: identical to Setting 1 (no sidecar in the input pipeline).\n"
        "Primary task: stage classification from `stage_labels.v0.json`.\n"
        "Auxiliary task: per-edge narrative_role classification; loss\n"
        "mask excludes low-confidence (`mid_span_representative`) and\n"
        "unlabelled edges. At test time, drop the auxiliary head and\n"
        "evaluate exactly as Setting 1.\n"
    )


def _write_top_level_docs(release_root: Path) -> None:
    schemas_dir = release_root / "schemas"
    _write_json(schemas_dir / "main_sample.v0.schema.json", _schema_main_sample())
    _write_json(
        schemas_dir / "narrative_roles.v0.schema.json",
        _schema_narrative_roles(),
    )
    _write_json(
        schemas_dir / "stage_labels.v0.schema.json",
        _schema_stage_labels(),
    )
    _write_text(release_root / "README.md", _release_readme())


def _release_readme() -> str:
    return (
        "# dataset_release_v1\n\n"
        "Three-layer dataset release for attack-stage learning:\n\n"
        "1. **Main sample layer** — per-scenario `main_sample.json` and\n"
        "   `main_sample.meta.json` under `shared/scenarios/`. Only event\n"
        "   facts and context. No narrative roles, no stage labels.\n"
        "2. **narrative_roles sidecar** — `narrative_roles.v0.json`.\n"
        "   Per-edge high-level role annotations derived from backbone\n"
        "   structure (entry/result anchors, preparation boundaries, ...).\n"
        "   Every role carries a `confidence_tier` (high/mid/low) and a\n"
        "   `role_source` describing the rule that produced it.\n"
        "3. **stage_labels sidecar** — `stage_labels.v0.json`. Authoritative\n"
        "   stage labels with vocabulary `preparation / execution / result /\n"
        "   stage_unclosed`. Span-level is canonical; per-edge projection is\n"
        "   derived.\n\n"
        "Three experiment settings live under `settings/`:\n\n"
        "- `setting_1_real_input/` — pure real input\n"
        "- `setting_2_anchor_hint/` — setting 1 + entry/result/handoff anchor\n"
        "  bit features (full `roles[*]` is forbidden)\n"
        "- `setting_3_multitask/` — setting 1 input + stage primary head +\n"
        "  narrative_role auxiliary head (high/mid tiers only)\n\n"
        "Optional stage-segment fields are exported separately;\n"
        "`stage_labels.v0.json` contains the authoritative stage labels.\n"
    )


def _schema_main_sample() -> dict[str, Any]:
    return {
        "schema_version": MAIN_SAMPLE_SCHEMA_VERSION,
        "top_level_fields": [
            "schema_version", "scenario_id", "chain_id", "spine", "_join_stats"
        ],
        "spine_entry_fields": [
            "seq", "edge_id", "subject", "relation", "object", "attrs",
            "audit_context", "multisource_context"
        ],
        "spine_attrs_whitelist": list(MAIN_SAMPLE_ATTR_WHITELIST),
        "forbidden_in_main_sample": [
            "narrative_role", "narrative_role_alt",
            "stage", "stage_segments", "substage_segments",
            "expression_clarity", "semantic_narrative_summary",
        ],
        "applog_entry_derived_fields": {
            "attack_relevance_tier": {
                "vocabulary": list(APPLOG_TIER_VOCABULARY),
                "derivation": (
                    "attack_related if is_attack_related is truthy; "
                    "otherwise error_or_hv when semantic_type in "
                    "{error_exception, db_query, generic_runtime_log}; "
                    "otherwise background"
                ),
                "mutates_existing_fields": False,
            }
        },
        "audit_context_entry_slim_policy": {
            "dropped_top_level_fields": [
                {
                    "name": "link_features",
                    "reason": (
                        "Attachment-judgement details are not required by the model-facing record. "
                        "The public attachment decision fields remain available."
                    ),
                },
            ],
            "dropped_inner_event_fields_unconditional": [
                {
                    "name": "event.record_mode",
                    "reason": (
                        "The outer attachment record_mode identifies the record representation used by consumers."
                    ),
                },
            ],
            "dropped_inner_event_fields_when_redundant": [
                {
                    "name": "event.proc",
                    "keep_fields": [
                        "container_id", "pid", "name", "exepath"
                    ],
                    "reason": (
                        "Repeated process attributes are omitted when the corresponding event attributes "
                        "are identical; differing or unknown values remain available."
                    ),
                },
                {
                    "name": "event.fd",
                    "keep_fields": ["name", "type"],
                    "reason": (
                        "Repeated file-descriptor attributes are omitted when the corresponding event "
                        "attributes are identical; differing or unknown values remain available."
                    ),
                },
            ],
            "preserved_attach_decision_fields": [
                "position", "context_role", "source_tier", "record_mode",
                "attach_to_backbone_edge_id", "attach_reason",
                "attach_strength", "is_malicious",
                "is_necessary_context", "explanatory_channel",
            ],
            "mutates_existing_fields": False,
            "affects_supervision": False,
        },
        "traffic_entry_slim_policy": {
            "dropped_top_level_fields": [
                {
                    "name": "attach_basis",
                    "reason": (
                        "Traffic attachment metadata duplicates normalized connection, timing, "
                        "and sequence information already represented in the public record."
                    ),
                },
                {
                    "name": "frame_range",
                    "reason": (
                        "Packet-capture frame indices are not required for interpreting the public flow record."
                    ),
                },
                {
                    "name": "network_node_ids",
                    "reason": (
                        "Parser-internal graph node identifiers are not part of the public flow record."
                    ),
                },
                {
                    "name": "nat_alias_used",
                    "reason": (
                        "The normalized connection key is the public representation after address normalization."
                    ),
                },
            ],
            "direction_counts_policy": {
                "rule": (
                    "Drop `reverse` iff its value is 0 (unidirectional "
                    "flow summary); keep the `forward` key."
                ),
                "semantic_equivalence": (
                    "absent `reverse` == reverse:0"
                ),
            },
            "preserved_fields": [
                "summary_type", "normalized_conn_key", "l4_proto",
                "src_ip", "src_port", "dst_ip", "dst_port",
                "container_id", "service_name",
                "first_seen_ts", "last_seen_ts",
                "packet_count", "direction_counts",
                "semantic_type", "malicious", "is_attack_related",
                "attack_label_source",
                "attach_to_backbone_edge_id", "attach_reason",
                "attach_strength",
            ],
            "mutates_existing_fields": False,
            "affects_supervision": False,
        },
    }


def _schema_narrative_roles() -> dict[str, Any]:
    return {
        "schema_version": NARRATIVE_ROLES_SCHEMA_VERSION,
        "top_level_fields": [
            "schema_version", "scenario_id", "chain_id", "produced_by",
            "vocabulary", "result_tail_seq_window",
            "anchors", "result_tail_reason",
            "roles", "role_counts", "roles_present",
            "story_phase_coverage", "role_source_counts", "computed_from",
        ],
        "vocabulary": list(NARRATIVE_ROLE_VOCABULARY),
        "role_entry_fields": [
            "edge_id", "seq", "relation", "evt_num", "subject", "object",
            "malicious", "role", "role_alt", "role_source", "confidence_tier",
        ],
        "confidence_tiers": ["high", "mid", "low"],
    }


def _schema_stage_labels() -> dict[str, Any]:
    return {
        "schema_version": STAGE_LABELS_SCHEMA_VERSION,
        "top_level_fields": [
            "schema_version", "scenario_id", "chain_id",
            "stage_vocabulary", "gap_label",
            "derivation", "stage_spans", "edge_stage_projection",
            "compact_view", "substage_hints", "stats",
        ],
        "stage_vocabulary": ["preparation", "execution", "result", "stage_unclosed"],
        "gap_label": "stage_unclosed",
        "span_entry_fields": [
            "stage", "start_seq", "end_seq",
            "start_edge_id", "end_edge_id", "source",
        ],
        "projection_entry_fields": ["edge_id", "seq", "stage"],
        "compact_view_shape": {
            "schema": "compact_span_view_v0",
            "authority": "derived_from_stage_spans",
            "supervision": "not_used",
            "fields": {
                "stage_vocabulary": "list[str] (preparation/execution/result/stage_unclosed)",
                "spans[*]": {
                    "stage": "preparation | execution | result",
                    "start_seq": "int",
                    "end_seq": "int",
                    "edge_count": "int",
                },
                "stages_present": "list[str]",
                "total_spine_edges": "int",
                "covered_edge_count": "int",
                "uncovered_edge_count": "int",
            },
            "mutates_existing_fields": False,
            "affects_supervision": False,
        },
        "rule_versions_known": [
            "stage_derivation_v0.4.5",
        ],
        "result_rule_used_vocabulary": [
            "no_result_anchor_no_result",
            "no_anchor_subject_no_result",
            "anchor_continuity_walker",
            "anchor_continuity_walker_empty",
            "anchor_continuity_walker_tier_b_extended",
            "anchor_continuity_walker_exe_relaxation",
            "anchor_at_spine_tail_single_edge_result",
        ],
        "prep_rule_used_vocabulary": [
            "no_prep_end_marker_preparation_empty",
            "prep_end_marker_latest",
            "inferred_prep_pre_entry_same_subject_window",
            "inferred_prep_pre_entry_same_exe_in_container_window",
            "inferred_prep_pre_entry_same_subject_window_gap_tolerant",
            "inferred_prep_pre_entry_same_exe_in_container_window_gap_tolerant",
        ],
        "result_walk_accepted_as_vocabulary": [
            "result_like_same_subject",
            "result_like_same_exe_in_container",
            "tail_context_seed",
            "post_result_shell_same_subject",
            "post_result_shell_same_exe_in_container",
            "anchor_at_spine_tail",
        ],
        "substage_hints_shape": {
            "schema": "non_authoritative_hint_view_v0",
            "authority": "non_authoritative",
            "supervision": "not_used",
            "source": "narrative_roles.v0.json/anchors",
            "fields": {
                "hints.entry_anchor_seq": "int | null",
                "hints.result_anchor_seq": "int | null",
                "hints.handoff_exec_seq": "int | null",
                "hints_detail[*]": {
                    "name": "entry_anchor | result_anchor | handoff_exec",
                    "seq": "int",
                    "edge_id": "str",
                    "relation": "str | null",
                    "source_role": (
                        "semantic_entry_anchor | result_anchor | "
                        "startup_handoff_exec"
                    ),
                    "in_stage": "preparation | execution | result | stage_unclosed",
                },
            },
            "mutates_existing_fields": False,
            "affects_supervision": False,
        },
    }


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def build_release(
    chain_dirs: list[Path],
    release_root: Path,
    emit_stage_reasoning_benchmark: bool = True,
    scenario_id_overrides: Optional[dict[str, str]] = None,
) -> dict[str, Any]:
    release_root.mkdir(parents=True, exist_ok=True)
    _write_top_level_docs(release_root)
    settings = _write_settings(release_root)

    scenario_rows: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    for cv1 in chain_dirs:
        try:
            override = None
            if scenario_id_overrides:
                override = scenario_id_overrides.get(str(cv1.resolve()))
            row = export_scenario(cv1, release_root, scenario_id_override=override)
            scenario_rows.append(row)
            print(
                f"[release] exported scenario={row['scenario_id']} "
                f"slug={row['scenario_slug']} spine={row['spine_edge_count']} "
                f"nroles={row['narrative_roles_computed_from']}"
            )
        except Exception as exc:
            errors.append({"chain_dir": str(cv1), "error": repr(exc)})
            print(f"[release][error] {cv1}: {exc!r}", file=sys.stderr)

    manifest = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "release_root": str(release_root),
        "scenario_count": len(scenario_rows),
        "scenarios": scenario_rows,
        "settings": settings,
        "errors": errors,
    }
    _write_json(release_root / "manifest.json", manifest)

    # Optional downstream step: emit the stage-reasoning benchmark
    # data-pack (v2: model_input / gold / sample_index) directly from
    # the release we just wrote.  Read-only consumer — failures here
    # never roll back the release.
    if emit_stage_reasoning_benchmark:
        try:
            try:
                from .export_stage_reasoning_benchmark import (
                    export_benchmark as _export_stage_reasoning_benchmark,
                )
            except ImportError:
                module_path = Path(__file__).with_name(
                    "export_stage_reasoning_benchmark.py"
                )
                spec = importlib.util.spec_from_file_location(
                    "export_stage_reasoning_benchmark_fallback",
                    module_path,
                )
                if spec is None or spec.loader is None:
                    raise
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                _export_stage_reasoning_benchmark = module.export_benchmark

            bench_manifest = _export_stage_reasoning_benchmark(release_root)
            dataset_output = bench_manifest["outputs"]["dataset"]
            manifest["stage_reasoning_benchmark"] = {
                "data_dir": dataset_output["data_dir"],
                "model_input": dataset_output["model_input"],
                "gold": dataset_output["gold"],
                "sample_index": dataset_output["sample_index"],
                "sample_count": dataset_output["samples"],
                "stage_counts": bench_manifest["stage_counts"],
                "reasoning_schema_version": (
                    (bench_manifest.get("benchmark_design") or {})
                    .get("reasoning_schema_version")
                ),
                "reasoning_protocol": (
                    (bench_manifest.get("benchmark_design") or {})
                    .get("reasoning_protocol")
                ),
            }
            _write_json(release_root / "manifest.json", manifest)
            print(
                "[release] stage_reasoning_benchmark emitted: "
                f"samples={dataset_output['samples']} "
                f"data_dir={dataset_output['data_dir']}"
            )
        except Exception as exc:
            print(
                f"[release][warn] stage_reasoning_benchmark emit failed: {exc!r}",
                file=sys.stderr,
            )
    return manifest


def _iter_chain_dirs(roots: list[Path]) -> list[Path]:
    out: list[Path] = []
    seen: set[Path] = set()
    for root in roots:
        if root.name in {CHAIN_DIR_NAME, LEGACY_CHAIN_DIR_NAME} and (
            root / "behavior_chain_dataset.v2.json"
        ).exists():
            candidates = [root]
        else:
            candidates = sorted(
                path
                for path in root.rglob("*")
                if path.is_dir() and path.name in {CHAIN_DIR_NAME, LEGACY_CHAIN_DIR_NAME}
            )
        for cv1 in candidates:
            if not cv1.is_dir():
                continue
            if not (cv1 / "behavior_chain_dataset.v2.json").exists():
                continue
            if cv1 in seen:
                continue
            seen.add(cv1)
            out.append(cv1)
    return out


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Assemble dataset_release_v1/ from existing chain/ products. "
            "Pure downstream: does not modify any upstream artefact."
        )
    )
    parser.add_argument(
        "--chain-dir",
        action="append",
        type=Path,
        default=[],
        help=(
            f"One {CHAIN_DIR_NAME}/ directory to export. Can be passed multiple "
            "times. Takes precedence over --scenario-root."
        ),
    )
    parser.add_argument(
        "--scenario-root",
        action="append",
        type=Path,
        default=[],
        help=(
            f"Recurse under this path to discover {CHAIN_DIR_NAME}/ directories. "
            "Can be passed multiple times."
        ),
    )
    parser.add_argument(
        "--release-root",
        type=Path,
        default=DEFAULT_RELEASE_ROOT,
        help=f"Release output root. Default: {DEFAULT_RELEASE_ROOT_DISPLAY}",
    )
    parser.add_argument(
        "--no-stage-reasoning-benchmark",
        dest="emit_stage_reasoning_benchmark",
        action="store_false",
        help=(
            "Skip the optional stage-reasoning benchmark export step "
            "(unified SecLog-Bench-216 layout: data/model_input.jsonl, "
            "gold.jsonl, sample_index.jsonl). "
            "The step defaults to ON and only ever reads from the "
            "release it just wrote."
        ),
    )
    parser.set_defaults(emit_stage_reasoning_benchmark=True)
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    roots: list[Path] = list(args.chain_dir) + list(args.scenario_root)
    if not roots:
        print(
            "[release][error] pass at least one --chain-dir or "
            "--scenario-root",
            file=sys.stderr,
        )
        return 2
    dirs = _iter_chain_dirs(roots)
    if not dirs:
        print(f"[release][error] no {CHAIN_DIR_NAME}/ directories discovered", file=sys.stderr)
        return 2
    print(f"[release] discovered {len(dirs)} {CHAIN_DIR_NAME} dirs")
    manifest = build_release(
        chain_dirs=dirs,
        release_root=args.release_root.resolve(),
        emit_stage_reasoning_benchmark=args.emit_stage_reasoning_benchmark,
    )
    print(
        f"[release] manifest written: scenarios={manifest['scenario_count']} "
        f"errors={len(manifest['errors'])} "
        f"root={manifest['release_root']}"
    )
    return 0 if not manifest["errors"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
