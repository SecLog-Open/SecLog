"""Stage-reasoning benchmark exporter – v2 (blind evaluation data-pack).

This module is a pure downstream consumer of an already-built
``dataset_release_v1/`` tree.  It does NOT modify any release
artefact and does NOT introduce new stage-label semantics.

Output structure (default, masked blind)::

    <benchmark_root>/
        manifest.json
        README.md
        data/
            model_input.jsonl
            gold.jsonl
            sample_index.jsonl
            README.md

Optional ``--emit-evidence-visible-setting`` adds an ``evidence_visible/``
subtree with the same shape but retaining attack-related labels.

Frozen constraints
------------------
* raw / index / chain unchanged
* shared/scenarios release files unchanged
* benchmark is one unified dataset unit (no public partition)
* preparation / execution / result / stage_unclosed label vocabulary unchanged
"""
from __future__ import annotations

import argparse
import copy
import json
import re
import sys
import textwrap
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Iterator, Optional

# ---------------------------------------------------------------------------
# Schema constants
# ---------------------------------------------------------------------------

MODEL_INPUT_SCHEMA = "attack_chain_stage_reasoning_input.v1"
GOLD_SCHEMA = "attack_chain_stage_reasoning_gold.v1"
BENCHMARK_MANIFEST_SCHEMA = "attack_chain_stage_reasoning_benchmark.v1"

LEGAL_STAGES = frozenset({"preparation", "execution", "result", "stage_unclosed"})

TASK_INSTRUCTION = (
    "You are given a strict blind attack-chain evidence window for formal "
    "stage prediction. Predict exactly one stage from preparation, execution, "
    "result, or stage_unclosed, and return an EWVAA-style four-step claim-based "
    "reasoning chain grounded only in the visible evidence. Do not assume "
    "access to label.stage, gold annotations, sample_index, scenario "
    "metadata, CVE knowledge, vulnerability descriptions, or derived "
    "malicious/attack-related labels."
)
REASONING_PROTOCOL = [
    "scenario_or_evidence_understanding",
    "observable_evidence",
    "attack_stage_path_reasoning",
    "final_judgement",
]
REASONING_SCHEMA_VERSION = "ewvaa_four_step_v1"
REASONING_SOURCE = "four_step_reasoning_reference"

_REASONING_TEXT_REPLACEMENTS = [
    (re.compile(r"\bCVE-\d{4}-\d{4,7}(?:-[A-Za-z0-9_.-]+)?\b", re.IGNORECASE), "public_advisory"),
    (re.compile(r"\bCVE\b", re.IGNORECASE), "public_advisory"),
    (re.compile(r"\bvulhub[A-Za-z0-9_.-]*\b", re.IGNORECASE), "lab_corpus"),
    (re.compile(r"\bcmsms[A-Za-z0-9_.-]*\b", re.IGNORECASE), "app_family"),
    (re.compile(r"\bjoomla[A-Za-z0-9_.-]*\b", re.IGNORECASE), "app_family"),
    (re.compile(r"\bgitlist[A-Za-z0-9_.-]*\b", re.IGNORECASE), "app_family"),
    (re.compile(r"\badminer[A-Za-z0-9_.-]*\b", re.IGNORECASE), "app_family"),
    (re.compile(r"\bsolr[A-Za-z0-9_.-]*\b", re.IGNORECASE), "app_family"),
    (re.compile(r"\bgeoserver[A-Za-z0-9_.-]*\b", re.IGNORECASE), "app_family"),
    (re.compile(r"\bmetabase[A-Za-z0-9_.-]*\b", re.IGNORECASE), "app_family"),
    (re.compile(r"\bofbiz[A-Za-z0-9_.-]*\b", re.IGNORECASE), "app_family"),
    (re.compile(r"\bpgadmin[A-Za-z0-9_.-]*\b", re.IGNORECASE), "app_family"),
    (re.compile(r"\bjuice-shop[A-Za-z0-9_.-]*\b", re.IGNORECASE), "app_family"),
    (re.compile(r"\bmulti-jump[A-Za-z0-9_.-]*\b", re.IGNORECASE), "scenario_family"),
    (re.compile(r"\bsandworm[A-Za-z0-9_.-]*\b", re.IGNORECASE), "scenario_family"),
    (re.compile(r"\bRCE\b", re.IGNORECASE), "remote command behavior"),
    (re.compile(r"\bXXE\b", re.IGNORECASE), "parser interaction behavior"),
    (re.compile(r"\bexecve\b", re.IGNORECASE), "process_exec"),
    (re.compile(r"\bresource\b", re.IGNORECASE), "asset"),
    (re.compile(r"\bresources\b", re.IGNORECASE), "assets"),
    (re.compile(r"\bpre-exploitation\b", re.IGNORECASE), "pre-execution"),
    (re.compile(r"\bpost-exploitation\b", re.IGNORECASE), "post-execution"),
    (re.compile(r"\bexploitation\b", re.IGNORECASE), "attack execution"),
]

# ---------------------------------------------------------------------------
# Leakage field sets – fields to remove from model_input
# ---------------------------------------------------------------------------

# Stage-answer / gold / derivation fields (recursive removal)
STAGE_ANSWER_FIELDS = frozenset({
    "label", "gold", "stage", "stage_span", "edge_stage_projection",
    "expected_stage", "target_stage", "answer", "is_high_conf", "high_conf",
    "prep_rule_used", "result_rule_used", "derivation", "compact_view",
    "stage_inputs", "per_stage_edge_counts", "in_stage", "source_stage",
})

# Narrative-role leakage fields (top-level input keys to remove entirely)
NARRATIVE_LEAKAGE_KEYS = frozenset({
    "narrative_roles", "narrative_anchors", "substage_hints",
    "preparation_boundary_start", "preparation_boundary_end",
    "result_anchor", "result_tail_context",
    "semantic_entry_anchor", "entry_anchor", "handoff_exec",
})

# Attack-related / malicious label fields (recursive removal in masked mode)
ATTACK_LABEL_FIELDS = frozenset({
    "malicious", "is_malicious", "is_attack_related",
    "attack_relevance_tier", "attack_label_source",
    "attack_related_level", "attack_related_reason",
    "write_self_malicious", "containing_unit_malicious",
    "attached_backbone_edge_malicious",
})

# Sub-keys inside attach_basis that leak attack labels
ATTACH_BASIS_ATTACK_KEYS = frozenset({
    "attack_related_level", "attack_related_reason",
})

# Combined for strict leakage check on the final model_input blob
ALL_LEAKAGE_FIELDS = STAGE_ANSWER_FIELDS | NARRATIVE_LEAKAGE_KEYS | ATTACK_LABEL_FIELDS

_MALICIOUS_PREFIX_RE = re.compile(r"\[\*MALICIOUS\*\]\s*")


# ---------------------------------------------------------------------------
# IO helpers
# ---------------------------------------------------------------------------


def _read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with path.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False))
            fh.write("\n")
            n += 1
    return n


def _write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        json.dump(obj, fh, ensure_ascii=False, indent=2)
        fh.write("\n")


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        fh.write(text)


def _manifest_path(path: Path, release_root: Path) -> str:
    """Use portable relative paths when output is inside the release tree."""
    try:
        return str(path.resolve().relative_to(release_root.resolve()))
    except ValueError:
        return str(path.resolve())


# ---------------------------------------------------------------------------
# Sample-ID construction (leak-free)
# ---------------------------------------------------------------------------


def make_safe_sample_id(slug: str, start_seq: int, end_seq: int) -> str:
    """Build a sample_id that carries no stage information."""
    return f"{slug}__window_{start_seq}_{end_seq}"


def _slug_from_scenario_id(scenario_id: str) -> str:
    return (
        scenario_id.replace("/", "__")
        .replace(":", "_")
        .replace(" ", "_")
    )


# ---------------------------------------------------------------------------
# Sanitize / mask helpers
# ---------------------------------------------------------------------------


def _strip_malicious_prefix(text: str) -> str:
    """Remove ``[*MALICIOUS*] `` prefix from log messages."""
    if isinstance(text, str):
        return _MALICIOUS_PREFIX_RE.sub("", text)
    return text


def _remove_keys_recursive(
    obj: Any,
    keys_to_remove: frozenset[str],
    *,
    strip_malicious_prefix_in_messages: bool = False,
) -> Any:
    """Deep-copy *obj* with offending keys removed at every nesting level."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if k in keys_to_remove:
                continue
            if k == "attach_basis" and isinstance(v, dict):
                v = {
                    bk: bv for bk, bv in v.items()
                    if bk not in ATTACH_BASIS_ATTACK_KEYS
                } if keys_to_remove & ATTACK_LABEL_FIELDS else v
            cleaned = _remove_keys_recursive(
                v, keys_to_remove,
                strip_malicious_prefix_in_messages=strip_malicious_prefix_in_messages,
            )
            if strip_malicious_prefix_in_messages and k in (
                "message", "normalized_message",
            ):
                cleaned = _strip_malicious_prefix(cleaned)
            out[k] = cleaned
        return out
    if isinstance(obj, list):
        return [
            _remove_keys_recursive(
                item, keys_to_remove,
                strip_malicious_prefix_in_messages=strip_malicious_prefix_in_messages,
            )
            for item in obj
        ]
    return obj


def sanitize_spine_edge(
    edge: dict[str, Any],
    setting: str = "masked",
) -> dict[str, Any]:
    """Sanitize a single spine edge for model_input."""
    keys = STAGE_ANSWER_FIELDS | (ATTACK_LABEL_FIELDS if setting == "masked" else frozenset())
    return _remove_keys_recursive(
        edge, keys,
        strip_malicious_prefix_in_messages=(setting == "masked"),
    )


def sanitize_model_input_spine(
    spine: list[dict[str, Any]],
    setting: str = "masked",
) -> list[dict[str, Any]]:
    return [sanitize_spine_edge(e, setting) for e in spine]


def contains_leakage_field(obj: Any, extra: frozenset[str] | None = None) -> list[str]:
    """Return list of leakage field names found anywhere in *obj*."""
    check = ALL_LEAKAGE_FIELDS | (extra or frozenset())
    found: list[str] = []

    def _walk(o: Any) -> None:
        if isinstance(o, dict):
            for k, v in o.items():
                if k in check:
                    found.append(k)
                _walk(v)
        elif isinstance(o, list):
            for item in o:
                _walk(item)

    _walk(obj)
    return found


# ---------------------------------------------------------------------------
# Window extraction (reused from v0.3 — no semantic change)
# ---------------------------------------------------------------------------


def _load_scenario(
    release_root: Path,
    scenario_row: dict[str, Any],
) -> Optional[dict[str, Any]]:
    paths = scenario_row.get("paths") or {}
    try:
        main_sample = _read_json(release_root / paths["main_sample"])
        stage_labels = _read_json(release_root / paths["stage_labels"])
        narrative_roles = _read_json(release_root / paths["narrative_roles"])
    except (FileNotFoundError, KeyError):
        return None
    return {
        "scenario_row": scenario_row,
        "main_sample": main_sample,
        "stage_labels": stage_labels,
        "narrative_roles": narrative_roles,
        "release_paths": paths,
    }


def _resolve_source_stage_derivation_version(
    versions: set[str],
) -> str:
    cleaned = {v for v in versions if isinstance(v, str) and v}
    if not cleaned:
        return "stage_derivation_v0.4.5"
    if len(cleaned) != 1:
        raise ValueError(
            "benchmark export expects a single stage derivation version; "
            f"got {sorted(cleaned)}"
        )
    return next(iter(cleaned))


def _slice_spine(
    main_sample: dict[str, Any],
    start_seq: int,
    end_seq: int,
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for edge in main_sample.get("spine") or []:
        try:
            seq = int(edge.get("seq"))
        except (TypeError, ValueError):
            continue
        if start_seq <= seq <= end_seq:
            out.append(edge)
    return out


def _slice_narrative_roles(
    narrative_roles: dict[str, Any],
    start_seq: int,
    end_seq: int,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    roles_in_window: list[dict[str, Any]] = []
    for role in narrative_roles.get("roles") or []:
        try:
            seq = int(role.get("seq"))
        except (TypeError, ValueError):
            continue
        if start_seq <= seq <= end_seq:
            roles_in_window.append(role)

    anchors_in_window: dict[str, Any] = {}
    for key, anchor in (narrative_roles.get("anchors") or {}).items():
        if not isinstance(anchor, dict):
            anchors_in_window[key] = None
            continue
        try:
            seq = int(anchor.get("seq"))
        except (TypeError, ValueError):
            anchors_in_window[key] = None
            continue
        anchors_in_window[key] = anchor if start_seq <= seq <= end_seq else None

    return roles_in_window, anchors_in_window


def _slice_stage_label_side(
    stage_labels: dict[str, Any],
    start_seq: int,
    end_seq: int,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    edge_proj: list[dict[str, Any]] = []
    for ep in stage_labels.get("edge_stage_projection") or []:
        try:
            seq = int(ep.get("seq"))
        except (TypeError, ValueError):
            continue
        if start_seq <= seq <= end_seq:
            edge_proj.append(ep)

    hints = (stage_labels.get("substage_hints") or {}).get("hints") or {}
    hints_in_window: dict[str, Any] = {}
    for hint_name, hint_seq in hints.items():
        if hint_seq is None:
            hints_in_window[hint_name] = None
            continue
        try:
            s = int(hint_seq)
        except (TypeError, ValueError):
            hints_in_window[hint_name] = None
            continue
        hints_in_window[hint_name] = s if start_seq <= s <= end_seq else None

    return edge_proj, hints_in_window


# ---------------------------------------------------------------------------
# Gold reasoning chain builder
# ---------------------------------------------------------------------------


def _pick_key_evidence(
    spine: list[dict[str, Any]],
    stage: str,
    narrative_roles_window: list[dict[str, Any]],
    anchors_window: dict[str, Any],
    max_refs: int = 3,
) -> list[dict[str, str | int | None]]:
    """Pick up to *max_refs* representative evidence refs for the reasoning chain."""
    refs: list[dict[str, str | int | None]] = []
    if not spine:
        return refs

    if stage == "preparation":
        candidates = spine[-min(max_refs, len(spine)):]
    elif stage == "execution":
        anchor_seq = None
        ea = anchors_window.get("entry_anchor")
        if isinstance(ea, dict):
            anchor_seq = ea.get("seq")
        if anchor_seq is not None:
            candidates = [e for e in spine if e.get("seq") == anchor_seq]
            if len(candidates) < max_refs:
                mid = len(spine) // 2
                for e in spine[mid: mid + max_refs]:
                    if e not in candidates:
                        candidates.append(e)
        else:
            mid = len(spine) // 2
            candidates = spine[mid: mid + max_refs]
    elif stage == "result":
        ra = anchors_window.get("result_anchor")
        if isinstance(ra, dict) and ra.get("seq") is not None:
            candidates = [e for e in spine if e.get("seq") == ra.get("seq")]
            for e in spine[:max_refs]:
                if e not in candidates:
                    candidates.append(e)
        else:
            candidates = spine[:max_refs]
    else:
        candidates = spine[:max_refs]

    for e in candidates[:max_refs]:
        refs.append({"seq": e.get("seq"), "edge_id": e.get("edge_id")})
    return refs


def _describe_edge_behavior(edge: dict[str, Any]) -> str:
    """Short behavioral description for an edge."""
    rel = edge.get("relation", "UNKNOWN")
    subj = edge.get("subject", "?")
    obj = edge.get("object", "?")
    attrs = edge.get("attrs") or {}
    evt = attrs.get("raw_evt_type", "")
    parts = [f"{rel} ({evt})" if evt else rel, f"subject={subj}", f"object={obj}"]
    return "; ".join(parts)


def _sanitize_reasoning_claim(text: str) -> str:
    """Keep deterministic gold claims within the strict-blind-safe vocabulary."""
    out = str(text or "")
    for pattern, replacement in _REASONING_TEXT_REPLACEMENTS:
        out = pattern.sub(replacement, out)
    return out


def _normalise_evidence_refs(refs: Any) -> list[dict[str, Any]]:
    if not isinstance(refs, list):
        return []
    out: list[dict[str, Any]] = []
    seen: set[tuple[Any, Any]] = set()
    for ref in refs:
        if not isinstance(ref, dict):
            continue
        clean: dict[str, Any] = {}
        if "seq" in ref:
            clean["seq"] = ref.get("seq")
        if "edge_id" in ref:
            clean["edge_id"] = ref.get("edge_id")
        if not clean:
            continue
        marker = (clean.get("seq"), clean.get("edge_id"))
        if marker in seen:
            continue
        seen.add(marker)
        out.append(clean)
    return out


def build_gold_reasoning_chain(
    stage: str,
    spine_window: list[dict[str, Any]],
    narrative_roles_window: list[dict[str, Any]],
    anchors_window: dict[str, Any],
) -> list[dict[str, Any]]:
    """Generate a deterministic EWVAA four-step initial reasoning chain."""
    evidence_refs = _pick_key_evidence(
        spine_window, stage, narrative_roles_window, anchors_window
    )
    if not evidence_refs and not spine_window:
        return []

    behavior_descs = []
    for ref in evidence_refs:
        matching = [e for e in spine_window if e.get("seq") == ref.get("seq")]
        if matching:
            behavior_descs.append(_describe_edge_behavior(matching[0]))

    edge_count = len(spine_window)
    evidence_summary = (
        f"Window contains {edge_count} spine edge(s). "
        + (f"Key evidence: {'; '.join(behavior_descs[:3])}." if behavior_descs else "")
    )

    stage_explanations = {
        "preparation": (
            "The observed behaviors are consistent with pre-execution "
            "setup — reconnaissance, scanning, or resource staging that "
            "comes before the primary attack execution."
        ),
        "execution": (
            "The observed behaviors correspond to active exploitation or "
            "primary attack execution — the core malicious actions in the "
            "attack chain."
        ),
        "result": (
            "The observed behaviors are consistent with post-execution "
            "outcomes — data exfiltration, persistence establishment, or "
            "consequence of the executed attack."
        ),
        "stage_unclosed": (
            "The window is attack-related, but the visible evidence does not "
            "sufficiently close preparation, execution, or result. "
            "stage_unclosed is a stage-closure label, not a fourth real "
            "attack lifecycle stage."
        ),
    }

    other_stages = [s for s in ("preparation", "execution", "result", "stage_unclosed") if s != stage]
    counter_claim = (
        f"Not {' / '.join(other_stages)} because the behavioral evidence "
        f"does not match the characteristics of those stages."
    )
    behavior_claim = (
        "Behavioral categories observed: "
        + ", ".join(
            sorted({
                e.get("relation", "UNKNOWN") for e in spine_window
            })[:6]
        )
        + "."
    )

    chain: list[dict[str, Any]] = [
        {
            "step": "scenario_or_evidence_understanding",
            "claim": evidence_summary,
            "evidence_refs": evidence_refs,
        },
        {
            "step": "observable_evidence",
            "claim": evidence_summary,
            "evidence_refs": evidence_refs,
        },
        {
            "step": "attack_stage_path_reasoning",
            "claim": f"{behavior_claim} {stage_explanations.get(stage, '')}".strip(),
            "evidence_refs": evidence_refs[:2],
        },
        {
            "step": "final_judgement",
            "claim": f"{counter_claim} Final stage assignment: {stage}.",
            "evidence_refs": evidence_refs,
        },
    ]
    for step in chain:
        step["claim"] = _sanitize_reasoning_claim(step["claim"]).strip() or f"Reference stage remains {stage}."
        step["evidence_refs"] = _normalise_evidence_refs(step.get("evidence_refs") or evidence_refs)
    return chain


# ---------------------------------------------------------------------------
# Projection builders
# ---------------------------------------------------------------------------


def _build_task_block() -> dict[str, Any]:
    return {
        "task_name": "attack_chain_stage_reasoning",
        "instruction": TASK_INSTRUCTION,
        "allowed_labels": sorted(LEGAL_STAGES),
        "reasoning_protocol": list(REASONING_PROTOCOL),
        "protocol_constraints": [
            "task_mode must be `stage_prediction`.",
            "Predict `predicted_stage`; do not explain or restate an unseen gold stage.",
            "The model cannot rely on `label.stage`, `gold.jsonl`, or `sample_index.jsonl`.",
            "Do not use CVE identifiers, scenario names, vulnerability descriptions, service/scenario metadata, or derived malicious/attack-related labels as reasoning shortcuts.",
            "`stage_unclosed` means the window is attack-related but the visible evidence does not sufficiently close preparation, execution, or result; it does not prove absolute safety.",
            "Every reasoning step must contain a non-empty `claim` grounded in visible evidence.",
            "Every reasoning step should cite local visible `seq` and/or `edge_id` references when available.",
        ],
        "output_schema": {
            "task_mode": "stage_prediction",
            "sample_id": "",
            "predicted_stage": "preparation | execution | result | stage_unclosed",
            "reasoning_chain": [
                {
                    "step": "scenario_or_evidence_understanding",
                    "claim": "",
                    "evidence_refs": [
                        {"seq": "integer or null", "edge_id": "string or null"}
                    ],
                },
                {
                    "step": "observable_evidence",
                    "claim": "",
                    "evidence_refs": [
                        {"seq": "integer or null", "edge_id": "string or null"}
                    ],
                },
                {
                    "step": "attack_stage_path_reasoning",
                    "claim": "",
                    "evidence_refs": [
                        {"seq": "integer or null", "edge_id": "string or null"}
                    ],
                },
                {
                    "step": "final_judgement",
                    "claim": "",
                    "evidence_refs": [
                        {"seq": "integer or null", "edge_id": "string or null"}
                    ],
                }
            ],
            "confidence": "",
        },
    }


def project_model_input(
    sample_id: str,
    scenario_id: str,
    start_seq: int,
    end_seq: int,
    spine_window: list[dict[str, Any]],
    setting: str = "masked",
) -> dict[str, Any]:
    """Build model_input row.  *spine_window* must already be sanitized."""
    return {
        "schema_version": MODEL_INPUT_SCHEMA,
        "sample_id": sample_id,
        "scenario_id": scenario_id,
        "window": {"start_seq": start_seq, "end_seq": end_seq},
        "task": _build_task_block(),
        "input": {
            "spine": spine_window,
        },
    }


def project_gold(
    sample_id: str,
    scenario_id: str,
    start_seq: int,
    end_seq: int,
    stage: str,
    stage_span: dict[str, Any],
    edge_stage_projection: list[dict[str, Any]],
    gold_reasoning_chain: list[dict[str, Any]],
) -> dict[str, Any]:
    row = {
        "schema_version": GOLD_SCHEMA,
        "sample_id": sample_id,
        "scenario_id": scenario_id,
        "window": {"start_seq": start_seq, "end_seq": end_seq},
        "label": {
            "stage": stage,
            "stage_span": stage_span,
            "edge_stage_projection": edge_stage_projection,
        },
        "reasoning_schema_version": REASONING_SCHEMA_VERSION,
        "reasoning_source": REASONING_SOURCE,
        "gold_reasoning_chain": gold_reasoning_chain,
    }
    return row


def project_sample_index(
    sample_id: str,
    scenario_id: str,
    stage: str,
    start_seq: int,
    end_seq: int,
    release_paths: dict[str, Any],
    line_no: int,
) -> dict[str, Any]:
    return {
        "sample_id": sample_id,
        "scenario_id": scenario_id,
        "stage": stage,
        "window": {"start_seq": start_seq, "end_seq": end_seq},
        "source_files": {
            "main_sample": release_paths.get("main_sample"),
            "stage_labels": release_paths.get("stage_labels"),
            "narrative_roles": release_paths.get("narrative_roles"),
        },
        "line_no": line_no,
    }


# ---------------------------------------------------------------------------
# Window-sample iteration
# ---------------------------------------------------------------------------


def _window_samples_for_scenario(
    scenario: dict[str, Any],
) -> Iterator[dict[str, Any]]:
    """Yield one raw sample per stage span (unchanged selection logic)."""
    scenario_row = scenario["scenario_row"]
    scenario_id = scenario_row["scenario_id"]
    scenario_slug = scenario_row.get("scenario_slug") or _slug_from_scenario_id(
        scenario_id
    )
    main_sample = scenario["main_sample"]
    stage_labels = scenario["stage_labels"]
    narrative_roles = scenario["narrative_roles"]
    paths = scenario["release_paths"]

    for span in stage_labels.get("stage_spans") or []:
        stage = span.get("stage")
        if stage not in LEGAL_STAGES:
            continue
        try:
            start_seq = int(span.get("start_seq"))
            end_seq = int(span.get("end_seq"))
        except (TypeError, ValueError):
            continue
        if end_seq < start_seq:
            continue

        spine_window = _slice_spine(main_sample, start_seq, end_seq)
        if not spine_window:
            continue

        roles_window, anchors_window = _slice_narrative_roles(
            narrative_roles, start_seq, end_seq
        )
        edge_stage_projection_window, substage_hints_window = (
            _slice_stage_label_side(stage_labels, start_seq, end_seq)
        )

        sample_id = make_safe_sample_id(scenario_slug, start_seq, end_seq)

        yield {
            "sample_id": sample_id,
            "scenario_id": scenario_id,
            "scenario_slug": scenario_slug,
            "start_seq": start_seq,
            "end_seq": end_seq,
            "stage": stage,
            "spine_window": spine_window,
            "roles_window": roles_window,
            "anchors_window": anchors_window,
            "edge_stage_projection_window": edge_stage_projection_window,
            "substage_hints_window": substage_hints_window,
            "stage_span": span,
            "release_paths": paths,
        }


# ---------------------------------------------------------------------------
# Leakage validation
# ---------------------------------------------------------------------------


def validate_no_leakage(
    rows: list[dict[str, Any]],
    label: str = "model_input",
) -> list[str]:
    """Check every row for residual leakage fields.  Returns error messages."""
    errors: list[str] = []
    stage_pattern = re.compile(
        r"\b(preparation|execution|result)\b", re.IGNORECASE
    )
    for i, row in enumerate(rows):
        sid = row.get("sample_id", f"row_{i}")
        leaked = contains_leakage_field(row)
        if leaked:
            errors.append(
                f"[{label}] sample {sid}: residual leakage fields {leaked}"
            )
        if stage_pattern.search(sid):
            errors.append(
                f"[{label}] sample_id contains stage name: {sid}"
            )
    return errors


def validate_alignment(
    model_input_rows: list[dict[str, Any]],
    gold_rows: list[dict[str, Any]],
    index_rows: list[dict[str, Any]],
    split_name: str,
) -> list[str]:
    """Cross-check row counts and sample_id alignment."""
    errors: list[str] = []
    mi_ids = [r["sample_id"] for r in model_input_rows]
    g_ids = [r["sample_id"] for r in gold_rows]
    idx_ids = [r["sample_id"] for r in index_rows]
    if len(mi_ids) != len(g_ids):
        errors.append(
            f"[{split_name}] model_input ({len(mi_ids)}) vs gold ({len(g_ids)}) "
            "row count mismatch"
        )
    if len(mi_ids) != len(idx_ids):
        errors.append(
            f"[{split_name}] model_input ({len(mi_ids)}) vs sample_index "
            f"({len(idx_ids)}) row count mismatch"
        )
    if mi_ids != g_ids:
        errors.append(f"[{split_name}] sample_id order differs between model_input and gold")
    if mi_ids != idx_ids:
        errors.append(f"[{split_name}] sample_id order differs between model_input and sample_index")
    for sid in mi_ids:
        for stage_word in ("preparation", "execution", "result", "stage_unclosed"):
            if stage_word in sid.lower():
                errors.append(f"[{split_name}] sample_id leaks stage: {sid}")
                break
    return errors


# ---------------------------------------------------------------------------
# README generators
# ---------------------------------------------------------------------------


def _top_readme(
    sample_count: int,
    stage_counts: dict[str, int],
    has_evidence_visible: bool,
    source_stage_derivation: str,
) -> str:
    ev_section = ""
    if has_evidence_visible:
        ev_section = textwrap.dedent("""\

        ## Evidence-visible ablation

        The `evidence_visible/` subtree retains attack-related labels
        (malicious, is_attack_related, attack_relevance_tier, etc.) in
        `model_input.jsonl`.  This is an **assisted reasoning / ablation
        setting** — NOT the default blind evaluation.  Use it only to
        measure how much attack-evidence labels help stage reasoning.
        """)

    return textwrap.dedent(f"""\
    # Stage Reasoning Benchmark

    Unified blind attack-chain stage reasoning evaluation data-pack.

    ## Task

    Given an attack-chain evidence window, determine the attack stage:
    **preparation**, **execution**, **result**, or **stage_unclosed**.

    This release is one indivisible dataset unit containing {sample_count}
    samples. The model reads `data/model_input.jsonl`; `data/gold.jsonl`
    is for scoring only and `data/sample_index.jsonl` is the aligned index.

    ## Files

    | File | Purpose |
    |------|---------|
    | `data/model_input.jsonl` | Blind model input ({sample_count} samples) |
    | `data/gold.jsonl` | Ground-truth labels + reasoning chain |
    | `data/sample_index.jsonl` | Aligned traceability index |
    | `manifest.json` | Machine-readable benchmark metadata |

    Stage distribution: {stage_counts}

    ## Input policy (masked blind setting)

    * **Preserved**: spine edges, audit_context, multisource_context.applog,
      multisource_context.traffic — all factual behavioral evidence.
    * **Removed**: stage labels, narrative role/anchor objects, substage hints,
      malicious/attack-related derived labels, derivation rules.

    Formal model evaluation should use the strict blind
    `data/model_input.jsonl` and score predictions against `data/gold.jsonl`.

    ## Model output format

    `predictions.jsonl` — one JSON per line:

    ```json
    {{
      "task_mode": "stage_prediction",
      "sample_id": "...",
      "predicted_stage": "preparation | execution | result | stage_unclosed",
      "reasoning_chain": [
        {{"step": "scenario_or_evidence_understanding", "claim": "", "evidence_refs": []}},
        {{"step": "observable_evidence", "claim": "", "evidence_refs": []}},
        {{"step": "attack_stage_path_reasoning", "claim": "", "evidence_refs": []}},
        {{"step": "final_judgement", "claim": "", "evidence_refs": []}}
      ],
      "confidence": ""
    }}
    ```

    ## Gold reasoning chain

    `gold_reasoning_chain` in `gold.jsonl` is the current EWVAA-style
    four-step claim-based reference chain:

    1. `scenario_or_evidence_understanding`
    2. `observable_evidence`
    3. `attack_stage_path_reasoning`
    4. `final_judgement`

    `label.stage` remains the authoritative stage label from
    `{source_stage_derivation}`.  The reasoning chain explains that label;
    it does not regenerate or override it.  Rows converted without a
    validated EWVAA/API candidate are marked with
    `reasoning_source = "{REASONING_SOURCE}"`.
    {ev_section}
    ## Source

    Built from `dataset_release_v1` using `{source_stage_derivation}`.
    """)


# ---------------------------------------------------------------------------
# Main export logic
# ---------------------------------------------------------------------------


def export_benchmark(
    release_root: Path,
    out_dir: Optional[Path] = None,
    *,
    emit_evidence_visible: bool = False,
    strict_leakage_check: bool = True,
    no_gold_reasoning: bool = False,
) -> dict[str, Any]:
    """Build one unified stage-reasoning benchmark data unit."""
    release_root = release_root.resolve()
    manifest_path = release_root / "manifest.json"
    if not manifest_path.exists():
        raise FileNotFoundError(
            f"release manifest not found at {manifest_path}; "
            "run build_dataset_release_v1 first."
        )
    release_manifest = _read_json(manifest_path)
    scenarios = release_manifest.get("scenarios") or []

    if out_dir is None:
        out_dir = release_root / "benchmarks" / "stage_reasoning"
    out_dir = out_dir.resolve()

    # Collect all windows first.  The public contract has one dataset unit;
    # quality-selection metadata is deliberately not emitted as a partition.
    all_samples: list[dict[str, Any]] = []
    source_rule_versions: set[str] = set()

    for row in scenarios:
        scenario = _load_scenario(release_root, row)
        if scenario is None:
            continue
        source_rule_versions.add(
            str(
                (
                    (scenario["stage_labels"].get("derivation") or {})
                    .get("rule_version")
                )
                or ""
            )
        )
        for sample in _window_samples_for_scenario(scenario):
            all_samples.append(sample)

    # Public IDs are assigned only after deterministic collection order is
    # known, so every generated publication uses sample_000001..N.
    for index, sample in enumerate(all_samples, 1):
        sample["sample_id"] = f"sample_{index:06d}"

    source_stage_derivation = _resolve_source_stage_derivation_version(
        source_rule_versions
    )

    stage_counts: Counter = Counter(s["stage"] for s in all_samples)
    total_samples = len(all_samples)

    # Build projected rows for each setting
    settings_to_emit = ["masked"]
    if emit_evidence_visible:
        settings_to_emit.append("evidence_visible")

    all_results: dict[str, Any] = {}

    for setting in settings_to_emit:
        if setting == "masked":
            setting_root = out_dir
        else:
            setting_root = out_dir / "evidence_visible"

        data_dir = setting_root / "data"
        data_dir.mkdir(parents=True, exist_ok=True)
        mi_rows: list[dict[str, Any]] = []
        gold_rows: list[dict[str, Any]] = []
        index_rows: list[dict[str, Any]] = []

        for line_no, sample in enumerate(all_samples, 1):
                sid = sample["sample_id"]
                scenario_id = sample["scenario_id"]
                start_seq = sample["start_seq"]
                end_seq = sample["end_seq"]
                stage = sample["stage"]

                # Sanitize spine for model_input
                sanitized_spine = sanitize_model_input_spine(
                    sample["spine_window"], setting=setting
                )

                mi = project_model_input(
                    sample_id=sid,
                    scenario_id=scenario_id,
                    start_seq=start_seq,
                    end_seq=end_seq,
                    spine_window=sanitized_spine,
                    setting=setting,
                )
                mi_rows.append(mi)

                # Gold
                reasoning_chain: list[dict[str, Any]] = []
                if not no_gold_reasoning:
                    reasoning_chain = build_gold_reasoning_chain(
                        stage=stage,
                        spine_window=sample["spine_window"],
                        narrative_roles_window=sample["roles_window"],
                        anchors_window=sample["anchors_window"],
                    )

                g = project_gold(
                    sample_id=sid,
                    scenario_id=scenario_id,
                    start_seq=start_seq,
                    end_seq=end_seq,
                    stage=stage,
                    stage_span=sample["stage_span"],
                    edge_stage_projection=sample["edge_stage_projection_window"],
                    gold_reasoning_chain=reasoning_chain,
                )
                gold_rows.append(g)

                # Sample index
                idx = project_sample_index(
                    sample_id=sid,
                    scenario_id=scenario_id,
                    stage=stage,
                    start_seq=start_seq,
                    end_seq=end_seq,
                    release_paths=sample["release_paths"],
                    line_no=line_no,
                )
                index_rows.append(idx)

        # Leakage check on masked model input
        if strict_leakage_check and setting == "masked":
            leakage_errors = validate_no_leakage(mi_rows, f"{setting}/data")
            if leakage_errors:
                raise ValueError("Leakage detected in model_input:\n" + "\n".join(leakage_errors))

        alignment_errors = validate_alignment(mi_rows, gold_rows, index_rows, f"{setting}/data")
        if alignment_errors:
            raise ValueError("Alignment errors in model_input/gold/sample_index:\n" + "\n".join(alignment_errors))

        _write_jsonl(data_dir / "model_input.jsonl", mi_rows)
        _write_jsonl(data_dir / "gold.jsonl", gold_rows)
        _write_jsonl(data_dir / "sample_index.jsonl", index_rows)
        _write_text(
            data_dir / "README.md",
            textwrap.dedent(f"""\
            # Unified benchmark data

            {len(mi_rows)} aligned samples. Stage distribution: {dict(sorted(stage_counts.items()))}

            `model_input.jsonl` is the blind model input; `gold.jsonl` is for scoring;
            `sample_index.jsonl` is the aligned index. No public partition is defined.
            """),
        )
        key = "evidence_visible" if setting == "evidence_visible" else "dataset"
        all_results[key] = {
            "model_input": _manifest_path(data_dir / "model_input.jsonl", release_root),
            "gold": _manifest_path(data_dir / "gold.jsonl", release_root),
            "sample_index": _manifest_path(data_dir / "sample_index.jsonl", release_root),
            "sample_count": len(mi_rows),
            "stage_counts": dict(sorted(stage_counts.items())),
        }

        # Setting-level manifest (evidence_visible gets its own)
        if setting == "evidence_visible":
            ev_manifest = {
                "schema_version": BENCHMARK_MANIFEST_SCHEMA,
                "setting": "evidence_visible",
                "note": (
                    "Assisted reasoning ablation — attack-related labels "
                    "retained in model_input. NOT the default blind evaluation."
                ),
                "dataset": all_results.get("evidence_visible"),
            }
            _write_json(setting_root / "manifest.json", ev_manifest)

    # Write top-level manifest
    bench_manifest = {
        "schema_version": BENCHMARK_MANIFEST_SCHEMA,
        "source_stage_derivation": source_stage_derivation,
        "source_benchmark_schema": BENCHMARK_MANIFEST_SCHEMA,
        "benchmark_design": {
            "task": "blind attack-chain stage reasoning",
            "labels": sorted(LEGAL_STAGES),
            "reasoning_protocol": list(REASONING_PROTOCOL),
            "reasoning_schema_version": REASONING_SCHEMA_VERSION,
            "reasoning_chain_structure": "EWVAA-style four-step claim-based chain",
            "default_reasoning_source": REASONING_SOURCE,
            "default_setting": "masked_blind",
            "input_policy": {
                "preserve_spine": True,
                "preserve_audit_context": True,
                "preserve_multisource_context": True,
                "preserve_applog_facts": True,
                "preserve_traffic_facts": True,
                "remove_stage_labels": True,
                "remove_narrative_role_labels": True,
                "remove_malicious_and_attack_related_labels": True,
            },
            "leakage_control": {
                "stage_in_sample_id_removed": True,
                "narrative_roles_removed_or_neutralized_from_model_input": True,
                "narrative_anchors_removed_or_neutralized_from_model_input": True,
                "substage_hints_removed_or_neutralized_from_model_input": True,
                "malicious_fields_masked_from_model_input": True,
                "attack_related_fields_masked_from_model_input": True,
            },
            "external_frameworks": [
                "MITRE ATT&CK for adversarial behavior semantics",
                "Cyber Kill Chain for lifecycle-style attack progression",
                "CVE/CWE for vulnerability and weakness context",
                "NIST incident handling guidance for evidence-driven analysis",
            ],
            "note": (
                "The external frameworks guide the reasoning protocol, "
                "but do not redefine the dataset's "
                "preparation/execution/result labels."
            ),
        },
        "dataset": {
            "sample_count": total_samples,
            "stage_counts": dict(sorted(stage_counts.items())),
            "model_input": "data/model_input.jsonl",
            "gold": "data/gold.jsonl",
            "sample_index": "data/sample_index.jsonl",
        },
        "alignment_checks": {
            "model_input_gold_sample_index_aligned": True,
            "sample_count": total_samples,
        },
    }

    if emit_evidence_visible:
        bench_manifest["evidence_visible"] = {
            "note": (
                "Assisted reasoning ablation. Attack-related labels "
                "retained in model_input. NOT the default blind evaluation."
            ),
            "dataset": all_results.get("evidence_visible"),
        }

    _write_json(out_dir / "manifest.json", bench_manifest)

    # Top-level README
    _write_text(
        out_dir / "README.md",
        _top_readme(
            total_samples,
            dict(sorted(stage_counts.items())),
            emit_evidence_visible,
            source_stage_derivation,
        ),
    )

    # The public exporter emits one canonical data unit.

    # Return manifest compatible with build_dataset_release_v1 integration
    return {
        **bench_manifest,
        "outputs": {
            "dataset": {
                "data_dir": _manifest_path(out_dir / "data", release_root),
                "model_input": _manifest_path(out_dir / "data" / "model_input.jsonl", release_root),
                "gold": _manifest_path(out_dir / "data" / "gold.jsonl", release_root),
                "sample_index": _manifest_path(out_dir / "data" / "sample_index.jsonl", release_root),
                "samples": total_samples,
            }
        },
        "stage_counts": dict(sorted(stage_counts.items())),
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Emit stage-reasoning benchmark data-pack (model_input / gold / "
            "sample_index) from a built dataset_release_v1/ tree."
        )
    )
    parser.add_argument(
        "--release-root",
        type=Path,
        required=True,
        help="Path to a built dataset_release_v1/ directory.",
    )
    parser.add_argument(
        "--benchmark-root",
        "--out-dir",
        type=Path,
        default=None,
        dest="out_dir",
        help=(
            "Output directory. Default: <release-root>/benchmarks/"
            "stage_reasoning/."
        ),
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Allow overwriting existing benchmark files.",
    )
    parser.add_argument(
        "--emit-evidence-visible-setting",
        action="store_true",
        default=False,
        dest="emit_evidence_visible",
        help=(
            "Emit an evidence_visible/ subtree where attack-related "
            "labels are retained in model_input (ablation setting)."
        ),
    )
    parser.add_argument(
        "--strict-leakage-check",
        action="store_true",
        default=True,
        dest="strict_leakage_check",
        help="Fail on residual leakage fields in model_input (default: on).",
    )
    parser.add_argument(
        "--no-strict-leakage-check",
        action="store_false",
        dest="strict_leakage_check",
        help="Disable strict leakage checking.",
    )
    parser.add_argument(
        "--no-gold-reasoning",
        action="store_true",
        default=False,
        help="Allow empty gold_reasoning_chain (only stage label gold).",
    )
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    manifest = export_benchmark(
        release_root=args.release_root,
        out_dir=args.out_dir,
        emit_evidence_visible=args.emit_evidence_visible,
        strict_leakage_check=args.strict_leakage_check,
        no_gold_reasoning=args.no_gold_reasoning,
    )
    dataset = manifest["dataset"]
    print(
        f"[stage_reasoning_benchmark_v2] "
        f"samples={dataset['sample_count']} "
        f"stages={dataset['stage_counts']}"
    )
    if args.emit_evidence_visible:
        print("[stage_reasoning_benchmark_v2] evidence_visible setting emitted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
