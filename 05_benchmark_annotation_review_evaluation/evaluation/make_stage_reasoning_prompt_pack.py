#!/usr/bin/env python3
"""Generate prompt packs for the unified public SecLog-Bench-216 evaluation.

Reads public ``evidence_windows.jsonl`` (or a canonical construction-time
``model_input.jsonl``) and emits one prompt per sample in either **direct** or
**cot** mode.

Prompt design uses evidence-referenced claims and leaves the organization of
the model's reasoning chain open. The reference chain is evaluated after
inference and is not an output template.

Does NOT read gold.jsonl — no label leakage into prompts.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Prompt templates
# ---------------------------------------------------------------------------

SYSTEM_MSG = (
    "You are a cybersecurity analyst specializing in attack-chain forensics. "
    "You analyze system audit logs, process execution traces, file operations, "
    "network connections, application logs, and network traffic to determine "
    "which phase of an attack lifecycle a given evidence window belongs to. "
    "You must base all conclusions strictly on the provided evidence. "
    "Do not fabricate events, processes, files, or network connections that "
    "are not present in the input."
)

_STAGE_DEFS = """\
Allowed labels (choose exactly ONE):
- preparation — Pre-exploitation setup: reconnaissance, scanning, resource staging, or initial access attempts that precede the primary attack.
- execution — Active exploitation: the core malicious actions in the attack chain (e.g. command injection, request content delivery, vulnerability trigger).
- result — Post-exploitation outcomes: data exfiltration, persistence establishment, lateral movement, or other consequences of the executed attack.
- stage_unclosed — The window is attack-related, but the visible evidence does not sufficiently close preparation, execution, or result. This is a stage-closure label, not a fourth real attack lifecycle stage."""

_RULES_SHARED = """\
Rules:
1. The input is strict blind visible evidence for an attack-chain evidence window — your task is to determine the STAGE, not whether it is an attack.
2. Base your decision ONLY on the evidence provided. Do NOT use external CVE knowledge to override observable evidence.
3. Do NOT fabricate processes, files, network connections, or log entries not present in the input.
4. Do NOT use scenario names, vulnerability descriptions, service/scenario metadata, or derived malicious / attack-related labels as shortcuts.
5. The model cannot see `label.stage`, `gold.jsonl`, or `sample_index.jsonl`; do not assume them.
6. `stage_unclosed` means the window is attack-related but the visible evidence does not sufficiently close preparation, execution, or result; it does not prove absolute safety.
7. You may use general cybersecurity knowledge to interpret process / file / network / applog / traffic behavior.
8. If uncertain, still choose a label and lower confidence.
9. Output ONLY a valid JSON object — no markdown, no ```json code fences, no extra text."""

_DIRECT_OUTPUT_FMT = """\
Required output (JSON only):
{{"sample_id": "<same as input>", "predicted_stage": "<preparation|execution|result|stage_unclosed>", "confidence": <0.0-1.0>}}"""

_COT_STEPS = """\
Reasoning guidance (the organization is free-form; no fixed number or names of
steps are required):
- State the visible facts and cross-source relations that support the label.
- Explain stage-closure or stage-unclosed conditions without inventing hidden
  payloads, effects, or outcomes.
- Make each substantive claim independently checkable and cite one or more
  real visible seq / edge_id values from the input spine.
- You may use any clear claim grouping or step names. Do not add rich JSON
  fields such as source summaries or entity lists to the output."""

_COT_OUTPUT_FMT = """\
Required output (JSON only, no markdown):
{{"task_mode": "stage_prediction", "sample_id": "<same as input>", "predicted_stage": "<preparation|execution|result|stage_unclosed>", "reasoning_chain": [{{"claim": "<free-form evidence-grounded claim>", "evidence_refs": [{{"seq": <int>, "edge_id": "..."}}]}}], "confidence": <0.0-1.0>}}

The reasoning_chain may be empty, and its claims may use any organization. If
you include a step name, it is treated as descriptive only."""


# ---------------------------------------------------------------------------
# Compact representation helpers
# ---------------------------------------------------------------------------


def _compact_edge(edge: dict[str, Any]) -> dict[str, Any]:
    """Reduce a spine edge to core behavioral fields for token efficiency."""
    # Public release windows expose normalized fields at edge level, while
    # construction-time inputs may keep the same fields under ``attrs``.
    attrs = edge.get("attrs") or {}
    ac = edge.get("audit_context") or []
    mc = edge.get("multisource_context") or {}
    applog = mc.get("applog") or []
    traffic = mc.get("traffic") or []
    out: dict[str, Any] = {
        "seq": edge.get("seq"),
        "edge_id": edge.get("edge_id"),
        "subject": edge.get("subject"),
        "relation": edge.get("relation"),
        "object": edge.get("object"),
    }
    for k in ("evt_num", "timestamp", "raw_evt_type", "container_id", "proc_name", "fd_name"):
        if k in edge:
            out[k] = edge[k]
        elif k in attrs:
            out[k] = attrs[k]
    if ac:
        out["audit_context_count"] = len(ac)
    if applog:
        out["applog_count"] = len(applog)
        out["applog_messages"] = [
            a.get("message", "")[:200] for a in applog[:3]
        ]
    if traffic:
        out["traffic_count"] = len(traffic)
    return out


def _compact_sample_input(sample: dict[str, Any]) -> dict[str, Any]:
    """Build a compact prompt view from public or canonical evidence rows."""
    inp = sample.get("input") or {}
    spine = sample.get("selected_spine") or inp.get("spine") or []
    return {
        "sample_id": sample.get("sample_id"),
        "window": sample.get("window"),
        "spine_edge_count": len(spine),
        "spine": [_compact_edge(e) for e in spine],
    }


# ---------------------------------------------------------------------------
# Prompt builder
# ---------------------------------------------------------------------------


def build_sample_prompt(
    sample: dict[str, Any],
    mode: str = "cot",
    compact: bool = False,
) -> dict[str, Any]:
    """Build prompt dict for one model_input sample.

    Returns a prompt record with both a chat ``messages`` list and the
    human-readable system/user fields used by inspection tools.
    """
    sample_id = sample.get("sample_id", "unknown")

    if compact:
        evidence_json = json.dumps(_compact_sample_input(sample), ensure_ascii=False, indent=2)
    else:
        evidence_json = json.dumps(sample, ensure_ascii=False, indent=2)

    if mode == "direct":
        user_parts = [
            "# Attack-Chain Stage Classification (Direct)\n",
            _STAGE_DEFS, "\n\n",
            _RULES_SHARED, "\n\n",
            "## Evidence Window\n\n",
            evidence_json, "\n\n",
            _DIRECT_OUTPUT_FMT,
        ]
        expected_format = {
            "sample_id": sample_id,
            "predicted_stage": "preparation|execution|result|stage_unclosed",
            "confidence": 0.0,
        }
    else:
        user_parts = [
            "# Attack-Chain Stage Reasoning (Chain-of-Thought)\n",
            _STAGE_DEFS, "\n\n",
            _COT_STEPS, "\n\n",
            _RULES_SHARED, "\n\n",
            "## Evidence Window\n\n",
            evidence_json, "\n\n",
            _COT_OUTPUT_FMT,
        ]
        expected_format = {
            "sample_id": sample_id,
            "predicted_stage": "preparation|execution|result|stage_unclosed",
            "reasoning_chain": "[free-form claims, optional]",
            "confidence": 0.0,
        }

    return {
        "sample_id": sample_id,
        "mode": mode,
        "system": SYSTEM_MSG,
        "user": "".join(user_parts),
        "expected_output_format": expected_format,
    }


# ---------------------------------------------------------------------------
# IO helpers
# ---------------------------------------------------------------------------


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            s = line.strip()
            if s:
                rows.append(json.loads(s))
    return rows


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with path.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False))
            fh.write("\n")
            n += 1
    return n


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Generate prompt packs for the unified public SecLog-Bench-216 dataset.",
        epilog=(
            "Examples:\n"
            "  # Evidence-referenced reasoning prompt pack\n"
            "  python make_stage_reasoning_prompt_pack.py \\\n"
            "    --model-input ../SecLog-Bench-216/data/evidence_windows.jsonl \\\n"
            "    --output prompts_cot.jsonl --mode cot\n"
            "\n"
            "  # Direct prompt pack, compact, first 5 samples\n"
            "  python make_stage_reasoning_prompt_pack.py \\\n"
            "    --model-input ../SecLog-Bench-216/data/evidence_windows.jsonl \\\n"
            "    --output prompts_direct.jsonl --mode direct --compact --limit 5\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--model-input", type=Path, required=True,
                    help="Path to evidence_windows.jsonl or canonical model_input.jsonl")
    p.add_argument("--output", type=Path, required=True,
                    help="Output prompt-pack JSONL path")
    p.add_argument("--mode", choices=["direct", "cot"], default="cot",
                    help="Prompt mode: direct (label only) or cot (free-form reasoning claims)")
    p.add_argument("--compact", action="store_true",
                    help="Compact spine representation to reduce token count")
    p.add_argument("--include-system-message", action="store_true",
                    help="Include separate system/user fields alongside the chat messages")
    p.add_argument("--limit", type=int, default=None,
                    help="Process only first N samples (for debugging)")
    p.add_argument("--max-spine-edges", type=int, default=None,
                    help="Warn (but do not truncate) if a sample exceeds this spine edge count")
    return p.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)

    samples = _read_jsonl(args.model_input)
    if args.limit is not None:
        samples = samples[:args.limit]

    rows: list[dict[str, Any]] = []
    for i, sample in enumerate(samples, 1):
        spine_count = len(sample.get("selected_spine") or (sample.get("input") or {}).get("spine") or [])
        if args.max_spine_edges and spine_count > args.max_spine_edges:
            print(
                f"[warn] sample {sample.get('sample_id','?')} has {spine_count} spine edges "
                f"(> --max-spine-edges {args.max_spine_edges})",
                file=sys.stderr,
            )

        prompt_data = build_sample_prompt(sample, mode=args.mode, compact=args.compact)

        if args.include_system_message:
            row = {
                "sample_id": prompt_data["sample_id"],
                "mode": prompt_data["mode"],
                "system": prompt_data["system"],
                "user": prompt_data["user"],
                "messages": [
                    {"role": "system", "content": prompt_data["system"]},
                    {"role": "user", "content": prompt_data["user"]},
                ],
                "expected_output_format": prompt_data["expected_output_format"],
            }
        else:
            row = {
                "sample_id": prompt_data["sample_id"],
                "mode": prompt_data["mode"],
                "prompt": prompt_data["system"] + "\n\n" + prompt_data["user"],
                "messages": [
                    {"role": "system", "content": prompt_data["system"]},
                    {"role": "user", "content": prompt_data["user"]},
                ],
                "expected_output_format": prompt_data["expected_output_format"],
            }
        rows.append(row)

    n = _write_jsonl(args.output, rows)
    print(f"[prompt_pack] wrote {n} prompts to {args.output} (mode={args.mode})", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
