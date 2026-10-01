#!/usr/bin/env python3
"""Normalise raw model outputs into evaluator-compatible predictions.jsonl.

Handles:
* Already-valid prediction JSON
* Formal `task_mode=stage_prediction` prediction rows
* EWVAA reference rows by explicitly rejecting them as non-prediction input
* ``{"sample_id": "...", "response": "..."}`` wrapper format
* Markdown ```json ... ``` code fences in model output
* Chinese / English stage synonym normalisation
* OpenAI-style chat completion response objects
* Preservation of free-form reasoning claims and optional step labels

Identifiable model rows without a canonical stage are retained as
``invalid_stage`` predictions so the full benchmark join remains intact. They are also written to
``invalid_outputs.jsonl`` for inspection and count as incorrect stage
predictions. No reasoning claim is fabricated.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Optional

LEGAL_STAGES = frozenset({"preparation", "execution", "result", "stage_unclosed"})

# Chinese / English synonyms → canonical label
_STAGE_SYNONYMS: dict[str, str] = {
    "preparation": "preparation",
    "prep": "preparation",
    "准备": "preparation",
    "准备阶段": "preparation",
    "execution": "execution",
    "execute": "execution",
    "exploit": "execution",
    "exploitation": "execution",
    "执行": "execution",
    "攻击执行": "execution",
    "result": "result",
    "impact": "result",
    "consequence": "result",
    "结果": "result",
    "后果": "result",
    "stage_unclosed": "stage_unclosed",
    "stage unclosed": "stage_unclosed",
    "unclosed": "stage_unclosed",
    "未闭合": "stage_unclosed",
    "阶段未闭合": "stage_unclosed",
}

_JSON_FENCE_RE = re.compile(r"```(?:json)?\s*\n?(.*?)\n?\s*```", re.DOTALL)


# ---------------------------------------------------------------------------
# Extraction helpers
# ---------------------------------------------------------------------------


def _extract_json_from_text(text: str) -> Optional[dict[str, Any]]:
    """Try to extract a JSON object from possibly messy model output."""
    text = text.strip()

    # 1. Try direct parse first
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return obj
        return None
    except json.JSONDecodeError:
        pass

    # 2. Try extracting from markdown code fence
    m = _JSON_FENCE_RE.search(text)
    if m:
        try:
            obj = json.loads(m.group(1))
            if isinstance(obj, dict):
                return obj
            return None
        except json.JSONDecodeError:
            pass

    # 3. Try finding first { ... last }
    start = text.find("{")
    end = text.rfind("}")
    if start >= 0 and end > start:
        try:
            obj = json.loads(text[start:end + 1])
            if isinstance(obj, dict):
                return obj
        except json.JSONDecodeError:
            pass

    return None


def _normalise_stage(raw: Any) -> Optional[str]:
    if raw is None:
        return None
    s = str(raw).strip().lower()
    return _STAGE_SYNONYMS.get(s)


def _normalise_reasoning_chain(chain: Any) -> list[dict[str, Any]]:
    if not isinstance(chain, list):
        return []
    out: list[dict[str, Any]] = []
    for step in chain:
        if not isinstance(step, dict):
            continue
        entry: dict[str, Any] = {}
        if "step" in step and isinstance(step["step"], str):
            raw_step = step["step"].strip()
            # Model reasoning does not have to use the reference step labels.
            entry["step"] = raw_step
        if "claim" in step:
            entry["claim"] = str(step.get("claim") or "")
        refs = step.get("evidence_refs")
        if refs is None:
            refs = []
        if not isinstance(refs, list):
            refs = []
        clean_refs: list[dict[str, Any]] = []
        for ref in refs:
            if isinstance(ref, dict):
                clean_ref: dict[str, Any] = {}
                if "seq" in ref:
                    try:
                        clean_ref["seq"] = int(ref["seq"])
                    except (TypeError, ValueError):
                        clean_ref["seq"] = None
                if "edge_id" in ref:
                    clean_ref["edge_id"] = str(ref["edge_id"]) if ref["edge_id"] is not None else None
                clean_refs.append(clean_ref)
        entry["evidence_refs"] = clean_refs
        out.append(entry)
    return out


def _normalise_confidence(raw: Any) -> Optional[float]:
    if raw is None:
        return None
    try:
        v = float(raw)
        if 0.0 <= v <= 1.0:
            return round(v, 4)
        return None
    except (TypeError, ValueError):
        return None


def _extract_chat_completion_content(raw_row: dict[str, Any]) -> Optional[str]:
    """Extract text from a raw OpenAI-compatible chat completion object."""
    choices = raw_row.get("choices")
    if not isinstance(choices, list):
        return None
    for choice in choices:
        if not isinstance(choice, dict):
            continue
        message = choice.get("message")
        if not isinstance(message, dict):
            continue
        content = message.get("content")
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            parts: list[str] = []
            for item in content:
                if isinstance(item, str):
                    parts.append(item)
                elif isinstance(item, dict) and isinstance(item.get("text"), str):
                    parts.append(item["text"])
            if parts:
                return "\n".join(parts)
    return None


def normalise_single(raw_row: Any) -> tuple[Optional[dict[str, Any]], Optional[dict[str, Any]]]:
    """Normalise one raw output row.

    Returns ``(prediction_or_None, invalid_row_or_None)``.
    """
    if not isinstance(raw_row, dict):
        return None, {
            "sample_id": None,
            "reason": "input_is_not_an_object",
            "raw_preview": str(raw_row)[:500],
        }
    sample_id = raw_row.get("sample_id")

    task_mode = raw_row.get("task_mode")
    if task_mode == "ewvaa_reference_reasoning":
        return None, {
            "sample_id": sample_id,
            "reason": "ewvaa_reference_reasoning_is_not_model_prediction",
            "raw_preview": str(raw_row)[:500],
        }

    if "response" in raw_row:
        response_text = raw_row["response"]
    elif "output_raw" in raw_row:
        response_text = raw_row["output_raw"]
    elif "choices" in raw_row:
        response_text = _extract_chat_completion_content(raw_row)
    else:
        response_text = raw_row
    if isinstance(response_text, str):
        parsed = _extract_json_from_text(response_text)
    elif isinstance(response_text, dict):
        parsed = response_text
    else:
        parsed = None

    if parsed is not None and parsed.get("task_mode") == "ewvaa_reference_reasoning":
        return None, {
            "sample_id": sample_id,
            "reason": "ewvaa_reference_reasoning_is_not_model_prediction",
            "raw_preview": str(raw_row)[:500],
        }

    if sample_id is None and parsed is not None:
        sample_id = parsed.get("sample_id")
    if not isinstance(sample_id, str) or not sample_id.strip():
        return None, {
            "sample_id": None,
            "reason": "missing_sample_id",
            "raw_preview": str(raw_row)[:500],
        }

    stage = _normalise_stage(parsed.get("predicted_stage")) if parsed is not None else None
    invalid = None
    if stage is None:
        invalid = {
            "sample_id": sample_id,
            "reason": "json_extraction_failed" if parsed is None else "unparseable_predicted_stage",
            "raw_value": str(parsed.get("predicted_stage")) if parsed is not None else None,
            "raw_preview": str(raw_row)[:500],
        }

    chain = _normalise_reasoning_chain(parsed.get("reasoning_chain")) if parsed is not None else []
    confidence = _normalise_confidence(parsed.get("confidence")) if parsed is not None else None

    return {
        "task_mode": "stage_prediction",
        "sample_id": sample_id,
        "predicted_stage": stage or "invalid_stage",
        "reasoning_chain": chain,
        "confidence": confidence,
    }, invalid


# ---------------------------------------------------------------------------
# IO
# ---------------------------------------------------------------------------


def _read_jsonl(path: Path) -> list[Any]:
    rows: list[Any] = []
    with path.open("r", encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, 1):
            s = line.strip()
            if not s:
                continue
            try:
                rows.append(json.loads(s))
            except json.JSONDecodeError:
                rows.append({"_parse_error_line": line_no, "raw": s[:500]})
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
        description="Normalise raw model outputs into evaluator-compatible predictions.jsonl.",
        epilog=(
            "Supports:\n"
            "  - Direct JSON predictions\n"
            "  - {sample_id, response} wrapper format\n"
            "  - Markdown ```json code blocks\n"
            "  - Chinese / English stage synonym normalisation\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--input", type=Path, required=True,
                    help="Raw model output JSONL (or predictions JSONL)")
    p.add_argument("--output", type=Path, required=True,
                    help="Normalised predictions.jsonl path")
    p.add_argument("--invalid-output", type=Path, default=None,
                    help="Diagnostics for invalid stages and rejected rows (default: <output_dir>/invalid_outputs.jsonl)")
    return p.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)

    raw_rows = _read_jsonl(args.input)
    invalid_path = args.invalid_output or (args.output.parent / "invalid_outputs.jsonl")

    predictions: list[dict[str, Any]] = []
    invalids: list[dict[str, Any]] = []

    for raw_row in raw_rows:
        if isinstance(raw_row, dict) and "_parse_error_line" in raw_row:
            invalids.append({
                "sample_id": None,
                "reason": "json_parse_error",
                "line_number": raw_row["_parse_error_line"],
                "raw_preview": raw_row.get("raw", "")[:500],
            })
            continue
        pred, inv = normalise_single(raw_row)
        if pred is not None:
            predictions.append(pred)
        if inv is not None:
            invalids.append(inv)

    n_pred = _write_jsonl(args.output, predictions)
    n_inv = _write_jsonl(invalid_path, invalids)
    n_invalid_stage = sum(row["predicted_stage"] == "invalid_stage" for row in predictions)

    print(
        f"[normalise] input={len(raw_rows)} predictions={n_pred} "
        f"valid_stages={n_pred - n_invalid_stage} retained_invalid_stages={n_invalid_stage} "
        f"rejected_rows={len(raw_rows) - n_pred} diagnostics={n_inv} output={args.output}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
