#!/usr/bin/env python3
"""Run SecLog-Bench prompts through an OpenAI-compatible chat endpoint.

The default invocation is a no-network preflight. Real inference requires
``--call-api`` and writes only to an explicit output directory.
"""
from __future__ import annotations

import argparse
import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as stream:
        for line_no, line in enumerate(stream, 1):
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError(f"{path}:{line_no}: expected a JSON object")
            rows.append(value)
    return rows


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        for row in rows:
            stream.write(json.dumps(row, ensure_ascii=False) + "\n")


def endpoint(base_url: str) -> str:
    value = base_url.rstrip("/")
    return value if value.endswith("/chat/completions") else value + "/chat/completions"


def call_chat(
    *,
    url: str,
    api_key: str,
    model: str,
    messages: list[dict[str, Any]],
    temperature: float,
    max_tokens: int,
    timeout: int,
    retries: int,
) -> str:
    payload = json.dumps(
        {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "response_format": {"type": "json_object"},
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=payload,
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        method="POST",
    )
    last_error: Exception | None = None
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                body = json.loads(response.read().decode("utf-8"))
            return str(body["choices"][0]["message"]["content"])
        except (urllib.error.URLError, urllib.error.HTTPError, KeyError, IndexError, json.JSONDecodeError) as exc:
            last_error = exc
            if attempt < retries:
                time.sleep(min(2**attempt, 8))
    raise RuntimeError(f"chat request failed after {retries + 1} attempts: {last_error}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prompt-pack", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True, help="Raw response JSONL written outside the release tree")
    parser.add_argument("--model", required=True)
    parser.add_argument("--base-url", default="https://api.openai.com/v1")
    parser.add_argument("--api-key-env", default="OPENAI_API_KEY")
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--max-tokens", type=int, default=2048)
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--retries", type=int, default=2)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--call-api", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    prompts = read_jsonl(args.prompt_pack)
    if args.limit is not None:
        prompts = prompts[: args.limit]
    ids = [str(row.get("sample_id") or "") for row in prompts]
    if not ids or any(not sid for sid in ids) or len(ids) != len(set(ids)):
        raise ValueError("prompt pack must contain non-empty unique sample_id values")

    if not args.call_api:
        print(json.dumps({
            "mode": "preflight_no_api",
            "prompt_count": len(prompts),
            "model": args.model,
            "endpoint": endpoint(args.base_url),
            "output": str(args.output),
        }, ensure_ascii=False, indent=2))
        return 0

    api_key = os.environ.get(args.api_key_env, "").strip()
    if not api_key:
        raise RuntimeError(f"missing API key environment variable: {args.api_key_env}")
    release_root = Path(__file__).resolve().parents[2]
    output = args.output.resolve()
    try:
        output.relative_to(release_root)
    except ValueError:
        pass
    else:
        raise RuntimeError("model outputs must be written outside the public release directory")

    completed: list[dict[str, Any]] = []
    completed_ids: set[str] = set()
    if args.resume and output.is_file():
        completed = read_jsonl(output)
        completed_ids = {str(row.get("sample_id") or "") for row in completed}
    elif output.exists():
        raise FileExistsError(f"refusing existing output without --resume: {output}")

    for row in prompts:
        sid = str(row["sample_id"])
        if sid in completed_ids:
            continue
        response = call_chat(
            url=endpoint(args.base_url),
            api_key=api_key,
            model=args.model,
            messages=list(row.get("messages") or []),
            temperature=args.temperature,
            max_tokens=args.max_tokens,
            timeout=args.timeout,
            retries=args.retries,
        )
        completed.append({"sample_id": sid, "response": response})
        completed_ids.add(sid)
        write_jsonl(output, completed)
        print(json.dumps({"completed": len(completed), "total": len(prompts), "sample_id": sid}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
