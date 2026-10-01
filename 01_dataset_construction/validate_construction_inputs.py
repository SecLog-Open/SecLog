#!/usr/bin/env python3
"""Validate public scenario inputs without starting Docker or capture tools."""
from __future__ import annotations

import json
from pathlib import Path

import yaml

from schema import Scene


ROOT = Path(__file__).resolve().parent
EXAMPLE_ROOT = ROOT / "example"


def main() -> int:
    scene_paths = sorted(EXAMPLE_ROOT.rglob("scene.yml"))
    invalid: list[dict[str, str]] = []
    for path in scene_paths:
        try:
            payload = yaml.safe_load(path.read_text(encoding="utf-8"))
            Scene.model_validate(payload)
        except Exception as exc:  # report every independent public scene
            invalid.append({"path": path.relative_to(ROOT).as_posix(), "error": str(exc)})

    checks = {
        "all_scene_configs_schema_valid": not invalid,
        "required_lua_parser_present": (ROOT / "print_fields_new.lua").is_file(),
        "poetry_lock_present": (ROOT / "poetry.lock").is_file(),
    }
    result = {
        "schema_version": "seclog.dataset_construction_input_validation.v1",
        "checks": checks,
        "validation_passed": all(checks.values()),
        "invalid_scene_configs": invalid,
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["validation_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
