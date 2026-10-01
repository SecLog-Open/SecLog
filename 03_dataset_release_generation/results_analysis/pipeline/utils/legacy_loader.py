from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
from types import ModuleType


def load_legacy_module(current_file: str, legacy_filename: str, module_name: str) -> ModuleType:
    pipeline_dir = Path(current_file).resolve().parent
    legacy_path = pipeline_dir.parent / legacy_filename
    spec = importlib.util.spec_from_file_location(module_name, legacy_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Unable to load legacy module: {legacy_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module
