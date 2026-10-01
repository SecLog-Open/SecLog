from __future__ import annotations

from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[3]
RESULTS_ANALYSIS_DIR = PROJECT_ROOT / "results_analysis"
CHAIN_DIR_NAME = "chain"
LEGACY_CHAIN_DIR_NAME = "chain_v1"


def scenario_raw_sysdig_dir(scenario_dir: Path) -> Path:
    return scenario_dir / "raw" / "sysdig"


def scenario_chain_dir(scenario_dir: Path) -> Path:
    chain_dir = scenario_dir / CHAIN_DIR_NAME
    if chain_dir.exists():
        return chain_dir
    legacy_chain_dir = scenario_dir / LEGACY_CHAIN_DIR_NAME
    if legacy_chain_dir.exists():
        return legacy_chain_dir
    return chain_dir


def scenario_index_dir(scenario_dir: Path) -> Path:
    return scenario_dir / "index"


def rules_file_path() -> Path:
    return RESULTS_ANALYSIS_DIR / "audit_stats" / "triple_rules_v1_1.json"
