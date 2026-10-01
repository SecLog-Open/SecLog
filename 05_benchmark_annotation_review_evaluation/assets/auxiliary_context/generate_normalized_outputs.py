import json
import os
import re
from collections import defaultdict
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
BASE = SCRIPT_DIR
SOURCE_ROOT = (
    SCRIPT_DIR.parents[2]
    / "04_benchmark_window_selection"
    / "auxiliary_context"
    / "vulnerability_facts_seed"
)
RAW = SOURCE_ROOT / "scenario_vulnerability_facts.json"
OUT = BASE / "normalized"

POLICY = {
    "role": "auxiliary_vulnerability_context",
    "can_support": [
        "checking whether a vulnerability mechanism term is factually valid",
        "checking whether observed behavior is consistent with public vulnerability facts",
    ],
    "cannot_support": [
        "stage assignment without primary evidence",
        "inventing unseen payloads",
        "inventing unseen attack results",
        "adding CVE facts to model_input",
    ],
}

RISK_TERMS = [
    "RCE",
    "XXE",
    "SQL injection",
    "command injection",
    "code injection",
    "exploit",
    "payload",
    "attacker",
    "execute",
    "injection",
    "curl",
    "docker",
    "shell obtained",
    "data exfiltration",
    "privilege escalation",
    "persistence installed",
    "attack succeeded",
]

REQUIRED_FIELDS = [
    "scenario_id",
    "original_scenario_id",
    "scenario_type",
    "cve_ids",
    "product_hint",
    "language_or_stack",
    "sources",
    "official_summary",
    "confirmed_weakness",
    "confirmed_impact",
    "affected_component",
    "allowed_terms",
    "disallowed_if_not_observed",
    "annotation_use_policy",
]


def path_text(path: Path) -> str:
    try:
        return path.relative_to(BASE).as_posix()
    except ValueError:
        try:
            return Path(os.path.relpath(path, BASE)).as_posix()
        except ValueError:
            return path.as_posix()


def term_hits(text: str) -> list[str]:
    return [term for term in RISK_TERMS if re.search(re.escape(term), text or "", re.IGNORECASE)]


def source_status(sources: list[dict]) -> dict:
    ok_types = {source.get("source_type") for source in sources if source.get("status") == "ok"}
    failed_sources = [
        {
            "source_type": source.get("source_type", ""),
            "url": source.get("url", ""),
            "status": source.get("status", ""),
            "error": source.get("error", ""),
        }
        for source in sources
        if source.get("status") != "ok"
    ]
    return {
        "has_nvd": "NVD" in ok_types,
        "has_cve_program": "CVE_PROGRAM" in ok_types,
        "has_vulhub": "VULHUB" in ok_types,
        "has_owasp": "OWASP" in ok_types,
        "has_local_context": "LOCAL_SCENARIO_CONTEXT" in ok_types,
        "failed_sources": failed_sources,
    }


def category(blocked_terms: list[str], weaknesses: list[dict]) -> str:
    weakness_text = " ".join(item.get("term", "") for item in weaknesses)
    lowered_terms = {term.lower() for term in blocked_terms}
    if "sql injection" in lowered_terms or "CWE-89" in weakness_text:
        return "SQL-injection weakness metadata"
    if "xxe" in lowered_terms or "CWE-611" in weakness_text:
        return "XML external entity weakness metadata"
    if "command injection" in lowered_terms or "CWE-78" in weakness_text:
        return "command-injection weakness metadata"
    if "code injection" in lowered_terms or "CWE-94" in weakness_text or "CWE-95" in weakness_text:
        return "code-execution or code-injection weakness metadata"
    if "rce" in lowered_terms:
        return "remote-code-execution impact metadata"
    if "CWE-22" in weakness_text:
        return "path traversal or local file inclusion weakness metadata"
    if "CWE-79" in weakness_text:
        return "cross-site scripting weakness metadata"
    if "CWE-502" in weakness_text:
        return "unsafe deserialization weakness metadata"
    if "CWE-918" in weakness_text:
        return "server-side request forgery weakness metadata"
    if any(term in weakness_text for term in ["CWE-863", "CWE-862", "CWE-284", "CWE-425"]):
        return "access-control or forced-browsing weakness metadata"
    return "public vulnerability metadata"


def safe_annotation_summary(scenario: dict, blocked_terms: list[str]) -> str:
    scenario_id = scenario["scenario_id"]
    product = scenario.get("product_hint") or scenario_id
    if scenario_id == "juice-shop":
        return "OWASP Juice Shop is a non-CVE training application context. It may be used only as auxiliary background for the lab application and must not be used for stage assignment. This auxiliary fact must not be used without primary log evidence."
    if scenario_id in {"sandworm", "multi-jump"}:
        return f"{product} is a composite local lab context, not a CVE fact source. It may be used only as auxiliary scenario background and must not be used for stage assignment. This auxiliary fact must not be used without primary log evidence."
    extra = ""
    if scenario_id == "vulhub/cmsms/CVE-2021-26120-lab":
        extra = " The scenario documentation source is missing and requires manual review."
    if scenario_id == "vulhub/solr/CVE-2017-12629-RCE":
        extra = " This RCE variant is kept separate from the XXE scenario."
    if scenario_id == "vulhub/solr/CVE-2017-12629-XXE":
        extra = " This XXE variant is kept separate from the RCE scenario."
    return f"{product} is associated with {category(blocked_terms, scenario.get('confirmed_weakness', []))}.{extra} This auxiliary fact must not be used without primary log evidence."


def scenario_doc_summary(scenario_id: str, status: dict) -> str:
    if status["has_vulhub"]:
        return f"Vulhub scenario documentation is present for {scenario_id}."
    if status["has_local_context"] or status["has_owasp"]:
        return f"Local or OWASP context files are present for {scenario_id}."
    if status["failed_sources"]:
        return "Scenario documentation source failed and requires manual review."
    return ""


def main() -> None:
    raw_doc = json.loads(RAW.read_text(encoding="utf-8"))
    OUT.mkdir(parents=True, exist_ok=True)
    scenarios = raw_doc["scenarios"]
    missing_required_fields = []
    missing_cache_files = []
    normalized_scenarios = []
    report_items = []
    risky_terms = []
    empty_or_weak_context = []
    non_cve_scenarios = []
    needs_manual_review = []
    failed_source_count = 0
    sanitized_summary_count = 0

    for scenario in scenarios:
        scenario_id = scenario["scenario_id"]
        official_summary = scenario.get("official_summary", "") or ""
        blocked_terms = term_hits(official_summary)
        status = source_status(scenario.get("sources", []))
        failed_source_count += len(status["failed_sources"])

        missing = [field for field in REQUIRED_FIELDS if field not in scenario]
        if missing:
            missing_required_fields.append({"scenario_id": scenario_id, "fields": missing})

        for source in scenario.get("sources", []):
            local_cache_path = source.get("local_cache_path") or ""
            if local_cache_path and not (SOURCE_ROOT / local_cache_path).exists():
                missing_cache_files.append({"scenario_id": scenario_id, "local_cache_path": local_cache_path})

        non_cve_context = scenario_id in {"juice-shop", "sandworm", "multi-jump"} or scenario.get("scenario_type") != "cve"
        scenario_doc_missing = (
            scenario_id == "vulhub/cmsms/CVE-2021-26120-lab" and bool(status["failed_sources"])
        ) or (scenario.get("scenario_type") == "cve" and not status["has_vulhub"])
        needs_review = non_cve_context or scenario_doc_missing
        official_summary_empty = official_summary == ""
        summary_was_sanitized = bool(blocked_terms)

        if needs_review:
            needs_manual_review.append(scenario_id)
        if non_cve_context:
            non_cve_scenarios.append(
                {
                    "scenario_id": scenario_id,
                    "scenario_type": scenario.get("scenario_type"),
                    "cve_ids": scenario.get("cve_ids", []),
                }
            )
        if summary_was_sanitized:
            sanitized_summary_count += 1
            risky_terms.append(
                {
                    "scenario_id": scenario_id,
                    "field": "official_summary",
                    "blocked_or_risky_terms": blocked_terms,
                }
            )
        if official_summary_empty or (not scenario.get("confirmed_weakness") and not scenario.get("confirmed_impact")):
            empty_or_weak_context.append(
                {
                    "scenario_id": scenario_id,
                    "official_summary_empty": official_summary_empty,
                    "confirmed_weakness_count": len(scenario.get("confirmed_weakness", [])),
                    "confirmed_impact_count": len(scenario.get("confirmed_impact", [])),
                }
            )

        actions = []
        reasons = []
        if summary_was_sanitized:
            actions.append("sanitized_official_summary")
            reasons.append("official_summary contained risky or mechanism terms")
        if non_cve_context:
            actions.append("marked_non_cve_context_only")
            reasons.append("scenario is non-CVE or composite context")
        if scenario_doc_missing:
            actions.append("marked_missing_scenario_doc")
            reasons.append("scenario documentation source missing or failed")

        report_items.append(
            {
                "scenario_id": scenario_id,
                "status": "needs_manual_review" if needs_review else "normalized_with_warnings" if actions else "ok",
                "actions": actions,
                "reasons": reasons,
            }
        )

        normalized_scenarios.append(
            {
                "scenario_id": scenario_id,
                "original_scenario_id": scenario.get("original_scenario_id", scenario_id),
                "scenario_type": scenario.get("scenario_type", "local_scenario"),
                "cve_ids": scenario.get("cve_ids", []),
                "product_hint": scenario.get("product_hint", ""),
                "language_or_stack": scenario.get("language_or_stack", ""),
                "source_status": status,
                "safe_annotation_summary": safe_annotation_summary(scenario, blocked_terms),
                "official_fact_summary": official_summary[:500],
                "scenario_doc_summary": scenario_doc_summary(scenario_id, status),
                "confirmed_weakness": scenario.get("confirmed_weakness", []),
                "confirmed_impact": scenario.get("confirmed_impact", []),
                "affected_component": scenario.get("affected_component", ""),
                "allowed_terms": scenario.get("allowed_terms", []),
                "blocked_or_risky_terms": blocked_terms,
                "disallowed_if_not_observed": scenario.get(
                    "disallowed_if_not_observed",
                    [
                        "payload executed",
                        "shell obtained",
                        "data exfiltration",
                        "privilege escalation",
                        "persistence installed",
                    ],
                ),
                "quality_flags": {
                    "needs_manual_review": needs_review,
                    "non_cve_context_only": non_cve_context,
                    "summary_was_sanitized": summary_was_sanitized,
                    "official_summary_empty": official_summary_empty,
                    "scenario_doc_missing": scenario_doc_missing,
                    "contains_risky_mechanism_terms": summary_was_sanitized,
                },
                "annotation_use_policy": scenario.get("annotation_use_policy", POLICY),
                "sources": scenario.get("sources", []),
            }
        )

    cve_map = defaultdict(list)
    for scenario in normalized_scenarios:
        for cve_id in scenario["cve_ids"]:
            cve_map[cve_id].append(scenario["scenario_id"])
    duplicate_cve_multi_scenario = [
        {"cve_id": cve_id, "scenario_ids": scenario_ids}
        for cve_id, scenario_ids in sorted(cve_map.items())
        if len(scenario_ids) > 1
    ]

    normalized_doc = {
        "schema_version": "scenario_vulnerability_facts.normalized.v0.1",
        "created_from": path_text(RAW),
        "normalization_policy": {
            "network_access": False,
            "raw_seed_preserved": True,
            "prompt_safe_field": "safe_annotation_summary",
            "required_warning": "This auxiliary fact must not be used without primary log evidence.",
        },
        "scenarios": normalized_scenarios,
    }
    schema_doc = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "scenario_vulnerability_facts.normalized",
        "type": "object",
        "required": ["schema_version", "created_from", "normalization_policy", "scenarios"],
        "properties": {
            "schema_version": {"type": "string"},
            "created_from": {"type": "string"},
            "normalization_policy": {"type": "object"},
            "scenarios": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": [
                        "scenario_id",
                        "original_scenario_id",
                        "scenario_type",
                        "cve_ids",
                        "product_hint",
                        "language_or_stack",
                        "source_status",
                        "safe_annotation_summary",
                        "official_fact_summary",
                        "scenario_doc_summary",
                        "confirmed_weakness",
                        "confirmed_impact",
                        "affected_component",
                        "allowed_terms",
                        "blocked_or_risky_terms",
                        "disallowed_if_not_observed",
                        "quality_flags",
                        "annotation_use_policy",
                        "sources",
                    ],
                },
            },
        },
    }
    normalization_report = {
        "input_file": path_text(RAW),
        "output_file": path_text(OUT / "scenario_vulnerability_facts.normalized.json"),
        "total_scenarios": len(scenarios),
        "actions": [
            "created_normalized_directory",
            "generated_prompt_safe_summary",
            "preserved_raw_seed",
            "recorded_duplicate_cve_multi_scenario",
            "generated_quality_audit",
        ],
        "items": report_items,
    }
    quality_audit_report = {
        "total_scenarios": len(scenarios),
        "schema_valid": not missing_required_fields,
        "source_cache_valid": not missing_cache_files,
        "missing_required_fields": missing_required_fields,
        "missing_cache_files": missing_cache_files,
        "needs_manual_review": needs_manual_review,
        "risky_terms": risky_terms,
        "empty_or_weak_context": empty_or_weak_context,
        "non_cve_scenarios": non_cve_scenarios,
        "duplicate_cve_multi_scenario": duplicate_cve_multi_scenario,
        "summary": {
            "normalized_ok": sum(1 for item in report_items if item["status"] == "ok"),
            "manual_review_count": len(needs_manual_review),
            "sanitized_summary_count": sanitized_summary_count,
            "non_cve_context_only_count": len(non_cve_scenarios),
            "failed_source_count": failed_source_count,
        },
    }

    (OUT / "scenario_vulnerability_facts.normalized.json").write_text(
        json.dumps(normalized_doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (OUT / "scenario_vulnerability_facts.pretty.json").write_text(
        json.dumps(normalized_doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (OUT / "scenario_vulnerability_facts.min.json").write_text(
        json.dumps(normalized_doc, ensure_ascii=False, separators=(",", ":")) + "\n", encoding="utf-8"
    )
    (OUT / "scenario_vulnerability_facts.schema.json").write_text(
        json.dumps(schema_doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (BASE / "normalization_report.json").write_text(
        json.dumps(normalization_report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (BASE / "quality_audit_report.json").write_text(
        json.dumps(quality_audit_report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(
        json.dumps(
            {
                "total": len(normalized_scenarios),
                "manual_review": len(needs_manual_review),
                "sanitized": sanitized_summary_count,
                "failed_source_count": failed_source_count,
                "duplicate_cve_multi_scenario": duplicate_cve_multi_scenario,
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
