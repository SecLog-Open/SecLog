#!/usr/bin/env python3
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import copy
import json
import re
import shutil
from pathlib import Path
from typing import Any, Iterable


PACKAGE_ROOT = Path(__file__).resolve().parents[3]
PRIVATE_WORK_ROOT = Path("workdir")
DEFAULT_MODEL_INPUT = PRIVATE_WORK_ROOT / "canonical_benchmark/data/model_input.jsonl"
DEFAULT_GOLD = PRIVATE_WORK_ROOT / "canonical_benchmark/data/gold.jsonl"
DEFAULT_SAMPLE_INDEX = PRIVATE_WORK_ROOT / "canonical_benchmark/data/sample_index.jsonl"
DEFAULT_CANONICAL_MANIFEST = PRIVATE_WORK_ROOT / "canonical_benchmark/manifest.json"
DEFAULT_STRICT_BLIND_MANIFEST = PRIVATE_WORK_ROOT / "strict_blind_benchmark/manifest.json"
DEFAULT_STRICT_BLIND_SAMPLE_ID_MAP = PRIVATE_WORK_ROOT / "strict_blind_benchmark/data/id_maps/sample_id_map.json"
DEFAULT_STAGE_LABEL_QUALITY_SUMMARY = PRIVATE_WORK_ROOT / "optional_stage_label_quality_summary.json"
DEFAULT_ANNOTATION_CONTEXT = (
    PACKAGE_ROOT
    / "05_benchmark_annotation_review_evaluation/assets/auxiliary_context/"
    "scenario_vulnerability_facts.annotation_context.v0.4.json"
)
DEFAULT_PRIVATE_WORKBENCH_ROOT = PRIVATE_WORK_ROOT / "compact_annotation_workbench"

STAGE_ORDER = ("preparation", "execution", "result", "stage_unclosed")
DEFAULT_STAGE_TARGET_10 = {"preparation": 3, "execution": 3, "result": 2, "stage_unclosed": 2}
PLACEHOLDER_ID_VALUES = {"", "...", "string", "string or null"}
DEFAULT_COMPACT_CONFIG = {
    "max_primary_edges": 40,
    "max_applog_message_chars": 500,
    "max_audit_context_items": 3,
    "max_traffic_items": 3,
    "max_applog_items": 3,
    "api_safe_budget": False,
    "long_window_threshold": 1000,
    "annotator_long_window_primary_cap": 70,
    "reviewer_long_window_primary_cap": 90,
}

COMPACT_V2_STAGE_BUDGETS = {
    "annotator": {"execution": 100, "stage_unclosed": 100, "preparation": 60, "result": 60},
    "reviewer": {"execution": 140, "stage_unclosed": 140, "preparation": 90, "result": 90},
}

COMPACT_V2_MODALITY_FLOORS = {"audit_context": 2, "applog": 2, "traffic": 2}

SALIENT_RELATION_TERMS = (
    "write",
    "exec",
    "connect",
    "send",
    "recv",
    "accept",
    "open",
    "read",
    "listen",
)

SALIENT_EVIDENCE_TERMS = (
    "process",
    "proc",
    "file",
    "network",
    "net",
    "http",
    "service_response",
    "response",
    "request",
)

METADATA_FORBIDDEN_PATTERNS = [
    "CVE-",
    "vulhub",
    "RCE",
    "XXE",
    "SQLi",
    "SSTI",
    "command injection",
    "path traversal",
    "deserialization",
    "authentication bypass",
]

SEMANTIC_FORBIDDEN_PATTERNS = [
    "exploit",
    "exploitation",
    "payload",
    "shell obtained",
    "data exfiltration",
    "privilege escalation",
    "remote code execution",
]

ANNOTATION_CONTEXT_ALLOWED_FIELDS = (
    "scenario_id",
    "scenario_type",
    "cve_ids",
    "product_hint",
    "affected_component_human",
    "official_context_summary",
    "scenario_context_summary",
    "mechanism_category",
    "impact_category",
    "attack_surface_hint",
    "observable_artifact_hints",
    "stage_reasoning_hints",
    "annotation_prompt_context",
    "source_extracts",
    "quality_flags",
    "strict_use_constraints",
)

SOURCE_PATH_KEYS = {
    "source_file",
    "source_files",
    "write_source_file",
    "source_path",
    "raw_source_path",
    "raw_path",
    "release_path",
    "local_cache_path",
    "main_sample",
    "stage_labels",
    "narrative_roles",
}

METADATA_REF_KEYS = {
    "source_url",
    "url",
    "source",
}

ALWAYS_METADATA_REF_KEYS = {
    "context_id",
    "event_key",
    "write_event_key",
    "source_url",
}

SYSTEM_PROMPT = (
    "You are preparing Evidence-Weighted Vulnerability-Aware Annotation for an existing "
    "stage_reasoning benchmark. EWVAA is not a stage classifier and does not re-label "
    "the stage: gold_stage / label.stage is the existing stage label for annotation "
    "construction, not a benchmark prediction target. Review the strict reasoning "
    "chain in English from primary evidence only. Treat vulnerability context as "
    "auxiliary background and never as scoring evidence."
)

TASK_INSTRUCTIONS = """# Evidence-Weighted Vulnerability-Aware Annotation

The gold_stage is known for EWVAA annotation construction only. EWVAA does not
re-label the stage, and this construction prompt must not be reused as a
benchmark evaluation prompt because evaluation prompts must not expose gold_stage.
EWVAA is not a stage classifier: gold_stage / label.stage is the existing stage
label for this construction and must not be changed. final_judgement is
evidence-based explanation closure for that existing label, not a new stage
prediction.

Strict constraints:
- Do not infer or change the stage from metadata identifiers.
- Write every generated natural-language field in English, including each claim,
  auxiliary_vulnerability_note.claim, final_judgement explanation, reviewer
  comment, reviewer judgement, and manual-review or revision reason if present.
- Do not translate raw evidence text. Keep audit log snippets, application log
  messages, traffic summaries, process names, file paths, network names,
  function names, variable names, CVE identifiers, sample_id, scenario_id,
  edge_id, and evidence_refs exactly as provided.
- Vulnerability context is auxiliary only.
- Primary evidence is the only basis for strict gold_reasoning_chain.
- Strict reasoning must be grounded in cited primary evidence.
- Use the four-step chain as a multi-source attack-log judgement:
  scenario_or_evidence_understanding scopes the visible multi-source evidence
  window, available source coverage, primary vs auxiliary evidence role,
  missing / weak / disconnected evidence conditions, and which visible
  stage-relevant evidence condition(s) matter for the stage interpretation,
  without making a final stage judgement; observable_evidence extracts
  source-bucketed auditable facts by source bucket such as audit, applog, and
  traffic, identifies directly visible cited facts and stage-relevant
  observable facts, and does not infer the stage; attack_stage_path_reasoning
  links evidence through temporal proximity, subject continuity, object/target
  consistency, request chain, process chain, file chain, and network chain;
  final_judgement closes the evidence-based stage interpretation.
- multisource_v1 step semantics:
  scenario_or_evidence_understanding = multi-source log window and evidence-condition scoping;
  observable_evidence = source-bucketed auditable log fact extraction;
  attack_stage_path_reasoning = temporal-subject-object cross-source chain reasoning;
  final_judgement = existing-label evidence-grounded explanation under EWVAA.
- CVE, exploit, payload, RCE, PoC, and public vulnerability descriptions must
  not be used as direct evidence in strict reasoning.
- CVE / public advisory / scenario prior cannot be used as strict evidence unless directly present in primary evidence.
- Such vulnerability background may appear only in auxiliary_vulnerability_note
  with not_for_scoring=true.
- Do not use the literal word "payload" in strict gold_reasoning_chain[*].claim;
  prefer neutral traffic wording such as "no traffic body/details visible",
  "no request body details visible", or "no additional traffic content beyond
  connect/send".
- Every strict claim must name cited primary evidence concretely: process/service, event/action, object/target, and seq or edge_id.
- Each strict reasoning step should follow: primary evidence fact -> behavior meaning -> stage relation.
- For EWVAA, scenario_or_evidence_understanding should identify which visible
  evidence conditions are relevant to explaining the stage interpretation, without
  using vulnerability background as strict evidence and without making a new
  stage classification.
- observable_evidence should make clear why the cited source-bucketed facts are
  relevant evidence for the stage interpretation while remaining factual; do not
  turn traffic-only evidence into result, and do not turn CVE / public advisory
  / scenario prior into an observable fact.
- attack_stage_path_reasoning must use primary fact -> stage predicate wording: first restate the cited primary fact, then explain why it satisfies the exact gold_stage.
- attack_stage_path_reasoning must explain why the cited links support the
  stage interpretation and why adjacent stages are not better supported.
- final_judgement must return to the strongest cited primary evidence before stating the exact gold_stage.
- final_judgement must explain uncertainty and missing evidence when needed,
  without using CVE / public advisory / scenario prior as strict evidence.
- For result, identify the concrete outcome/artifact, such as a file write path, state change, output artifact, created object, or observable result.
- For execution, do not treat NET_ACCEPT, NET_RECV, or PROCESS_FORK alone as sufficient; explain what additional cited fact makes the activity execution rather than ordinary service handling.
- For stage_unclosed samples, explain that the window is attack-related but the visible strict-blind evidence does not sufficiently close preparation, execution, or result. Do not describe stage_unclosed as a real attack lifecycle stage.
- For stage_unclosed, do not simply say "no attack"; state the missing observable stage-closing evidence such as no command execution, no file write, no output artifact, no post-auth action, or no state-changing outcome.
- Vulnerability-background-only claim must go only to auxiliary_vulnerability_note.
- The model must output masked sample_id and masked edge_id exactly as given.
- Strict gold_reasoning_chain must not mention public advisory identifiers, original scenario names, or source paths.
- Public advisory identifiers or descriptions may appear only in auxiliary_vulnerability_note when useful, and never as direct scoring evidence.
- strict gold_reasoning_chain[*].claim must avoid high-risk vulnerability mechanism terms listed in this validation policy: CVE, exploit, payload, RCE, PoC, public vulnerability description, and public advisory description.
- For negative evidence, use neutral phrases such as "without observed result artifacts", "without confirmed file/process/network outcome", or "insufficient primary evidence for the requested stage".
- Do not use unsupported vulnerability-background wording or unsupported outcome wording in strict gold_reasoning_chain[*].claim.
- Avoid abstract bridge phrases unless the same sentence anchors them to a cited primary fact: active interaction, runtime interaction, outcome artifact, stage-specific evidence.
- final_judgement.claim must explicitly contain the exact gold_stage token: preparation, execution, result, or stage_unclosed.
- For stage_unclosed samples, final_judgement.claim should state that the appropriate stage-closure label is stage_unclosed because the window is attack-related but the visible strict-blind evidence does not sufficiently close preparation, execution, or result.
- Evidence alignment requirements: formal claims may use only visible audit evidence, visible applog evidence, visible traffic evidence, sanitized applog summary/sanitized_message, and explicit visible evidence fields. Do not use CVE, scenario name, sample_id, run_dir, source path, traceability metadata, diagnostic metadata, weighted_verdict, human_review_priority, promotion_blocker, or needs_later_patch as formal stage-reasoning evidence.
- Candidate text is not evidence: original candidate text or current draft text is the object being audited, not evidence. Check every inherited URL/endpoint, process, connection, status code, file path, artifact, seq, edge_id, relation, raw_evt_type, fd_name, service_name, sanitized_message, attach_strength, attach_reason, backbone_seq, sec_delta, source coverage limitation, empty applog bucket, empty traffic bucket, and traffic flow field against visible evidence before using it.
- Field-level alignment: URL, endpoint, process, connection, and status code must match visible evidence exactly. Do not inherit or invent extra URL suffixes, hidden command arguments, hidden payloads, hidden request bodies, hidden response bodies, hidden file contents, hidden artifacts, hidden post-auth actions, hidden state changes, or durable outcomes not visible in evidence.
- Minimal revision requirements: if the current draft is mostly evidence-aligned, preserve correct seq, relation, process, URL, connection, status, and file-path anchors. Revise only unsupported claims, workflow leakage, fixed-gold wording, stage-boundary overclaims, stage_unclosed wording errors, or field mismatches; do not over-smooth or generalize away useful visible evidence details.
- Anti-template wording: do not force every claim to begin with generic openings such as "The visible evidence window contains" or "The directly visible audit evidence shows". Prefer evidence-specific openings such as "At seq X", "The audit spine centers on", "The cited events show", "The source coverage here is", or "The strongest visible support is" when supported.
- Formal vs review layer separation: gold_reasoning_chain and auxiliary_vulnerability_note are formal draft fields. Keep workflow/status terms such as manual review, promotion, clean final, canonical gold, writeback, human_verified, reviewer decision, and L1-L4 out of formal claims; those words belong only in review/status fields or notes if a target schema has them.
- Text quality issue is different from evidence weakness: needs_later_patch_after_review=yes only when text/schema/evidence wording/data issues remain unresolved; promotion_blocker_after_review=yes when evidence remains weak or the stage boundary remains weak after wording is fixed. Evidence weakness alone does not imply needs_later_patch_after_review=yes.
- stage_unclosed wording requirements: stage_unclosed is a stage-closure label, not a fourth real attack lifecycle stage. Do not describe stage_unclosed as the current or attack stage, as the current attack-stage value, as a lifecycle-stage term, or as a phase. Prefer "the appropriate stage-closure label is stage_unclosed" or "the window should be labeled stage_unclosed under the visible strict-blind evidence".
- Final reviewed output requirements: return final, copy-ready revised claim content and any requested review-status fields. Do not merely list suggestions or say "should be revised to" unless the output is explicitly a review note.
- evidence_refs.seq must be an integer.
- evidence_refs.edge_id must exactly match a masked edge_id from primary evidence.
- auxiliary_vulnerability_note must contain only claim and not_for_scoring.
- auxiliary_vulnerability_note.not_for_scoring must be true.
- auxiliary_vulnerability_note.not_for_scoring = true.

Output JSON only, no markdown.
"""


ANNOTATOR_ROLE_INSTRUCTIONS = """## Annotator role

Construct the EWVAA annotation object using the provided gold_stage and primary
evidence. Do not relabel the stage and do not act as a stage classifier. The
output must use the exact required schema, and all generated reasoning text
must be English.
"""


REVIEWER_ROLE_INSTRUCTIONS = """## Reviewer role

You are using the reviewer evidence budget to construct or check the same EWVAA
annotation object. Return the same annotation schema, not a verdict object.

Reviewer constraints:
- Do not change gold_stage or label.stage; EWVAA is not a stage classifier.
- Treat final_judgement as evidence-based closure for the existing gold_stage,
  not as a new prediction.
- Do not invent evidence_refs, seq values, or edge_id values.
- Do not use outside evidence.
- Do not rewrite strict reasoning based only on vulnerability background.
- If any reviewer comment, judgement, or revision reason appears in a generated
  natural-language field, write it in English.
- Keep vulnerability background out of strict gold_reasoning_chain; use
  auxiliary_vulnerability_note only when background context is useful.
"""


def role_instructions_for(consumer_role: str) -> str:
    return REVIEWER_ROLE_INSTRUCTIONS if consumer_role == "reviewer" else ANNOTATOR_ROLE_INSTRUCTIONS


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")
            count += 1
    return count


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def id_map_doc(prefix: str, originals: list[str]) -> dict[str, Any]:
    return {
        "schema_version": "ewvaa_id_map.v1",
        "items": [
            {"masked": f"{prefix}_m_{idx:06d}", "original": original}
            for idx, original in enumerate(originals, start=1)
        ],
    }


def map_lookup(map_doc: dict[str, Any]) -> dict[str, str]:
    return {item["original"]: item["masked"] for item in map_doc["items"]}


def is_placeholder_id(value: Any) -> bool:
    return value is None or (isinstance(value, str) and value.strip() in PLACEHOLDER_ID_VALUES)


def collect_ids(
    value: Any,
    scenarios: list[str],
    samples: list[str],
    edges: list[str],
    stats: dict[str, int],
    path: tuple[str, ...] = (),
) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            child_path = path + (str(key),)
            if isinstance(item, str):
                if key in {"scenario_id", "original_scenario_id"}:
                    scenarios.append(item)
                if key in {"sample_id", "original_sample_id"}:
                    samples.append(item)
                if "edge_id" in key:
                    if is_placeholder_id(item):
                        stats["placeholder_ids_excluded"] += 1
                    else:
                        edges.append(item)
            elif item is None and "edge_id" in key:
                stats["placeholder_ids_excluded"] += 1
            collect_ids(item, scenarios, samples, edges, stats, child_path)
    elif isinstance(value, list):
        for idx, item in enumerate(value):
            collect_ids(item, scenarios, samples, edges, stats, path + (str(idx),))


def ordered_unique(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out


def pattern_for(term: str) -> re.Pattern[str]:
    if term in {"RCE", "XXE", "SQLi", "SSTI"}:
        return re.compile(rf"\b{re.escape(term)}\b", re.IGNORECASE)
    return re.compile(re.escape(term), re.IGNORECASE)


METADATA_REPLACEMENTS = [
    (re.compile(r"CVE-\d{4}-\d{4,7}(?:-[A-Za-z0-9_.-]+)?", re.IGNORECASE), "public advisory identifier"),
    (re.compile(r"CVE-[A-Za-z0-9_.-]+", re.IGNORECASE), "public advisory"),
    (re.compile(r"\bvulhub\b", re.IGNORECASE), "lab corpus"),
    (re.compile(r"\bRCE\b", re.IGNORECASE), "code-related issue"),
    (re.compile(r"\bXXE\b", re.IGNORECASE), "XML-related issue"),
    (re.compile(r"\bSQLi\b", re.IGNORECASE), "database-query issue"),
    (re.compile(r"\bSQL[- ]input\b", re.IGNORECASE), "database-input"),
    (re.compile(r"\bSQLite\b", re.IGNORECASE), "embedded database"),
    (re.compile(r"\bSSTI\b", re.IGNORECASE), "template issue"),
    (re.compile(r"command[- ]injection", re.IGNORECASE), "command-related issue"),
    (re.compile(r"path[- ]traversal", re.IGNORECASE), "path access issue"),
    (re.compile(r"deserialization", re.IGNORECASE), "object parsing issue"),
    (re.compile(r"authentication[- ]bypass", re.IGNORECASE), "authentication control issue"),
]

SEMANTIC_REPLACEMENTS = [
    (re.compile(r"post-exploitation", re.IGNORECASE), "post-activity"),
    (re.compile(r"exploitation", re.IGNORECASE), "attack activity"),
    (re.compile(r"exploit", re.IGNORECASE), "attack activity"),
    (re.compile(r"payload", re.IGNORECASE), "request content"),
    (re.compile(r"shell obtained", re.IGNORECASE), "interactive access observed"),
    (re.compile(r"data exfiltration", re.IGNORECASE), "data movement"),
    (re.compile(r"privilege escalation", re.IGNORECASE), "permission change"),
    (re.compile(r"remote code execution", re.IGNORECASE), "code execution behavior"),
]

PROMPT_VISIBLE_REPLACEMENTS = METADATA_REPLACEMENTS + SEMANTIC_REPLACEMENTS + [
    (re.compile(r"vulhub", re.IGNORECASE), "lab_corpus_m"),
    (re.compile(r"cmsms", re.IGNORECASE), "app_family_m"),
    (re.compile(r"joomla", re.IGNORECASE), "app_family_m"),
    (re.compile(r"gitlist", re.IGNORECASE), "app_family_m"),
    (re.compile(r"adminer", re.IGNORECASE), "app_family_m"),
    (re.compile(r"solr", re.IGNORECASE), "app_family_m"),
    (re.compile(r"geoserver", re.IGNORECASE), "app_family_m"),
    (re.compile(r"metabase", re.IGNORECASE), "app_family_m"),
    (re.compile(r"ofbiz", re.IGNORECASE), "app_family_m"),
    (re.compile(r"pgadmin", re.IGNORECASE), "app_family_m"),
    (re.compile(r"juice-shop", re.IGNORECASE), "app_family_m"),
    (re.compile(r"multi-jump", re.IGNORECASE), "scenario_family_m"),
    (re.compile(r"sandworm", re.IGNORECASE), "scenario_family_m"),
]


def sanitize_prompt_visible_text(value: Any) -> Any:
    if isinstance(value, str):
        out = value
        for regex, replacement in PROMPT_VISIBLE_REPLACEMENTS:
            out = regex.sub(replacement, out)
        return out
    if isinstance(value, dict):
        return {key: sanitize_prompt_visible_text(item) for key, item in value.items()}
    if isinstance(value, list):
        return [sanitize_prompt_visible_text(item) for item in value]
    return value


def sanitize_non_primary_text(text: str) -> str:
    lower = text.lower()
    if not (
        "cve-" in lower
        or "vulhub" in lower
        or "rce" in lower
        or "xxe" in lower
        or "sqli" in lower
        or "sql-input" in lower
        or "sql input" in lower
        or "sqlite" in lower
        or "ssti" in lower
        or "injection" in lower
        or "traversal" in lower
        or "deserialization" in lower
        or "authentication" in lower
        or "exploit" in lower
        or "payload" in lower
        or "shell obtained" in lower
        or "data exfiltration" in lower
        or "privilege escalation" in lower
        or "remote code execution" in lower
        or "http://" in lower
        or "https://" in lower
        or "raw/" in lower
        or "shared/" in lower
        or "private_workdir/" in lower
        or "private_annotation_workdir/" in lower
        or "workdir/" in lower
        or "annotation_workdir/" in lower
        or "/benchmarks/" in lower
    ):
        return text
    out = text
    for regex, replacement in METADATA_REPLACEMENTS + SEMANTIC_REPLACEMENTS:
        out = regex.sub(replacement, out)
    out = re.sub(r"https?://\S+", "[masked_url]", out)
    out = re.sub(
        r"\b(?:raw|shared|private_workdir|private_annotation_workdir|workdir|annotation_workdir|canonical_benchmark|strict_blind_benchmark)/[^\s\"']+",
        "[masked_path]",
        out,
    )
    return out


def replace_ids(text: str, replacements: list[tuple[str, str]]) -> str:
    out = text
    for original, masked in replacements:
        if original:
            out = out.replace(original, masked)
    return out


def is_primary_evidence_path(path: tuple[str, ...]) -> bool:
    joined = ".".join(path)
    if ".source_file" in joined or ".write_source_file" in joined:
        return False
    for idx in range(0, max(0, len(path) - 1)):
        if path[idx : idx + 2] == ("input", "spine"):
            return True
    if path[:2] == ("input", "spine"):
        return True
    if "primary_evidence" in path:
        return True
    return False


class MetadataMasker:
    def __init__(self, scenario_map: dict[str, str], sample_map: dict[str, str], edge_map: dict[str, str]) -> None:
        self.scenario_map = scenario_map
        self.sample_map = sample_map
        self.edge_map = edge_map
        self.path_map: dict[str, str] = {}
        self.ref_map: dict[str, str] = {}
        replacements: list[tuple[str, str]] = []
        for mapping in (sample_map, scenario_map):
            replacements.extend(mapping.items())
        self.text_replacements = sorted(replacements, key=lambda item: len(item[0]), reverse=True)
        self.text_replacement_lookup = dict(self.text_replacements)
        if self.text_replacements:
            self.text_replacement_pattern = re.compile(
                "|".join(re.escape(original) for original, _ in self.text_replacements)
            )
        else:
            self.text_replacement_pattern = None

    def replace_text_ids(self, text: str) -> str:
        if self.text_replacement_pattern is None or not self.text_replacement_pattern.search(text):
            return text
        return self.text_replacement_pattern.sub(lambda match: self.text_replacement_lookup[match.group(0)], text)

    def masked_path_ref(self, value: Any) -> Any:
        if isinstance(value, dict):
            return {key: self.masked_path_ref(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self.masked_path_ref(item) for item in value]
        if not isinstance(value, str):
            return value
        if value not in self.path_map:
            self.path_map[value] = f"source_file_m_{len(self.path_map) + 1:06d}"
        return self.path_map[value]

    def masked_metadata_ref(self, value: Any) -> Any:
        if isinstance(value, dict):
            return {key: self.masked_metadata_ref(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self.masked_metadata_ref(item) for item in value]
        if not isinstance(value, str):
            return value
        replaced = self.replace_text_ids(value)
        if replaced != value:
            return sanitize_non_primary_text(replaced)
        if value not in self.ref_map:
            self.ref_map[value] = f"metadata_ref_m_{len(self.ref_map) + 1:06d}"
        return self.ref_map[value]

    def mask_value(self, value: Any, path: tuple[str, ...] = ()) -> Any:
        if isinstance(value, dict):
            masked: dict[str, Any] = {}
            for key, item in value.items():
                key_s = str(key)
                child_path = path + (key_s,)
                if key_s in SOURCE_PATH_KEYS:
                    masked[key_s] = self.masked_path_ref(item)
                elif key_s in {"scenario_id", "original_scenario_id"} and isinstance(item, str):
                    masked[key_s] = self.scenario_map.get(item, item)
                elif key_s == "cve_ids":
                    masked[key_s] = copy.deepcopy(item)
                elif key_s in {"sample_id", "original_sample_id"} and isinstance(item, str):
                    masked[key_s] = self.sample_map.get(item, item)
                elif "edge_id" in key_s and isinstance(item, str):
                    masked[key_s] = self.edge_map.get(item, item)
                elif key_s in ALWAYS_METADATA_REF_KEYS:
                    masked[key_s] = self.masked_metadata_ref(item)
                elif key_s in METADATA_REF_KEYS and not is_primary_evidence_path(child_path):
                    masked[key_s] = self.masked_metadata_ref(item)
                elif key_s == "service_name" and isinstance(item, str):
                    replaced = self.replace_text_ids(item)
                    sanitized = sanitize_non_primary_text(replaced)
                    masked[key_s] = sanitized
                else:
                    masked[key_s] = self.mask_value(item, child_path)
            return masked
        if isinstance(value, list):
            return [self.mask_value(item, path + (str(idx),)) for idx, item in enumerate(value)]
        if isinstance(value, str):
            replaced = self.replace_text_ids(value)
            if is_primary_evidence_path(path):
                return replaced
            return sanitize_non_primary_text(replaced)
        return value


def clean_annotation_context(doc: dict[str, Any], masker: MetadataMasker, annotation_source: Path) -> dict[str, Any]:
    cleaned = {
        "schema_version": "ewvaa_annotation_context.masked.v1",
        "created_from": str(annotation_source),
        "use": doc.get("use"),
        "scenarios": [],
    }
    for scenario in doc.get("scenarios", []):
        item = {key: copy.deepcopy(scenario.get(key)) for key in ANNOTATION_CONTEXT_ALLOWED_FIELDS if key in scenario}
        item = masker.mask_value(item)
        extracts = []
        for extract in item.get("source_extracts") or []:
            if not isinstance(extract, dict):
                continue
            extracts.append(
                {
                    "source_type": sanitize_non_primary_text(str(extract.get("source_type", ""))),
                    "summary": sanitize_non_primary_text(str(extract.get("summary", "")))[:700],
                    "confidence": sanitize_non_primary_text(str(extract.get("confidence", ""))),
                }
            )
        if "source_extracts" in item:
            item["source_extracts"] = extracts[:3]
        constraints = item.get("strict_use_constraints")
        if isinstance(constraints, dict) and "must_not_invent_payload" in constraints:
            constraints["must_not_invent_request_content"] = constraints.pop("must_not_invent_payload")
        cleaned["scenarios"].append(item)
    return cleaned


def compact_audit_context(items: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    out = []
    for item in items[:limit]:
        out.append({key: item.get(key) for key in ("evt.num", "evt.type", "proc.name", "proc.cmdline", "fd.name") if key in item})
    return out


def compact_log_items(items: list[dict[str, Any]], limit: int, message_chars: int) -> list[dict[str, Any]]:
    out = []
    for item in items[:limit]:
        row = {
            key: item.get(key)
            for key in ("timestamp", "service_name", "semantic_type", "message", "attach_to_backbone_edge_id")
            if key in item
        }
        if isinstance(row.get("message"), str):
            row["message"] = row["message"][:message_chars]
        out.append(row)
    return out


def compact_traffic(items: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    out = []
    for item in items[:limit]:
        out.append(
            {
                key: item.get(key)
                for key in (
                    "summary_type",
                    "l4_proto",
                    "src_ip",
                    "src_port",
                    "dst_ip",
                    "dst_port",
                    "semantic_type",
                    "attach_to_backbone_edge_id",
                )
                if key in item
            }
        )
    return out


def safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def edge_seq(edge: dict[str, Any]) -> int:
    return safe_int(edge.get("seq"), 0)


def item_text_for_score(item: Any) -> str:
    if isinstance(item, dict):
        parts: list[str] = []
        for key in (
            "relation",
            "semantic_type",
            "summary_type",
            "evt.type",
            "proc.name",
            "proc.cmdline",
            "fd.name",
            "message",
            "subject",
            "object",
            "raw_evt_type",
            "fd_name",
        ):
            value = item.get(key)
            if value is not None:
                parts.append(str(value))
        event = item.get("event")
        if isinstance(event, dict):
            parts.extend(str(event.get(key, "")) for key in ("relation", "object"))
            attrs = event.get("attrs")
            if isinstance(attrs, dict):
                parts.extend(str(attrs.get(key, "")) for key in ("raw_evt_type", "fd_name", "proc_name"))
        return " ".join(parts).lower()
    return str(item).lower()


def salience_score_text(text: str) -> float:
    score = 0.0
    for term in SALIENT_EVIDENCE_TERMS:
        if term in text:
            score += 2.0
    for term in SALIENT_RELATION_TERMS:
        if term in text:
            score += 4.0
    if "generic" in text:
        score -= 1.0
    return score


def select_representative_items(items: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    if limit <= 0 or not items:
        return []
    if len(items) <= limit:
        return items
    selected: set[int] = {0, len(items) - 1}
    scored = [
        (salience_score_text(item_text_for_score(item)), idx)
        for idx, item in enumerate(items)
    ]
    for _, idx in sorted(scored, key=lambda item: (-item[0], item[1])):
        selected.add(idx)
        if len(selected) >= limit:
            break
    if len(selected) < limit and len(items) > 2:
        step = max(1, len(items) // max(1, limit - len(selected)))
        for idx in range(0, len(items), step):
            selected.add(idx)
            if len(selected) >= limit:
                break
    return [items[idx] for idx in sorted(selected)[:limit]]


def compact_audit_context_v2(items: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    out = []
    for item in select_representative_items(items, limit):
        out.append({key: item.get(key) for key in ("evt.num", "evt.type", "proc.name", "proc.cmdline", "fd.name") if key in item})
    return out


def compact_log_items_v2(items: list[dict[str, Any]], limit: int, message_chars: int) -> list[dict[str, Any]]:
    out = []
    for item in select_representative_items(items, limit):
        row = {
            key: item.get(key)
            for key in ("timestamp", "service_name", "semantic_type", "message", "attach_to_backbone_edge_id")
            if key in item
        }
        if isinstance(row.get("message"), str):
            row["message"] = row["message"][:message_chars]
        out.append(row)
    return out


def compact_traffic_v2(items: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    out = []
    for item in select_representative_items(items, limit):
        out.append(
            {
                key: item.get(key)
                for key in (
                    "summary_type",
                    "l4_proto",
                    "src_ip",
                    "src_port",
                    "dst_ip",
                    "dst_port",
                    "semantic_type",
                    "attach_to_backbone_edge_id",
                )
                if key in item
            }
        )
    return out


def compact_edge(edge: dict[str, Any], compact_config: dict[str, int]) -> dict[str, Any]:
    attrs = edge.get("attrs") or {}
    multisource = edge.get("multisource_context") or {}
    compacted: dict[str, Any] = {
        "seq": edge.get("seq"),
        "edge_id": edge.get("edge_id"),
        "subject": edge.get("subject"),
        "relation": edge.get("relation"),
        "object": edge.get("object"),
        "audit_context": compact_audit_context(
            edge.get("audit_context") or [], compact_config["max_audit_context_items"]
        ),
        "multisource_context": {
            "applog": compact_log_items(
                multisource.get("applog") or [],
                compact_config["max_applog_items"],
                compact_config["max_applog_message_chars"],
            ),
            "traffic": compact_traffic(multisource.get("traffic") or [], compact_config["max_traffic_items"]),
        },
    }
    for key in ("evt_num", "timestamp", "raw_evt_type", "container_id", "proc_name", "fd_name"):
        if key in attrs:
            compacted[key] = attrs[key]
    return compacted


def compact_edge_v2(edge: dict[str, Any], compact_config: dict[str, int]) -> dict[str, Any]:
    attrs = edge.get("attrs") or {}
    multisource = edge.get("multisource_context") or {}
    compacted: dict[str, Any] = {
        "seq": edge.get("seq"),
        "edge_id": edge.get("edge_id"),
        "subject": edge.get("subject"),
        "relation": edge.get("relation"),
        "object": edge.get("object"),
        "audit_context": compact_audit_context_v2(
            edge.get("audit_context") or [], compact_config["max_audit_context_items"]
        ),
        "multisource_context": {
            "applog": compact_log_items_v2(
                multisource.get("applog") or [],
                compact_config["max_applog_items"],
                compact_config["max_applog_message_chars"],
            ),
            "traffic": compact_traffic_v2(multisource.get("traffic") or [], compact_config["max_traffic_items"]),
        },
    }
    for key in ("evt_num", "timestamp", "raw_evt_type", "container_id", "proc_name", "fd_name"):
        if key in attrs:
            compacted[key] = attrs[key]
    return compacted


def modality_counts_for_edges(spine: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"spine": len(spine), "audit_context": 0, "applog": 0, "traffic": 0}
    for edge in spine:
        counts["audit_context"] += len(edge.get("audit_context") or [])
        multisource = edge.get("multisource_context") or {}
        counts["applog"] += len(multisource.get("applog") or [])
        counts["traffic"] += len(multisource.get("traffic") or [])
    return counts


def modality_counts_for_primary(primary_evidence: dict[str, Any]) -> dict[str, int]:
    return modality_counts_for_edges(primary_evidence.get("spine") or [])


def edge_has_modality(edge: dict[str, Any], modality: str) -> bool:
    if modality == "audit_context":
        return bool(edge.get("audit_context"))
    multisource = edge.get("multisource_context") or {}
    return bool(multisource.get(modality))


def edge_salience_score(edge: dict[str, Any], anchors: list[int]) -> float:
    seq = edge_seq(edge)
    relation = str(edge.get("relation") or "").lower()
    text = " ".join(
        str(value or "")
        for value in (
            edge.get("subject"),
            edge.get("object"),
            relation,
            (edge.get("attrs") or {}).get("raw_evt_type"),
            (edge.get("attrs") or {}).get("fd_name"),
        )
    ).lower()
    score = salience_score_text(text)
    if anchors:
        score += 25.0 / (1.0 + min(abs(seq - anchor) for anchor in anchors))
    if relation:
        score += 1.0
    if edge.get("audit_context"):
        score += 3.0
    multisource = edge.get("multisource_context") or {}
    if multisource.get("applog"):
        score += 3.0
    if multisource.get("traffic"):
        score += 3.0
    return score


def base_compact_v2_budget(stage: str, compact_config: dict[str, Any], consumer_role: str) -> int:
    if compact_config.get("stage_adaptive_budget"):
        role = "reviewer" if consumer_role == "reviewer" else "annotator"
        return COMPACT_V2_STAGE_BUDGETS[role].get(stage, compact_config["max_primary_edges"])
    budget = compact_config["max_primary_edges"]
    if consumer_role == "reviewer" and compact_config.get("reviewer_more_evidence"):
        return max(budget, int(budget * 1.5))
    return budget


def compact_v2_budget(stage: str, compact_config: dict[str, Any], consumer_role: str, raw_spine_len: int) -> int:
    budget = base_compact_v2_budget(stage, compact_config, consumer_role)
    if not compact_config.get("api_safe_budget"):
        return budget
    if raw_spine_len <= int(compact_config.get("long_window_threshold", 0) or 0):
        return budget
    cap_key = "reviewer_long_window_primary_cap" if consumer_role == "reviewer" else "annotator_long_window_primary_cap"
    cap_value = compact_config.get(cap_key)
    try:
        cap = int(cap_value)
    except (TypeError, ValueError):
        return budget
    if cap <= 0:
        return budget
    return min(budget, cap)


def role_compact_config(compact_config: dict[str, Any], consumer_role: str) -> dict[str, Any]:
    role_config = dict(compact_config)
    if compact_config.get("compact_version") == "v2":
        role_config["max_audit_context_items"] = max(role_config["max_audit_context_items"], 4)
        role_config["max_applog_items"] = max(role_config["max_applog_items"], 4)
        role_config["max_traffic_items"] = max(role_config["max_traffic_items"], 4)
        if consumer_role == "reviewer" and compact_config.get("reviewer_more_evidence"):
            role_config["max_audit_context_items"] = max(role_config["max_audit_context_items"], 6)
            role_config["max_applog_items"] = max(role_config["max_applog_items"], 6)
            role_config["max_traffic_items"] = max(role_config["max_traffic_items"], 6)
            role_config["max_applog_message_chars"] = max(role_config["max_applog_message_chars"], 800)
    return role_config


def select_spine_v2(
    spine: list[dict[str, Any]],
    stage: str,
    compact_config: dict[str, Any],
    consumer_role: str,
    window: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    budget = compact_v2_budget(stage, compact_config, consumer_role, len(spine))
    base_budget = base_compact_v2_budget(stage, compact_config, consumer_role)
    api_safe_capped = budget < base_budget
    if budget <= 0 or not spine:
        return [], {
            "budget": budget,
            "base_budget": base_budget,
            "api_safe_capped": api_safe_capped,
            "selected_indices": [],
            "modality_floor_triggered": {},
            "selection_policy": "empty",
        }
    if len(spine) <= budget:
        return spine, {
            "budget": budget,
            "base_budget": base_budget,
            "api_safe_capped": api_safe_capped,
            "selected_indices": list(range(len(spine))),
            "modality_floor_triggered": {key: False for key in COMPACT_V2_MODALITY_FLOORS},
            "selection_policy": "all_edges_within_budget",
        }

    start_seq = safe_int(window.get("start_seq"), edge_seq(spine[0]))
    end_seq = safe_int(window.get("end_seq"), edge_seq(spine[-1]))
    midpoint = (start_seq + end_seq) // 2
    anchors = [start_seq, end_seq, midpoint]
    scored = [(edge_salience_score(edge, anchors), idx) for idx, edge in enumerate(spine)]
    selected: set[int] = set()
    floor_indices: set[int] = set()
    modality_floor_triggered = {key: False for key in COMPACT_V2_MODALITY_FLOORS}

    if compact_config.get("modality_floor"):
        for modality, floor_target in COMPACT_V2_MODALITY_FLOORS.items():
            candidates = [(score, idx) for score, idx in scored if edge_has_modality(spine[idx], modality)]
            selected_for_modality = 0
            for _, idx in sorted(candidates, key=lambda item: (-item[0], item[1]))[:floor_target]:
                selected.add(idx)
                floor_indices.add(idx)
                selected_for_modality += 1
            if selected_for_modality:
                modality_floor_triggered[modality] = True

    head_tail_each = max(1, min(8, budget // 10))
    selected.update(range(0, head_tail_each))
    selected.update(range(max(0, len(spine) - head_tail_each), len(spine)))

    coverage_slots = max(0, min(10, budget // 8))
    if coverage_slots:
        step = max(1, len(spine) // (coverage_slots + 1))
        for idx in range(step, len(spine), step):
            selected.add(idx)
            if len(selected) >= head_tail_each * 2 + coverage_slots + len(floor_indices):
                break

    for _, idx in sorted(scored, key=lambda item: (-item[0], item[1])):
        selected.add(idx)
        if len(selected) >= budget:
            break

    if len(selected) > budget:
        protected = set(floor_indices)
        protected.update(range(0, head_tail_each))
        protected.update(range(max(0, len(spine) - head_tail_each), len(spine)))
        removable = [idx for idx in selected if idx not in protected]
        score_by_idx = {idx: score for score, idx in scored}
        for idx in sorted(removable, key=lambda item: (score_by_idx.get(item, 0.0), -item)):
            if len(selected) <= budget:
                break
            selected.remove(idx)

    selected_indices = sorted(selected)
    return [spine[idx] for idx in selected_indices], {
        "budget": budget,
        "base_budget": base_budget,
        "api_safe_capped": api_safe_capped,
        "selected_indices": selected_indices,
        "modality_floor_triggered": modality_floor_triggered,
        "selection_policy": "salience_plus_modality_floor_plus_head_tail",
    }


def compact_primary_evidence(sample: dict[str, Any], compact_config: dict[str, int]) -> dict[str, Any]:
    spine = (sample.get("input") or {}).get("spine") or []
    max_edges = compact_config["max_primary_edges"]
    if max_edges <= 0:
        selected = []
    elif len(spine) <= max_edges:
        selected = spine
    else:
        head = max_edges // 2
        selected = spine[:head] + spine[-(max_edges - head) :]
    return {
        "spine_edge_count": len(spine),
        "spine_truncated": len(spine) > max_edges,
        "spine": [compact_edge(edge, compact_config) for edge in selected],
    }


def compact_primary_evidence_v2(
    sample: dict[str, Any],
    gold_stage: str,
    compact_config: dict[str, Any],
    consumer_role: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    spine = (sample.get("input") or {}).get("spine") or []
    role_config = role_compact_config(compact_config, consumer_role)
    selected, selection_report = select_spine_v2(
        spine,
        gold_stage,
        role_config,
        consumer_role,
        sample.get("window") or {},
    )
    primary_evidence = {
        "spine_edge_count": len(spine),
        "spine_truncated": len(selected) < len(spine),
        "compact_version": "v2",
        "consumer_role": consumer_role,
        "stage_adaptive_budget": bool(role_config.get("stage_adaptive_budget")),
        "modality_floor_enabled": bool(role_config.get("modality_floor")),
        "max_primary_edges_effective": selection_report["budget"],
        "selection_policy": selection_report["selection_policy"],
        "spine": [compact_edge_v2(edge, role_config) for edge in selected],
    }
    raw_counts = modality_counts_for_edges(spine)
    compact_counts = modality_counts_for_primary(primary_evidence)
    return primary_evidence, {
        "consumer_role": consumer_role,
        "gold_stage": gold_stage,
        "raw_counts": raw_counts,
        "compact_counts": compact_counts,
        "compression_ratio": {
            key: (compact_counts.get(key, 0) / raw_counts[key] if raw_counts.get(key) else None)
            for key in ("spine", "audit_context", "applog", "traffic")
        },
        "budget": selection_report["budget"],
        "base_budget": selection_report["base_budget"],
        "api_safe_capped": selection_report["api_safe_capped"],
        "context_item_limits": {
            "audit_context": role_config["max_audit_context_items"],
            "applog": role_config["max_applog_items"],
            "traffic": role_config["max_traffic_items"],
            "applog_message_chars": role_config["max_applog_message_chars"],
        },
        "modality_floor_triggered": selection_report["modality_floor_triggered"],
        "raw_positive_compact_zero": {
            key: raw_counts.get(key, 0) > 0 and compact_counts.get(key, 0) == 0
            for key in ("audit_context", "applog", "traffic")
        },
    }


def context_by_scenario(masked_context_doc: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {row["scenario_id"]: row for row in masked_context_doc.get("scenarios", []) if row.get("scenario_id")}


def original_context_by_scenario(doc: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {row["scenario_id"]: row for row in doc.get("scenarios", []) if row.get("scenario_id")}


def stage_of(gold: dict[str, Any], index_row: dict[str, Any] | None = None) -> str:
    return ((gold.get("label") or {}).get("stage") or (index_row or {}).get("stage") or "unknown")


def select_samples(
    model_rows: list[dict[str, Any]],
    gold_by_id: dict[str, dict[str, Any]],
    sample_index_by_id: dict[str, dict[str, Any]],
    context_by_original_scenario: dict[str, dict[str, Any]],
    args: argparse.Namespace,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    stats = {"manual_review_excluded": 0, "missing_vulnerability_context_excluded": 0}
    fixed_sample_ids = getattr(args, "fixed_sample_ids", None) or []
    if fixed_sample_ids:
        model_by_id = {row.get("sample_id"): row for row in model_rows}
        missing = [sample_id for sample_id in fixed_sample_ids if sample_id not in model_by_id]
        if missing:
            raise SystemExit(
                f"Fixed sample input contains {len(missing)} sample_id values not found in --model-input: "
                + ", ".join(missing[:10])
            )
        return [model_by_id[sample_id] for sample_id in fixed_sample_ids], stats

    quality_filter = {item.strip() for item in args.quality_filter.split(",") if item.strip()}
    eligible: list[dict[str, Any]] = []
    for row in model_rows:
        sample_id = row.get("sample_id")
        gold = gold_by_id.get(sample_id)
        index_row = sample_index_by_id.get(sample_id, {})
        if not gold:
            continue
        quality = index_row.get("quality") or index_row.get("quality_tier") or index_row.get("quality_label")
        if quality_filter and quality and quality not in quality_filter:
            continue
        context = context_by_original_scenario.get(row.get("scenario_id"))
        flags = (context or {}).get("quality_flags") or {}
        if args.exclude_manual_review and flags.get("needs_manual_review"):
            stats["manual_review_excluded"] += 1
            continue
        if args.require_vulnerability_context and context is None:
            stats["missing_vulnerability_context_excluded"] += 1
            continue
        eligible.append(row)

    by_stage: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in eligible:
        by_stage[stage_of(gold_by_id[row["sample_id"]], sample_index_by_id.get(row["sample_id"]))].append(row)

    selected: list[dict[str, Any]] = []
    used: set[str] = set()
    scenario_counts: Counter[str] = Counter()
    target = args.stage_targets_effective if args.stratify_by_stage else {}
    stage_order = [stage for stage in STAGE_ORDER if by_stage.get(stage) or stage in target]
    stage_order.extend(stage for stage in by_stage if stage not in stage_order)

    def can_add(row: dict[str, Any]) -> bool:
        if row["sample_id"] in used:
            return False
        if args.stratify_by_scenario and scenario_counts[row.get("scenario_id")] >= args.max_per_scenario:
            return False
        return True

    def add(row: dict[str, Any]) -> bool:
        if not can_add(row):
            return False
        selected.append(row)
        used.add(row["sample_id"])
        scenario_counts[row.get("scenario_id")] += 1
        return True

    if args.stratify_by_stage:
        if target:
            selected_by_stage: Counter[str] = Counter()
            for stage in stage_order:
                target_count = target.get(stage, 0)
                for row in by_stage.get(stage, []):
                    if len(selected) >= args.limit or selected_by_stage[stage] >= target_count:
                        break
                    if add(row):
                        selected_by_stage[stage] += 1
        while len(selected) < args.limit:
            progressed = False
            for stage in stage_order:
                for row in by_stage.get(stage, []):
                    if add(row):
                        progressed = True
                        break
                if len(selected) >= args.limit:
                    break
            if not progressed:
                break
    else:
        for row in eligible:
            if add(row) and len(selected) >= args.limit:
                break
    return selected[: args.limit], stats


def first_edge_id(primary_evidence: dict[str, Any]) -> str:
    for edge in primary_evidence.get("spine") or []:
        if edge.get("edge_id"):
            return str(edge["edge_id"])
    return "edge_m_000000"


def output_schema_for(sample_id: str, gold_stage: str, edge_id: str) -> dict[str, Any]:
    stage_reasoning_claim = (
        f"At seq 1 edge {edge_id}, PROCESS_OR_SERVICE performs EVENT_OR_ACTION on OBJECT_OR_TARGET; "
        f"temporal proximity, subject continuity, object/target consistency, and request/process/file/network chain links support stage {gold_stage} "
        "because STAGE_PREDICATE_GROUNDED_IN_THAT_FACT, while adjacent stages are not better supported."
    )
    if gold_stage == "stage_unclosed":
        final_claim = (
            f"At seq 1 edge {edge_id}, PROCESS_OR_SERVICE performs EVENT_OR_ACTION on OBJECT_OR_TARGET; "
            "the appropriate stage-closure label is stage_unclosed because the window is attack-related but the visible strict-blind evidence does not sufficiently close preparation, execution, or result."
        )
    elif gold_stage == "result":
        final_claim = (
            f"At seq 1 edge {edge_id}, PROCESS_OR_SERVICE performs EVENT_OR_ACTION on OUTCOME_OR_ARTIFACT; "
            "the visible evidence supports a result-stage interpretation in an evidence-limited sense."
        )
    elif gold_stage == "execution":
        final_claim = (
            f"At seq 1 edge {edge_id}, PROCESS_OR_SERVICE performs EVENT_OR_ACTION on OBJECT_OR_TARGET with "
            "EXECUTION_PREDICATE_BEYOND_NET_ACCEPT_RECV_OR_FORK; the visible evidence supports an execution-stage interpretation."
        )
    else:
        final_claim = (
            f"At seq 1 edge {edge_id}, PROCESS_OR_SERVICE performs EVENT_OR_ACTION on OBJECT_OR_TARGET; "
            f"the visible evidence supports a {gold_stage}-stage interpretation."
        )
    return {
        "sample_id": sample_id,
        "gold_stage": gold_stage,
        "gold_reasoning_chain": [
            {
                "step": "scenario_or_evidence_understanding",
                "claim": f"The visible multi-source evidence window has source coverage from primary evidence at seq 1 edge {edge_id}; missing or weak evidence conditions are stated separately, and the cited facts define the evidence boundary for the stage interpretation without making a final stage judgement.",
                "evidence_refs": [{"seq": 1, "edge_id": edge_id}],
            },
            {
                "step": "observable_evidence",
                "claim": "By source-bucketed audit/applog/traffic primary evidence, the cited directly visible facts show PROCESS_OR_SERVICE EVENT_OR_ACTION OBJECT_OR_TARGET, and these stage-relevant observable facts remain factual without inferring the final stage.",
                "evidence_refs": [{"seq": 1, "edge_id": edge_id}],
            },
            {
                "step": "attack_stage_path_reasoning",
                "claim": stage_reasoning_claim,
                "evidence_refs": [{"seq": 1, "edge_id": edge_id}],
            },
            {
                "step": "final_judgement",
                "claim": final_claim,
                "evidence_refs": [{"seq": 1, "edge_id": edge_id}],
            },
        ],
        "auxiliary_vulnerability_note": {
            "claim": "Auxiliary context note only; not used for scoring.",
            "not_for_scoring": True,
        },
    }


def build_prompt_row(
    sample: dict[str, Any],
    gold: dict[str, Any],
    context: dict[str, Any] | None,
    compact_config: dict[str, Any],
    consumer_role: str = "annotator",
) -> tuple[dict[str, Any], dict[str, Any]]:
    gold_stage = stage_of(gold)
    if compact_config.get("compact_version") == "v2":
        primary_evidence, compact_fidelity = compact_primary_evidence_v2(
            sample,
            gold_stage,
            compact_config,
            consumer_role,
        )
        primary_evidence = sanitize_prompt_visible_text(primary_evidence)
    else:
        primary_evidence = compact_primary_evidence(sample, compact_config)
        raw_counts = modality_counts_for_edges((sample.get("input") or {}).get("spine") or [])
        compact_counts = modality_counts_for_primary(primary_evidence)
        compact_fidelity = {
            "consumer_role": consumer_role,
            "gold_stage": gold_stage,
            "raw_counts": raw_counts,
            "compact_counts": compact_counts,
            "compression_ratio": {
                key: (compact_counts.get(key, 0) / raw_counts[key] if raw_counts.get(key) else None)
                for key in ("spine", "audit_context", "applog", "traffic")
            },
            "budget": compact_config["max_primary_edges"],
            "context_item_limits": {
                "audit_context": compact_config["max_audit_context_items"],
                "applog": compact_config["max_applog_items"],
                "traffic": compact_config["max_traffic_items"],
                "applog_message_chars": compact_config["max_applog_message_chars"],
            },
            "modality_floor_triggered": {key: False for key in COMPACT_V2_MODALITY_FLOORS},
            "raw_positive_compact_zero": {
                key: raw_counts.get(key, 0) > 0 and compact_counts.get(key, 0) == 0
                for key in ("audit_context", "applog", "traffic")
            },
        }
    schema = output_schema_for(sample["sample_id"], gold_stage, first_edge_id(primary_evidence))
    context_for_prompt = copy.deepcopy(context)
    if compact_config.get("compact_version") == "v2" and isinstance(context_for_prompt, dict):
        context_for_prompt["not_for_scoring"] = True
        context_for_prompt["scoring_use"] = "forbidden"
    role_instructions = role_instructions_for(consumer_role)
    prompt_input = {
        "sample_id": sample["sample_id"],
        "scenario_id": sample.get("scenario_id"),
        "gold_stage": gold_stage,
        "primary_evidence": primary_evidence,
        "auxiliary_vulnerability_context": context_for_prompt,
    }
    user_prompt = "\n".join(
        [
            TASK_INSTRUCTIONS,
            role_instructions,
            "## Input",
            json.dumps(prompt_input, ensure_ascii=False, indent=2),
            "## Required output schema",
            json.dumps(schema, ensure_ascii=False, indent=2),
        ]
    )
    row = {
        "schema_version": "ewvaa_annotation_prompt.masked.v1",
        "sample_id": sample["sample_id"],
        "scenario_id": sample.get("scenario_id"),
        "gold_stage": gold_stage,
        "mode": "ewvaa_masked_workbench_v1",
        "consumer_role": consumer_role,
        "compact_version": compact_config.get("compact_version", "v1"),
        "system": SYSTEM_PROMPT,
        "user": user_prompt,
        "prompt_input": prompt_input,
        "expected_output_schema": schema,
    }
    return row, compact_fidelity


def walk_strings(value: Any, path: tuple[str, ...] = ()) -> Iterable[tuple[tuple[str, ...], str]]:
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from walk_strings(item, path + (str(key),))
    elif isinstance(value, list):
        for idx, item in enumerate(value):
            yield from walk_strings(item, path + (str(idx),))


def load_json_or_jsonl(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def sample_ids_from_rows(rows: Iterable[dict[str, Any]], source: Path) -> list[str]:
    sample_ids: list[str] = []
    seen: set[str] = set()
    for idx, row in enumerate(rows, start=1):
        sample_id = str(row.get("sample_id") or "").strip()
        if not sample_id:
            raise SystemExit(f"{source} row {idx} is missing sample_id.")
        if sample_id not in seen:
            seen.add(sample_id)
            sample_ids.append(sample_id)
    return sample_ids


def load_sample_plan_ids(path: Path) -> list[str]:
    if path.suffix.lower() == ".jsonl":
        return sample_ids_from_rows(read_jsonl(path), path)
    doc = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(doc, dict):
        for key in ("selections", "samples", "sample_ids"):
            rows = doc.get(key)
            if isinstance(rows, list):
                if rows and all(isinstance(item, str) for item in rows):
                    return ordered_unique(str(item).strip() for item in rows)
                return sample_ids_from_rows(rows, path)
    if isinstance(doc, list):
        if doc and all(isinstance(item, str) for item in doc):
            return ordered_unique(str(item).strip() for item in doc)
        return sample_ids_from_rows(doc, path)
    raise SystemExit(f"Unsupported sample plan shape: {path}")


def load_sample_id_file(path: Path) -> list[str]:
    sample_ids: list[str] = []
    seen: set[str] = set()
    with path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            sample_id = line.strip()
            if not sample_id or sample_id.startswith("#"):
                continue
            if sample_id not in seen:
                seen.add(sample_id)
                sample_ids.append(sample_id)
    if not sample_ids:
        raise SystemExit(f"No sample ids found in {path}.")
    return sample_ids


def word_boundary_hits(text: str, tokens: Iterable[str]) -> list[str]:
    hits: list[str] = []
    for token in tokens:
        if re.search(rf"\b{re.escape(token)}\b", text, re.IGNORECASE):
            hits.append(token)
    return hits


def fallback_stage_reasoning_hints() -> dict[str, str]:
    return {
        "preparation": (
            "Preparation may be assigned only from cited primary evidence that shows setup, "
            "reconnaissance, access preparation, or capability checks. Do not infer it from "
            "scenario identity or auxiliary context."
        ),
        "execution": (
            "Execution may be assigned only from cited primary evidence showing the active core "
            "behavior. Do not infer it from scenario identity or auxiliary context."
        ),
        "result": (
            "Result may be assigned only from cited primary evidence showing a concrete outcome "
            "or artifact. Do not infer it from scenario identity or auxiliary context."
        ),
        "stage_unclosed": (
            "stage_unclosed should be used when the window is attack-related but visible strict-blind evidence does not "
            "sufficiently close preparation, execution, or result. It is a stage-closure label, not a fourth real attack lifecycle stage."
        ),
    }


def fallback_auxiliary_context(masked_scenario_id: str, original_scenario_id: str | None) -> dict[str, Any]:
    non_cve = "CVE-" not in str(original_scenario_id or "")
    summary = (
        "No seed-backed CVE auxiliary context exists for this non-CVE scenario. "
        "Treat the sample as primary-evidence-only."
        if non_cve
        else
        "Auxiliary vulnerability context is unavailable for this scenario in vulnerability_facts_seed. "
        "Treat the sample as primary-evidence-only."
    )
    return {
        "scenario_id": masked_scenario_id,
        "scenario_type": "non_cve_no_seed_context" if non_cve else "seed_context_unavailable",
        "product_hint": "auxiliary context unavailable",
        "affected_component_human": "auxiliary context unavailable",
        "official_context_summary": summary,
        "scenario_context_summary": summary,
        "mechanism_category": ["no auxiliary vulnerability context provided"],
        "impact_category": ["not for scoring; rely on primary evidence only"],
        "attack_surface_hint": "Use only observed primary evidence in the prompt input.",
        "observable_artifact_hints": [
            "Cite concrete seq and edge_id values from primary evidence only.",
            "Do not infer stage or outcome from scenario identity or benchmark metadata.",
            "If logs, files, processes, or network artifacts are absent in primary evidence, state that absence directly.",
        ],
        "stage_reasoning_hints": fallback_stage_reasoning_hints(),
        "annotation_prompt_context": (
            "No seed-backed CVE auxiliary context is available for this scenario. "
            "Use only primary evidence in the prompt input. Do not infer stage or outcome from "
            "metadata or scenario identity; final_judgement must cite seq and edge_id."
        ),
        "source_extracts": [],
        "quality_flags": {
            "context_missing_in_seed": True,
            "context_expected": not non_cve,
            "needs_manual_review": False,
        },
        "strict_use_constraints": {
            "auxiliary_not_for_scoring": True,
            "must_cite_primary_evidence": True,
            "must_not_infer_from_metadata": True,
        },
        "context_fallback": True,
    }


def stage_tokens_for(gold_stage: str) -> set[str]:
    return {"gold_stage", gold_stage}


def strict_chain_template_validation(row: dict[str, Any]) -> dict[str, Any]:
    allowed_steps = {"attack_stage_path_reasoning", "final_judgement"}
    violations: list[dict[str, Any]] = []
    tokens = stage_tokens_for(str(row.get("gold_stage") or ""))
    for item in ((row.get("expected_output_schema") or {}).get("gold_reasoning_chain") or []):
        step = str(item.get("step") or "")
        claim = str(item.get("claim") or "")
        hits = word_boundary_hits(claim, tokens)
        if step not in allowed_steps and hits:
            violations.append({"step": step, "hits": hits, "claim": claim})
    return {
        "sample_id": row.get("sample_id"),
        "gold_stage": row.get("gold_stage"),
        "valid": not violations,
        "violations": violations,
    }


def build_review_sample_plan(
    sample_index_by_original_id: dict[str, dict[str, Any]],
    sample_map: dict[str, str],
    scenario_map: dict[str, str],
    compact_fidelity_rows: list[dict[str, Any]],
    quality_summary_doc: dict[str, Any],
    output_dir: Path,
) -> dict[str, Any]:
    fidelity_by_original = {row["original_sample_id"]: row for row in compact_fidelity_rows}
    benchmark_ids = set(sample_index_by_original_id)
    selections: list[dict[str, Any]] = []
    mapping_errors: list[str] = []

    downgrade_rows = {
        str(row.get("sample_id") or ""): row
        for row in quality_summary_doc.get("strict_eval_downgrade_rows") or []
    }
    for idx, sample_id in enumerate(sorted(fidelity_by_original), start=1):
        index_row = sample_index_by_original_id.get(sample_id)
        fidelity = fidelity_by_original.get(sample_id)
        if not index_row:
            mapping_errors.append(sample_id)
            continue
        raw_spine = (fidelity or {}).get("raw_counts", {}).get("spine", 0)
        compact_spine = (fidelity or {}).get("compact_counts", {}).get("spine", 0)
        compact_ratio = (compact_spine / raw_spine) if raw_spine else None
        is_high_risk = bool(raw_spine > 1000 and compact_ratio is not None and compact_ratio < 0.1)
        selections.append(
            {
                "sample_id": sample_id,
                "masked_sample_id": sample_map.get(sample_id),
                "scenario_id": index_row.get("scenario_id"),
                "masked_scenario_id": scenario_map.get(index_row.get("scenario_id")),
                "gold_stage": index_row.get("stage"),
                "dataset": "SecLog-Bench-216",
                "is_high_risk": is_high_risk,
                "high_risk_reasons": (
                    ["spine_len>1000", "compact_ratio<0.1"] if is_high_risk else []
                ),
                "spine_len": raw_spine,
                "compact_spine_ratio": compact_ratio,
                "window": index_row.get("window"),
                "label_quality": (downgrade_rows.get(sample_id) or {}).get("label_quality"),
                "recommendation": "exclude_from_strict_eval" if sample_id in downgrade_rows else "keep_strict_eval",
                "rule_family": (downgrade_rows.get(sample_id) or {}).get("rule_family"),
                "notes": "Flagged by the unified benchmark quality audit." if sample_id in downgrade_rows else "",
                "selection_index": idx,
            }
        )

    stage_counts = dict(Counter(str(item.get("gold_stage") or "") for item in selections))
    high_risk_count = sum(1 for item in selections if item.get("is_high_risk"))
    unique_sample_ids = len({item["sample_id"] for item in selections}) == len(selections)
    all_sample_ids_from_benchmark = all(item["sample_id"] in benchmark_ids for item in selections)
    plan_doc = {
        "schema_version": "stage_reasoning_stratified_sample_plan.v1",
        "generated_at": __import__("datetime").datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
        "seed": 20260428,
        "sample_size": len(selections),
        "inputs": {
            "benchmark_data_root": str(DEFAULT_MODEL_INPUT.parent),
            "sample_index": str(DEFAULT_SAMPLE_INDEX),
            "quality_summary": str(DEFAULT_STAGE_LABEL_QUALITY_SUMMARY),
            "compact_report": str(output_dir / "reports/compact_fidelity_report.json"),
        },
        "rules": {
            "stage_quotas": dict(Counter(str(item.get("gold_stage") or "") for item in selections)),
            "high_risk_minimum": 0,
            "high_risk_definition": {
                "spine_len_gt": 1000,
                "compact_spine_ratio_lt": 0.1,
            },
        },
        "summary": {
            "selected_count": len(selections),
            "stage_counts": stage_counts,
            "high_risk_count": high_risk_count,
            "all_sample_ids_from_benchmark": all_sample_ids_from_benchmark,
            "unique_sample_ids": unique_sample_ids,
            "mapping_errors": mapping_errors,
            "all_masked_sample_ids_present": all(bool(item.get("masked_sample_id")) for item in selections),
            "all_masked_scenario_ids_present": all(bool(item.get("masked_scenario_id")) for item in selections),
        },
        "selections": selections,
    }
    plan_dir = output_dir / "stratified_sample_check"
    write_json(plan_dir / "sample_plan.review.json", plan_doc)
    write_jsonl(plan_dir / "sample_plan.review.jsonl", selections)
    lines = [
        "# Unified Benchmark Review Sample Plan",
        "",
        f"- selected_count: {len(selections)}",
        f"- high_risk_count: {high_risk_count}",
        f"- mapping_errors: {len(mapping_errors)}",
        "",
        "| idx | sample_id | masked_sample_id | stage | high_risk |",
        "| --- | --- | --- | --- | --- |",
    ]
    for item in selections:
        lines.append(
            f"| {item['selection_index']} | {item['sample_id']} | {item.get('masked_sample_id') or ''} | "
            f"{item['gold_stage']} | {str(bool(item['is_high_risk'])).lower()} |"
        )
    (plan_dir / "sample_plan.review.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return plan_doc


def prompt_components(row: dict[str, Any]) -> list[tuple[tuple[str, ...], Any]]:
    return [
        (("system",), row.get("system", "")),
        (("task_instructions",), TASK_INSTRUCTIONS),
        (("role_instructions",), role_instructions_for(str(row.get("consumer_role") or ""))),
        (("prompt_input",), row.get("prompt_input")),
        (("expected_output_schema",), row.get("expected_output_schema")),
    ]


def leakage_report_for(files: list[Path]) -> dict[str, Any]:
    metadata_hits: list[dict[str, Any]] = []
    semantic_hits: list[dict[str, Any]] = []
    primary_hits: list[dict[str, Any]] = []
    auxiliary_context_hits: list[dict[str, Any]] = []
    prompt_policy_hits: list[dict[str, Any]] = []
    checked_files: list[str] = []

    def maybe_add(target: list[dict[str, Any]], hit: dict[str, Any]) -> None:
        if len(target) < 500:
            target.append(hit)

    def may_contain_forbidden(text: str) -> bool:
        lower = text.lower()
        return (
            "cve-" in lower
            or "vulhub" in lower
            or "rce" in lower
            or "xxe" in lower
            or "sqli" in lower
            or "ssti" in lower
            or "command injection" in lower
            or "path traversal" in lower
            or "deserialization" in lower
            or "authentication bypass" in lower
            or "exploit" in lower
            or "payload" in lower
            or "shell obtained" in lower
            or "data exfiltration" in lower
            or "privilege escalation" in lower
            or "remote code execution" in lower
            or "poc" in lower
            or "public vulnerability description" in lower
        )

    def is_prompt_policy_path(path: tuple[str, ...]) -> bool:
        return any(part in {"system", "task_instructions", "role_instructions"} for part in path)

    def is_auxiliary_context_path(file_path: Path, path: tuple[str, ...]) -> bool:
        return file_path.name == "annotation_context.masked.json" or "auxiliary_vulnerability_context" in path

    def is_allowed_auxiliary_cve_id(path: tuple[str, ...], term: str) -> bool:
        return term == "CVE-" and "cve_ids" in path

    def scan_string(file_path: Path, path: tuple[str, ...], text: str) -> None:
        if not may_contain_forbidden(text):
            return
        primary = is_primary_evidence_path(path)
        is_auxiliary_context = is_auxiliary_context_path(file_path, path)
        is_policy = is_prompt_policy_path(path)
        for term in METADATA_FORBIDDEN_PATTERNS:
            if pattern_for(term).search(text):
                if is_auxiliary_context and is_allowed_auxiliary_cve_id(path, term):
                    continue
                hit = {"file": str(file_path), "path": ".".join(path), "pattern": term, "text": text[:240]}
                if is_policy:
                    maybe_add(prompt_policy_hits, hit)
                elif is_auxiliary_context:
                    maybe_add(auxiliary_context_hits, hit)
                elif primary:
                    maybe_add(primary_hits, hit)
                else:
                    maybe_add(metadata_hits, hit)
        for term in SEMANTIC_FORBIDDEN_PATTERNS:
            if pattern_for(term).search(text):
                hit = {"file": str(file_path), "path": ".".join(path), "pattern": term, "text": text[:240]}
                if is_policy:
                    maybe_add(prompt_policy_hits, hit)
                elif is_auxiliary_context:
                    maybe_add(auxiliary_context_hits, hit)
                elif primary:
                    maybe_add(primary_hits, hit)
                else:
                    maybe_add(semantic_hits, hit)

    prompt_pack_names = {
        "annotation_prompts.weighted.masked.jsonl",
        "reviewer_annotation_prompts.weighted.masked.jsonl",
    }
    for file_path in files:
        checked_files.append(str(file_path))
        if file_path.name in prompt_pack_names:
            for row_idx, row in enumerate(read_jsonl(file_path)):
                for root_path, component in prompt_components(row):
                    for path, text in walk_strings(component, (str(row_idx),) + root_path):
                        scan_string(file_path, path, text)
        elif file_path.suffix == ".jsonl":
            with file_path.open("r", encoding="utf-8") as handle:
                for row_idx, line in enumerate(handle):
                    line = line.strip()
                    if not line:
                        continue
                    payload = json.loads(line)
                    for path, text in walk_strings(payload, (str(row_idx),)):
                        scan_string(file_path, path, text)
        else:
            payload = load_json_or_jsonl(file_path)
            for path, text in walk_strings(payload):
                scan_string(file_path, path, text)

    metadata_clean = not metadata_hits
    prompt_clean = not semantic_hits
    return {
        "metadata_leakage_clean": metadata_clean,
        "prompt_leakage_clean": prompt_clean,
        "checked_files": checked_files,
        "metadata_forbidden_patterns": METADATA_FORBIDDEN_PATTERNS,
        "semantic_forbidden_patterns": SEMANTIC_FORBIDDEN_PATTERNS,
        "metadata_hits": metadata_hits,
        "semantic_hits": semantic_hits,
        "auxiliary_context_hits": auxiliary_context_hits,
        "auxiliary_context_leakage_clean": not auxiliary_context_hits,
        "primary_evidence_sensitive_terms": primary_hits,
        "allowed_prompt_policy_hits": prompt_policy_hits,
        "forbidden_terms_policy_present": bool(prompt_policy_hits),
        "notes": [
            "Primary evidence sensitive terms are reported separately and do not fail metadata masking.",
            "Prompt pack scanning uses structured prompt_input plus prompt instructions/schema to classify primary evidence correctly.",
            "Forbidden-term policy mentions inside system/task/role instructions are allowed policy text, not evidence leakage.",
        ],
    }


def parse_stage_targets(raw: str | None, limit: int, stratify_by_stage: bool) -> tuple[dict[str, int], list[str]]:
    warnings: list[str] = []
    if raw:
        targets: dict[str, int] = {}
        for item in raw.split(","):
            item = item.strip()
            if not item:
                continue
            if "=" not in item:
                raise SystemExit(f"Invalid --stage-targets item {item!r}; expected stage=count.")
            stage, count_text = item.split("=", 1)
            stage = stage.strip()
            try:
                count = int(count_text.strip())
            except ValueError as exc:
                raise SystemExit(f"Invalid --stage-targets count for {stage!r}: {count_text!r}") from exc
            if count < 0:
                raise SystemExit(f"Invalid --stage-targets count for {stage!r}: count must be >= 0.")
            targets[stage] = count
    elif stratify_by_stage and limit == 10:
        targets = dict(DEFAULT_STAGE_TARGET_10)
    else:
        targets = {}
    target_total = sum(targets.values())
    if targets and target_total != limit:
        warnings.append(
            f"stage-targets sum ({target_total}) does not match limit ({limit}); "
            "selection prioritizes stage targets, then fills remaining capacity if any."
        )
    return targets, warnings


def compact_config_from_args(args: argparse.Namespace) -> dict[str, Any]:
    return {
        "max_primary_edges": args.max_primary_edges,
        "max_applog_message_chars": args.max_applog_message_chars,
        "max_audit_context_items": args.max_audit_context_items,
        "max_traffic_items": args.max_traffic_items,
        "max_applog_items": args.max_applog_items,
        "compact_version": args.compact_version,
        "stage_adaptive_budget": args.stage_adaptive_budget,
        "modality_floor": args.modality_floor,
        "reviewer_more_evidence": args.reviewer_more_evidence,
        "api_safe_budget": args.api_safe_budget,
        "long_window_threshold": args.long_window_threshold,
        "annotator_long_window_primary_cap": args.annotator_long_window_primary_cap,
        "reviewer_long_window_primary_cap": args.reviewer_long_window_primary_cap,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Build the EWVAA masked workbench. "
            "Workbench paths must be passed explicitly for reproducible runs."
        )
    )
    parser.add_argument("--split", choices=("unified_216",), default="unified_216")
    parser.add_argument("--model-input", type=Path, default=DEFAULT_MODEL_INPUT)
    parser.add_argument("--gold", type=Path, default=DEFAULT_GOLD)
    parser.add_argument("--sample-index", type=Path, default=DEFAULT_SAMPLE_INDEX)
    parser.add_argument("--canonical-manifest", type=Path, default=DEFAULT_CANONICAL_MANIFEST)
    parser.add_argument("--strict-blind-manifest", type=Path, default=DEFAULT_STRICT_BLIND_MANIFEST)
    parser.add_argument("--strict-blind-sample-id-map", type=Path, default=DEFAULT_STRICT_BLIND_SAMPLE_ID_MAP)
    parser.add_argument("--stage-label-quality-summary", type=Path, default=DEFAULT_STAGE_LABEL_QUALITY_SUMMARY)
    parser.add_argument("--annotation-context", type=Path, default=DEFAULT_ANNOTATION_CONTEXT)
    parser.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help=(
            "Required. A public benchmark run should not silently default to "
            "workdir/compact_annotation_workbench; "
            "pass an explicit output directory for the intended run."
        ),
    )
    parser.add_argument("--limit", type=int, default=216)
    parser.add_argument(
        "--sample-plan",
        type=Path,
        help="Fixed sample plan (.json/.jsonl) containing sample_id values. When set, it takes precedence over --limit and stratified sampling.",
    )
    parser.add_argument(
        "--sample-id-file",
        type=Path,
        help="Fixed newline-delimited sample_id list. When set, it takes precedence over --limit and stratified sampling.",
    )
    parser.add_argument("--quality-filter", default="A,B")
    parser.add_argument("--stage-targets", help="Comma-separated stage counts, e.g. preparation=3,execution=3,result=2,stage_unclosed=2")
    parser.add_argument("--exclude-manual-review", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--require-vulnerability-context", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--stratify-by-stage", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--stratify-by-scenario", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--max-per-scenario", type=int, default=2)
    parser.add_argument("--max-primary-edges", type=int, default=DEFAULT_COMPACT_CONFIG["max_primary_edges"])
    parser.add_argument(
        "--max-applog-message-chars", type=int, default=DEFAULT_COMPACT_CONFIG["max_applog_message_chars"]
    )
    parser.add_argument("--max-audit-context-items", type=int, default=DEFAULT_COMPACT_CONFIG["max_audit_context_items"])
    parser.add_argument("--max-traffic-items", type=int, default=DEFAULT_COMPACT_CONFIG["max_traffic_items"])
    parser.add_argument("--max-applog-items", type=int, default=DEFAULT_COMPACT_CONFIG["max_applog_items"])
    parser.add_argument("--compact-version", choices=("v1", "v2"), default="v1")
    parser.add_argument("--stage-adaptive-budget", action=argparse.BooleanOptionalAction, default=False)
    parser.add_argument("--modality-floor", action=argparse.BooleanOptionalAction, default=False)
    parser.add_argument("--reviewer-more-evidence", action=argparse.BooleanOptionalAction, default=False)
    parser.add_argument("--api-safe-budget", action=argparse.BooleanOptionalAction, default=False)
    parser.add_argument("--long-window-threshold", type=int, default=DEFAULT_COMPACT_CONFIG["long_window_threshold"])
    parser.add_argument(
        "--annotator-long-window-primary-cap",
        type=int,
        default=DEFAULT_COMPACT_CONFIG["annotator_long_window_primary_cap"],
    )
    parser.add_argument(
        "--reviewer-long-window-primary-cap",
        type=int,
        default=DEFAULT_COMPACT_CONFIG["reviewer_long_window_primary_cap"],
    )
    parser.add_argument("--overwrite", action="store_true", help="Allow replacing an existing output directory.")
    parser.add_argument(
        "--allow-existing-output-dir",
        action="store_true",
        help="Allow writing into an existing output directory without deleting it.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.sample_plan and args.sample_id_file:
        raise SystemExit("Use only one of --sample-plan or --sample-id-file.")
    args.fixed_sample_ids = []
    args.fixed_sample_source = None
    if args.sample_plan:
        args.fixed_sample_ids = load_sample_plan_ids(args.sample_plan)
        args.fixed_sample_source = str(args.sample_plan)
    elif args.sample_id_file:
        args.fixed_sample_ids = load_sample_id_file(args.sample_id_file)
        args.fixed_sample_source = str(args.sample_id_file)
    for name in (
        "max_primary_edges",
        "max_applog_message_chars",
        "max_audit_context_items",
        "max_traffic_items",
        "max_applog_items",
        "long_window_threshold",
        "annotator_long_window_primary_cap",
        "reviewer_long_window_primary_cap",
    ):
        if getattr(args, name) < 0:
            raise SystemExit(f"--{name.replace('_', '-')} must be >= 0.")
    args.stage_targets_effective, stage_target_warnings = parse_stage_targets(
        args.stage_targets, args.limit, args.stratify_by_stage
    )
    compact_config = compact_config_from_args(args)
    if args.output_dir.exists():
        if not args.overwrite and not args.allow_existing_output_dir:
            raise SystemExit(
                f"Output directory already exists: {args.output_dir}. "
                "Use a new --output-dir, pass --allow-existing-output-dir, or pass --overwrite."
            )
        if args.overwrite:
            shutil.rmtree(args.output_dir)

    model_rows = read_jsonl(args.model_input)
    gold_rows = read_jsonl(args.gold)
    sample_index_rows = read_jsonl(args.sample_index)
    annotation_doc = json.loads(args.annotation_context.read_text(encoding="utf-8"))
    canonical_manifest = json.loads(args.canonical_manifest.read_text(encoding="utf-8"))
    strict_blind_manifest = json.loads(args.strict_blind_manifest.read_text(encoding="utf-8"))
    strict_blind_sample_id_map_doc = json.loads(args.strict_blind_sample_id_map.read_text(encoding="utf-8"))
    if args.stage_label_quality_summary.exists():
        stage_label_quality_summary_doc = json.loads(args.stage_label_quality_summary.read_text(encoding="utf-8"))
    elif args.fixed_sample_ids:
        stage_label_quality_summary_doc = {}
    else:
        raise SystemExit(f"Missing stage label quality summary: {args.stage_label_quality_summary}")

    scenarios: list[str] = []
    samples: list[str] = []
    edges: list[str] = []
    id_collection_stats = {"placeholder_ids_excluded": 0}
    for payload in (model_rows, gold_rows, sample_index_rows, annotation_doc):
        collect_ids(payload, scenarios, samples, edges, id_collection_stats)

    scenario_map_doc = id_map_doc("scenario", ordered_unique(scenarios))
    sample_map_doc = id_map_doc("sample", ordered_unique(samples))
    edge_map_doc = id_map_doc("edge", ordered_unique(edges))
    scenario_map = map_lookup(scenario_map_doc)
    sample_map = map_lookup(sample_map_doc)
    edge_map = map_lookup(edge_map_doc)
    masker = MetadataMasker(scenario_map, sample_map, edge_map)

    masked_model_rows = [masker.mask_value(row) for row in model_rows]
    masked_gold_rows = [masker.mask_value(row) for row in gold_rows]
    masked_sample_index_rows = [masker.mask_value(row) for row in sample_index_rows]
    masked_annotation_context = clean_annotation_context(annotation_doc, masker, args.annotation_context)

    output_dir = args.output_dir
    masked_inputs_dir = output_dir / "masked_inputs"
    id_maps_dir = output_dir / "id_maps"
    aux_dir = output_dir / "auxiliary_context"
    prompt_dir = output_dir / "prompt_packs"
    reports_dir = output_dir / "reports"

    model_count = write_jsonl(masked_inputs_dir / "model_input.masked.jsonl", masked_model_rows)
    gold_count = write_jsonl(masked_inputs_dir / "gold.masked.jsonl", masked_gold_rows)
    sample_index_count = write_jsonl(masked_inputs_dir / "sample_index.masked.jsonl", masked_sample_index_rows)
    write_json(id_maps_dir / "scenario_id_map.json", scenario_map_doc)
    write_json(id_maps_dir / "sample_id_map.json", sample_map_doc)
    write_json(id_maps_dir / "edge_id_map.json", edge_map_doc)
    write_json(aux_dir / "annotation_context.masked.json", masked_annotation_context)

    gold_by_original_id = {row["sample_id"]: row for row in gold_rows}
    sample_index_by_original_id = {row["sample_id"]: row for row in sample_index_rows}
    original_context = original_context_by_scenario(annotation_doc)
    selected_original, selection_stats = select_samples(
        model_rows, gold_by_original_id, sample_index_by_original_id, original_context, args
    )

    masked_model_by_sample = {row["sample_id"]: row for row in masked_model_rows}
    masked_gold_by_sample = {row["sample_id"]: row for row in masked_gold_rows}
    masked_context = context_by_scenario(masked_annotation_context)
    prompt_rows: list[dict[str, Any]] = []
    reviewer_prompt_rows: list[dict[str, Any]] = []
    compact_fidelity_rows: list[dict[str, Any]] = []
    reviewer_compact_fidelity_rows: list[dict[str, Any]] = []
    missing_context: list[dict[str, str]] = []
    fallback_context_rows: list[dict[str, Any]] = []
    context_attachment_rows: list[dict[str, Any]] = []
    manual_review_context_attached = 0
    for original_sample in selected_original:
        masked_sample_id = sample_map[original_sample["sample_id"]]
        masked_sample = masked_model_by_sample[masked_sample_id]
        masked_gold = masked_gold_by_sample[masked_sample_id]
        context = masked_context.get(masked_sample.get("scenario_id"))
        original_scenario_id = str(original_sample.get("scenario_id") or "")
        had_seed_context = context is not None
        if context is None:
            expected_seed_context = "CVE-" in original_scenario_id
            if expected_seed_context:
                missing_context.append(
                    {
                        "sample_id": masked_sample_id,
                        "scenario_id": str(masked_sample.get("scenario_id")),
                        "original_scenario_id": original_scenario_id,
                    }
                )
            context = fallback_auxiliary_context(str(masked_sample.get("scenario_id")), original_scenario_id)
            fallback_context_rows.append(
                {
                    "sample_id": masked_sample_id,
                    "original_sample_id": original_sample["sample_id"],
                    "scenario_id": str(masked_sample.get("scenario_id")),
                    "original_scenario_id": original_scenario_id,
                    "context_expected_in_seed": expected_seed_context,
                }
            )
        elif (context.get("quality_flags") or {}).get("needs_manual_review"):
            manual_review_context_attached += 1
        context_attachment_rows.append(
            {
                "sample_id": masked_sample_id,
                "original_sample_id": original_sample["sample_id"],
                "scenario_id": str(masked_sample.get("scenario_id")),
                "original_scenario_id": original_scenario_id,
                "seed_context_attached": had_seed_context,
                "fallback_context_attached": not had_seed_context,
                "cve_context_expected": "CVE-" in original_scenario_id,
            }
        )
        prompt_row, fidelity = build_prompt_row(masked_sample, masked_gold, context, compact_config, "annotator")
        fidelity.update(
            {
                "sample_id": masked_sample_id,
                "original_sample_id": original_sample["sample_id"],
                "scenario_id": masked_sample.get("scenario_id"),
                "original_scenario_id": original_sample.get("scenario_id"),
            }
        )
        prompt_rows.append(prompt_row)
        compact_fidelity_rows.append(fidelity)
        if compact_config.get("compact_version") == "v2" and compact_config.get("reviewer_more_evidence"):
            reviewer_row, reviewer_fidelity = build_prompt_row(masked_sample, masked_gold, context, compact_config, "reviewer")
            reviewer_fidelity.update(
                {
                    "sample_id": masked_sample_id,
                    "original_sample_id": original_sample["sample_id"],
                    "scenario_id": masked_sample.get("scenario_id"),
                    "original_scenario_id": original_sample.get("scenario_id"),
                }
            )
            reviewer_prompt_rows.append(reviewer_row)
            reviewer_compact_fidelity_rows.append(reviewer_fidelity)

    prompt_count = write_jsonl(prompt_dir / "annotation_prompts.weighted.masked.jsonl", prompt_rows)
    reviewer_prompt_count = 0
    reviewer_prompt_path = prompt_dir / "reviewer_annotation_prompts.weighted.masked.jsonl"
    if reviewer_prompt_rows:
        reviewer_prompt_count = write_jsonl(reviewer_prompt_path, reviewer_prompt_rows)

    stage_distribution = dict(Counter(row["gold_stage"] for row in prompt_rows))
    scenario_distribution_masked = dict(Counter(row["scenario_id"] for row in prompt_rows))
    all_prompts_use_masked_sample_id = all(str(row.get("sample_id", "")).startswith("sample_m_") for row in prompt_rows)
    all_prompts_use_masked_edge_id = all(
        str(ref.get("edge_id", "")).startswith("edge_m_")
        for row in prompt_rows
        for step in row["expected_output_schema"]["gold_reasoning_chain"]
        for ref in step.get("evidence_refs", [])
    )
    all_prompts_include_annotation_prompt_context = all(
        bool(((row.get("prompt_input") or {}).get("auxiliary_vulnerability_context") or {}).get("annotation_prompt_context"))
        for row in prompt_rows
    )

    checked_files = [
        masked_inputs_dir / "model_input.masked.jsonl",
        masked_inputs_dir / "gold.masked.jsonl",
        masked_inputs_dir / "sample_index.masked.jsonl",
        aux_dir / "annotation_context.masked.json",
        prompt_dir / "annotation_prompts.weighted.masked.jsonl",
    ]
    if reviewer_prompt_rows:
        checked_files.append(reviewer_prompt_path)
    leak = leakage_report_for(checked_files)
    write_json(reports_dir / "leakage_report.json", leak)

    reviewer_by_sample = {row["sample_id"]: row for row in reviewer_compact_fidelity_rows}
    reviewer_vs_annotator = []
    for row in compact_fidelity_rows:
        reviewer_row = reviewer_by_sample.get(row["sample_id"])
        reviewer_vs_annotator.append(
            {
                "sample_id": row["sample_id"],
                "original_sample_id": row["original_sample_id"],
                "annotator_budget": row["budget"],
                "reviewer_budget": (reviewer_row or {}).get("budget"),
                "annotator_compact_counts": row["compact_counts"],
                "reviewer_compact_counts": (reviewer_row or {}).get("compact_counts"),
            }
        )
    top_high_risk_samples = []
    for fidelity in sorted(
        compact_fidelity_rows,
        key=lambda row: (
            not bool(row.get("raw_counts", {}).get("spine", 0) > 1000
                     and row.get("compact_counts", {}).get("spine", 0) / max(row.get("raw_counts", {}).get("spine", 1), 1) < 0.1),
            -row.get("raw_counts", {}).get("spine", 0),
        ),
    )[:8]:
        raw_spine = int(fidelity.get("raw_counts", {}).get("spine", 0) or 0)
        compact_spine = int(fidelity.get("compact_counts", {}).get("spine", 0) or 0)
        top_high_risk_samples.append(
            {
                "original_sample_id": fidelity.get("original_sample_id"),
                "present_in_prompt_pack": True,
                "is_high_risk": raw_spine > 1000 and compact_spine / max(raw_spine, 1) < 0.1,
                "fidelity": fidelity,
            }
        )
    modality_zero_cases = [
        {
            "sample_id": row["sample_id"],
            "original_sample_id": row["original_sample_id"],
            "raw_positive_compact_zero": row["raw_positive_compact_zero"],
            "raw_counts": row["raw_counts"],
            "compact_counts": row["compact_counts"],
        }
        for row in compact_fidelity_rows
        if any(row["raw_positive_compact_zero"].values())
    ]
    largest_raw_context_samples = sorted(
        compact_fidelity_rows,
        key=lambda row: (
            row["raw_counts"].get("audit_context", 0)
            + row["raw_counts"].get("applog", 0)
            + row["raw_counts"].get("traffic", 0)
        ),
        reverse=True,
    )[:10]
    compact_fidelity_report = {
        "schema_version": "ewvaa_compact_fidelity_report.v2",
        "compact_version": compact_config.get("compact_version", "v1"),
        "selected_prompt_samples": prompt_count,
        "reviewer_prompt_samples": reviewer_prompt_count,
        "stage_adaptive_budget_enabled": bool(compact_config.get("stage_adaptive_budget")),
        "stage_adaptive_budgets": COMPACT_V2_STAGE_BUDGETS,
        "modality_floor_enabled": bool(compact_config.get("modality_floor")),
        "modality_floor_targets": COMPACT_V2_MODALITY_FLOORS,
        "api_safe_budget": {
            "enabled": bool(compact_config.get("api_safe_budget")),
            "long_window_threshold": compact_config.get("long_window_threshold"),
            "annotator_long_window_primary_cap": compact_config.get("annotator_long_window_primary_cap"),
            "reviewer_long_window_primary_cap": compact_config.get("reviewer_long_window_primary_cap"),
        },
        "sample_fidelity": compact_fidelity_rows,
        "reviewer_sample_fidelity": reviewer_compact_fidelity_rows,
        "modality_zero_cases": modality_zero_cases,
        "top_high_risk_samples": top_high_risk_samples,
        "largest_raw_context_samples": largest_raw_context_samples,
        "leakage_check_result": {
            "metadata_leakage_clean": leak["metadata_leakage_clean"],
            "prompt_leakage_clean": leak["prompt_leakage_clean"],
            "auxiliary_context_leakage_clean": leak["auxiliary_context_leakage_clean"],
            "leakage_clean": bool(
                leak["metadata_leakage_clean"]
                and leak["prompt_leakage_clean"]
                and leak["auxiliary_context_leakage_clean"]
            ),
        },
        "reviewer_vs_annotator_evidence_budget": reviewer_vs_annotator,
        "not_for_scoring_policy": {
            "auxiliary_vulnerability_context_not_for_scoring": compact_config.get("compact_version") == "v2",
            "cve_context_allowed_only_as_annotation_background": True,
            "canonical_model_input_modified": False,
        },
    }
    write_json(reports_dir / "compact_fidelity_report.json", compact_fidelity_report)
    write_json(output_dir / "compact_fidelity_report.json", compact_fidelity_report)

    id_summary = {
        "schema_version": "ewvaa_id_map_summary.v1",
        "scenario_ids_mapped": len(scenario_map_doc["items"]),
        "sample_ids_mapped": len(sample_map_doc["items"]),
        "edge_ids_mapped": len(edge_map_doc["items"]),
        "placeholder_ids_excluded": id_collection_stats["placeholder_ids_excluded"],
        "scenario_map_complete": len(scenario_map_doc["items"]) == len(set(scenarios)),
        "sample_map_complete": len(sample_map_doc["items"]) == len(set(samples)),
        "edge_map_complete": len(edge_map_doc["items"]) == len(set(edges)),
        "restore_direction": "Use each item as masked -> original.",
    }
    write_json(id_maps_dir / "id_map_summary.json", id_summary)

    masking_report = {
        "total_input_samples": len(model_rows),
        "selected_prompt_samples": prompt_count,
        "reviewer_prompt_samples": reviewer_prompt_count,
        "scenario_ids_mapped": len(scenario_map_doc["items"]),
        "sample_ids_mapped": len(sample_map_doc["items"]),
        "edge_ids_mapped": len(edge_map_doc["items"]),
        "model_input_masked_rows": model_count,
        "gold_masked_rows": gold_count,
        "sample_index_masked_rows": sample_index_count,
        "manual_review_excluded": selection_stats["manual_review_excluded"],
        "missing_vulnerability_context_excluded": selection_stats["missing_vulnerability_context_excluded"],
        "stage_distribution": stage_distribution,
        "stage_targets_effective": args.stage_targets_effective,
        "fixed_sample_source": args.fixed_sample_source,
        "fixed_sample_count": len(args.fixed_sample_ids),
        "warnings": stage_target_warnings,
        "compact_config": compact_config,
        "placeholder_ids_excluded": id_collection_stats["placeholder_ids_excluded"],
        "scenario_distribution_masked": scenario_distribution_masked,
        "original_files_modified": False,
    }
    write_json(reports_dir / "masking_report.json", masking_report)

    prompt_pack_report = {
        "total_prompts": prompt_count,
        "reviewer_prompts": reviewer_prompt_count,
        "stage_distribution": stage_distribution,
        "stage_targets_effective": args.stage_targets_effective,
        "fixed_sample_source": args.fixed_sample_source,
        "fixed_sample_count": len(args.fixed_sample_ids),
        "warnings": stage_target_warnings,
        "compact_config": compact_config,
        "scenario_distribution_masked": scenario_distribution_masked,
        "all_prompts_use_masked_sample_id": all_prompts_use_masked_sample_id,
        "all_prompts_use_masked_edge_id": all_prompts_use_masked_edge_id,
        "all_prompts_include_annotation_prompt_context": all_prompts_include_annotation_prompt_context,
        "manual_review_context_attached": manual_review_context_attached,
        "missing_vulnerability_context": missing_context,
        "fallback_auxiliary_context_rows": fallback_context_rows,
        "leakage_clean": bool(
            leak["metadata_leakage_clean"]
            and leak["prompt_leakage_clean"]
            and leak["auxiliary_context_leakage_clean"]
        ),
    }
    write_json(reports_dir / "prompt_pack_report.json", prompt_pack_report)

    strict_chain_rows = [strict_chain_template_validation(row) for row in prompt_rows]
    strict_chain_ok = all(row["valid"] for row in strict_chain_rows)
    canonical_dataset = canonical_manifest.get("dataset") or {}
    strict_blind_dataset = strict_blind_manifest.get("dataset") or {}
    canonical_stage_derivation = canonical_manifest.get("source_stage_derivation")
    strict_blind_stage_derivation = strict_blind_manifest.get("source_stage_derivation")
    strict_blind_original_sample_ids = [item.get("original") for item in strict_blind_sample_id_map_doc.get("items", [])]
    canonical_sample_ids = [row.get("sample_id") for row in model_rows]
    selected_original_sample_ids = [row.get("sample_id") for row in selected_original]
    reviewer_budget_ok = all(
        item.get("reviewer_budget") is None or item.get("reviewer_budget", 0) >= item.get("annotator_budget", 0)
        for item in reviewer_vs_annotator
    )
    cve_expected_total = sum(1 for row in context_attachment_rows if row["cve_context_expected"])
    cve_expected_seed_attached = sum(
        1 for row in context_attachment_rows if row["cve_context_expected"] and row["seed_context_attached"]
    )
    review_plan_doc = build_review_sample_plan(
        sample_index_by_original_id,
        sample_map,
        scenario_map,
        compact_fidelity_rows,
        stage_label_quality_summary_doc,
        output_dir,
    )
    alignment_validation_report = {
        "schema_version": "ewvaa_alignment_validation.v1",
        "dataset": "SecLog-Bench-216",
        "workbench_dir": str(output_dir),
        "prompt_pack_dir": str(prompt_dir),
        "source_paths": {
            "canonical_manifest": str(args.canonical_manifest),
            "strict_blind_manifest": str(args.strict_blind_manifest),
            "vulnerability_facts_seed": str(args.annotation_context),
            "quality_summary": str(args.stage_label_quality_summary),
        },
        "counts": {
            "canonical_dataset_expected": canonical_dataset.get("sample_count"),
            "strict_blind_dataset_expected": strict_blind_dataset.get("sample_count"),
            "annotator_prompts": prompt_count,
            "reviewer_prompt_samples": reviewer_prompt_count,
            "reviewer_prompts": reviewer_prompt_count,
        },
        "sample_alignment": {
            "selected_sample_ids_match_canonical_dataset": set(selected_original_sample_ids) == set(canonical_sample_ids),
            "selected_sample_id_count_matches_canonical_dataset": len(selected_original_sample_ids) == len(canonical_sample_ids),
            "sample_id_map_matches_canonical_count": len(sample_map_doc["items"]) == len(canonical_sample_ids),
            "sample_id_map_originals_match_canonical": set(item.get("original") for item in sample_map_doc["items"]) == set(canonical_sample_ids),
            "strict_blind_original_sample_ids_match_canonical": set(strict_blind_original_sample_ids) == set(canonical_sample_ids),
            "new_sample_id_map_matches_canonical_count": len(sample_map_doc["items"]) == len(canonical_sample_ids),
        },
        "stage_derivation": {
            "canonical_manifest": canonical_stage_derivation,
            "strict_blind_manifest": strict_blind_stage_derivation,
            "expected": "stage_derivation_v0.4.5",
            "aligned": (
                canonical_stage_derivation == "stage_derivation_v0.4.5"
                and strict_blind_stage_derivation == "stage_derivation_v0.4.5"
            ),
        },
        "auxiliary_context": {
            "reused_vulnerability_facts_seed": True,
            "seed_context_prompt_samples": sum(1 for row in context_attachment_rows if row["seed_context_attached"]),
            "fallback_context_prompt_samples": sum(1 for row in context_attachment_rows if row["fallback_context_attached"]),
            "cve_context_expected_prompt_samples": cve_expected_total,
            "cve_context_attached_from_seed": cve_expected_seed_attached,
            "cve_context_missing_from_seed": cve_expected_total - cve_expected_seed_attached,
            "fallback_rows": fallback_context_rows,
            "all_prompts_include_annotation_prompt_context": all_prompts_include_annotation_prompt_context,
        },
        "strict_chain": {
            "gold_stage_leakage_outside_allowed_steps": not strict_chain_ok,
            "checked_rows": len(strict_chain_rows),
            "violation_count": sum(1 for row in strict_chain_rows if not row["valid"]),
            "violations": [row for row in strict_chain_rows if not row["valid"]],
        },
        "compact_v2_plus": {
            "compact_version": compact_config.get("compact_version"),
            "reviewer_more_evidence": bool(compact_config.get("reviewer_more_evidence")),
            "compact_v3_generated": False,
            "modality_zero_cases": len(modality_zero_cases),
            "reviewer_budget_not_less_than_annotator": reviewer_budget_ok,
            "api_safe_budget": bool(compact_config.get("api_safe_budget")),
        },
        "review_sample_plan": {
            "path": str(output_dir / "stratified_sample_check" / "sample_plan.review.json"),
            "selected_count": review_plan_doc["summary"]["selected_count"],
            "mapping_errors": review_plan_doc["summary"]["mapping_errors"],
            "all_sample_ids_from_benchmark": review_plan_doc["summary"]["all_sample_ids_from_benchmark"],
            "all_masked_sample_ids_present": review_plan_doc["summary"]["all_masked_sample_ids_present"],
        },
        "forbidden_actions": {
            "called_api": False,
            "modified_raw_index": False,
            "modified_canonical_benchmark": False,
            "generated_final_candidate_gold": False,
            "ran_ewvaa_01_02_03_04_05": False,
            "refetched_cve_or_nvd_or_vulhub": False,
        },
    }
    write_json(reports_dir / "alignment_validation_report.json", alignment_validation_report)

    readme = f"""# EWVAA Masked Workbench v1

The canonical benchmark workspace supplied to this run was not modified.

This directory is the model-facing and API-facing masked workbench for EWVAA annotation, trials, and judge workflows. It masks benchmark metadata identifiers while preserving primary evidence facts such as HTTP, process, file, network, application log, traffic, seq, timestamp, subject, object, and audit relations.

The `id_maps/` files restore masked `sample_id`, `scenario_id`, and `edge_id` values back to their canonical originals. Use those maps for offline reconciliation only.

Compact mode: `{compact_config.get("compact_version", "v1")}`.

For `compact_v2`, annotator prompts use stage-adaptive budgets (`execution`/`stage_unclosed`: 100 primary edges; `preparation`/`result`: 60 primary edges) with modality floors for audit, applog, and traffic. When reviewer-more-evidence is enabled, `prompt_packs/reviewer_annotation_prompts.weighted.masked.jsonl` uses larger reviewer budgets (`execution`/`stage_unclosed`: 140; `preparation`/`result`: 90). If `api_safe_budget` is enabled, only long-window samples above the configured threshold are capped to smaller compact_v2-safe budgets while preserving modality floors and reviewer >= annotator. See `reports/compact_fidelity_report.json`.

This workbench is validated against the canonical and strict-blind manifests supplied by the run. See `reports/alignment_validation_report.json`.

Future EWVAA API trials and judge runs should use this workbench as input. Formal experiments should not use unmasked prompt directories directly.
"""
    (output_dir / "README.md").write_text(readme, encoding="utf-8")

    print(
        json.dumps(
            {
                "script": "results_analysis/release/build_ewvaa_masked_workbench.py",
                "output_dir": str(output_dir),
                "prompt_count": prompt_count,
                "stage_distribution": stage_distribution,
                "stage_targets_effective": args.stage_targets_effective,
                "compact_config": compact_config,
                "placeholder_ids_excluded": id_collection_stats["placeholder_ids_excluded"],
                "id_maps_complete": all(
                    [
                        id_summary["scenario_map_complete"],
                        id_summary["sample_map_complete"],
                        id_summary["edge_map_complete"],
                    ]
                ),
                "metadata_leakage_clean": leak["metadata_leakage_clean"],
                "prompt_leakage_clean": leak["prompt_leakage_clean"],
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
