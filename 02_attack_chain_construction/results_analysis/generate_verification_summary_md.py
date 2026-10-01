#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
METRICS = PROJECT_ROOT / "results_analysis" / "verification_metrics.json"
OUT_MD = PROJECT_ROOT / "verification_summary_all_scenarios.md"


def pct(x):
    if x is None:
        return 'N/A'
    return f'{x*100:.2f}%'


def scene_name(scene: str) -> tuple[str, str]:
    if '/' not in scene:
        return scene, '-'
    p = scene.split('/')
    app = p[-2] if len(p) >= 2 else p[0]
    cve = p[-1]
    if not cve.startswith('CVE-'):
        return scene, '-'
    return app, cve


def runtime_scope(runtime: str, scene: str) -> str:
    if runtime in {'php', 'java'}:
        return 'in-scope'
    if scene == 'multi-jump':
        return 'partial-scope'
    return 'out-of-scope'


def main():
    rows = json.loads(METRICS.read_text(encoding='utf-8'))['rows']

    # Part A table
    a_lines = []
    a_lines.append('| Application | CVE | Total units | Valid units | VTID concentration | Attack-chain edges (unit!=empty) | Distinct units in chain | Conclusion |')
    a_lines.append('| -- | -- | --: | --: | -- | --: | --: | -- |')

    for r in rows:
        s = r['stage1']
        app, cve = scene_name(r['scenario'])
        conc = s.get('vtid_concentration_proxy')
        conc_s = 'N/A' if conc is None else f'{conc:.3f} (unit-distribution proxy)'

        # scope override
        scope = runtime_scope(r['runtime'], r['scenario'])
        concl = s.get('conclusion', 'N/A')
        if scope == 'out-of-scope':
            concl = 'N/A (outside the runtime-aware Stage-1 validation scope for this run)'
        elif scope == 'partial-scope':
            concl = 'N/A (component-level runtime-aware validation is incomplete for multi-jump)'

        a_lines.append(
            f"| {app} | {cve} | {s.get('unit_total','N/A')} | {s.get('valid_units','N/A')} | {conc_s} | {s.get('edges_with_unit','N/A')} | {s.get('distinct_units','N/A')} | {concl} |"
        )

    # Part B table
    b_lines = []
    b_lines.append('| Scenario | Runtime | Triples | Subgraph | Backbone | sub_ratio | backbone_ratio | builder_mode | Unit coverage | Conclusion | Main issue |')
    b_lines.append('| -- | -- | --: | --: | --: | -- | -- | -- | -- | -- | -- |')
    for r in rows:
        s = r['subgraph']
        b_lines.append(
            f"| {r['scenario']} | {r['runtime']} | {s.get('triples','N/A')} | {s.get('subgraph','N/A')} | {s.get('backbone','N/A')} | {pct(s.get('sub_ratio'))} | {pct(s.get('backbone_ratio'))} | {s.get('builder_mode','N/A')} | {s.get('unit_strength','none')} | {s.get('conclusion','FAIL')} | {s.get('major_issue','')} |"
        )

    # per-scene qualitative notes (Part B)
    notes = []
    for r in rows:
        s = r['subgraph']
        notes.append(f"#### {r['scenario']}")
        if s.get('triples') is None:
            notes.append('- Scale relationship: required chain files are missing, so the triples/subgraph/backbone scale ratio cannot be formed.')
            notes.append('- Backbone visibility: cannot be determined.')
            notes.append('- Unit role: cannot be determined (no usable subgraph build result).')
            notes.append('- Relation gate: cannot be determined.')
            notes.append('- Seed/subgraph/backbone sampling: not possible (files are missing).')
            notes.append(f"- Main issue: {s.get('major_issue','missing data')}.")
            continue

        notes.append(f"- Scale relationship: triples={s.get('triples')}, subgraph={s.get('subgraph')} ({pct(s.get('sub_ratio'))}), backbone={s.get('backbone')} ({pct(s.get('backbone_ratio'))}).")
        notes.append(f"- Backbone visibility: conclusion={s.get('conclusion')}, builder_mode={s.get('builder_mode','N/A')}.")
        notes.append(f"- Unit role: {s.get('unit_strength','none')} (edge-level unit-coverage proxy).")
        notes.append(f"- Relation gate: dominant relation {s.get('dominant_relation') or 'N/A'}.")
        notes.append(f"- Seed sample: seed_count={s.get('seed_count','N/A')}; subgraph_relation_sample={s.get('sample_sub_rels', [])[:5]}.")
        notes.append(f"- Backbone sample: backbone_relation_sample={s.get('sample_backbone_rels', [])[:5]}.")
        notes.append('- Visibility of key attack actions: whether relations such as PROCESS_EXEC / FILE_WRITE / NET_SEND enter the backbone sample is used as a visibility proxy.')
        notes.append(f"- Main issue: {s.get('major_issue','none')}.")

    text = f"""# Part A Stage-1 / Unit Validation

## 1. What Is a Unit (Unified Definition)

unit is a sidecar semantic identifier for a runtime-interpretable execution unit (thread, task, or request context). It is not written back to raw/sysdig and is consumed by the attack-chain builder only through index/sidecar data.

## 2. Reading the Table

- Total units: the number of identifiable unit records in `unit_index.jsonl`.
- Valid units: units actually referenced by attack-chain edges.
- VTID concentration: no direct VTID field is available in this run, so the largest share of units across chain edges is used as a proxy.
- Attack-chain edges (unit!=empty): edges for which a non-empty unit can be resolved.
- Distinct units in chain: the number of deduplicated units appearing in the attack chain.
- Conclusion: FULL PASS / WEAK PASS / FAIL / N/A.

## 3. Interim PHP Stage-1 Conclusion

The PHP scenarios (gitlist/adminer/cmsms/joomla) generally show, in the available results, that units are indexed but chain-edge consumption is zero; a FULL PASS cannot yet be assigned. More precisely, the sidecar exists but does not form a stable chain-layer consumption loop.

## 4. Interim Java Stage-1 Conclusion

The Java scenarios (geoserver/metabase/solr/ofbiz) likewise show a primary pattern of unit indexes being present while non-empty chain-layer consumption is insufficient or missing. Under this convention, most are FAIL, indicating that the runtime-aware evidence loop is not complete for this data batch.

## 5. Unified Cross-runtime Acceptance Framework

- FULL PASS: total units > 0, valid units > 0, substantial unit coverage across chain edges, interpretable concentration, and positive diagnostics.
- WEAK PASS: units are consumed but coverage is weak or concentration is excessive.
- FAIL: units cannot enter chain-layer consumption or a required sidecar is missing.
- N/A: outside this run's runtime-aware Stage-1 validation scope.

## 6. Table Summary

{chr(10).join(a_lines)}

## 7. Results Suitable for a Paper Experiment Section

- Experimental setting: one convention across scenarios, strict raw/index separation, and no writes back to raw.  
- Sample coverage: 29 scenarios; PHP/Java are the Stage-1 focus; other runtimes are marked N/A.  
- Result character: Stage-1 chain-layer consumption is generally weak in this data batch.  
- Main conclusion: the runtime-aware mechanism can produce sidecars, but the available cross-scenario results do not show a stable attack-chain consumption loop.

## 8. Items to Freeze and Items to Defer

- Suitable to freeze: the non-contamination boundary for raw data, sidecar/index placement, and the distinction between N/A and FAIL.  
- Defer: the PHP/Java FULL PASS conclusion (current evidence is insufficient) and component-level Stage-1 validation for multi-jump.

# Part B Attack-chain Subgraph Extraction Quality Validation

## 1. Validation Objective

This section validates subgraph-extraction quality, not merely whether files were generated. It focuses on subgraph convergence, backbone compression, backbone clarity, and relation-gate effectiveness.

## 2. Reading the Table

 - Total triples: edge count in `audit_triples.core.v1.jsonl`.  
 - Subgraph edges: edge count in `attack_subgraph.v1.json`.  
 - Backbone edges: backbone edge count in `backbone_chain.v1.json`.  
 - Subgraph/triples ratio: convergence; lower is generally better.  
 - Backbone/subgraph ratio: backbone compression; lower is generally better.  
 - builder_mode: build mode from the build log.  
 - Unit coverage: strong/medium/weak/none (edge-level unit-coverage proxy).  
 - Main issues: an overly broad subgraph, insufficient compression, unbalanced relation distribution, or missing files.  
 - Conclusion: GOOD / WEAK / FAIL.

## 3. Per-scenario Table Summary

{chr(10).join(b_lines)}

## 4. Per-scenario Notes

{chr(10).join(notes)}

## 5. Interim Cross-scenario Conclusion

- Best single scenario: only `vulhub/cmsms/CVE-2019-9053` reached WEAK in this batch, showing some convergence and backbone compression.  
- Java weak cases: most Java scenarios either lack files or have a sub_ratio close to 1, indicating insufficient backbone convergence.  
- multi-jump: currently a failure case because required chain files are missing.  
- Runtime-aware quality improvement: no stable improvement is evident in this data batch; unit coverage is often none.  
- Paper example suggestion: `cmsms/CVE-2019-9053` can serve as a weak positive example; multi-jump and missing-chain-file scenarios can serve as failure examples.

## 6. Results Suitable for a Paper Experiment Section

- Experimental setting: apply the triple->subgraph->backbone quality test uniformly to 29 scenarios.  
- Sample coverage: 14 scenarios provide triples/subgraph/backbone metrics; the rest fail because chain files are missing.  
- Result character: mostly FAIL, a small number of WEAK, and no GOOD.  
- Main conclusion: the current version has clear backbone-convergence limits on complex or historical data batches; relation-gate and unit-consumption loops require further iteration.

## 7. Items to Freeze and Items to Defer

- Suitable to freeze: the GOOD/WEAK/FAIL quality convention, the dual metrics for subgraph convergence and backbone compression, and the failure-sample retention policy.  
- Defer: the multi-jump backbone-quality conclusion (files are currently missing) and relation-imbalance fixes for large Java/Node scenarios.

# Overall Conclusion

**Conclusion A: Stage-1 / unit mechanism**  
PHP/Java do not yet support a freezeable FULL PASS conclusion for this batch. Sidecar/index generation is confirmed, but chain-layer consumption evidence is insufficient. Python/Node/pgadmin/sandworm remain N/A and are outside this run's runtime-aware Stage-1 validation.

**Conclusion B: Triple-based backbone extraction quality**  
Only a few individual scenarios reach WEAK; most show an overly broad subgraph or missing chain files, and multi-jump remains a failure case. The method is usable for a single scenario with a balanced relation distribution, but its boundary is clear for complex or cross-component scenarios.

# Freezeable Items and Follow-up Questions

## Freezeable Items

1. The non-contamination principle for raw data and sidecar/index placement.  
2. Separate reporting structures for Stage-1 and subgraph quality.  
3. The unified GOOD/WEAK/FAIL + N/A convention.  
4. Retention of failure samples, especially multi-jump, as an iteration baseline.

## Follow-up Questions

1. Move the stable source of `unit_event_index` into the formal pipeline to avoid temporary completion.  
2. For PHP/Java runtime-aware processing, validate non-empty unit coverage on chain edges and the diagnostics->builder_mode link.  
3. The relation gate should suppress dominance by FILE_READ/FILE_WRITE alone.  
4. Re-evaluate multi-jump separately by component for both quality and Stage-1 criteria.
"""

    OUT_MD.write_text(text, encoding='utf-8')
    print(f'WROTE: {OUT_MD}')


if __name__ == '__main__':
    main()
