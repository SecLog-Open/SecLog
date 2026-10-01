#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import csv
import json
from collections import Counter, defaultdict
from pathlib import Path

from pipeline.utils.common import scenario_chain_dir

PROJECT_ROOT = Path(__file__).resolve().parents[1]
ROOT = PROJECT_ROOT / "results"
STATUS_PATH = PROJECT_ROOT / "results_analysis" / "verify_status_v2.tsv"
LOG_PATH = PROJECT_ROOT / "results_analysis" / "verify_build_chain_v2.log"
OUT_JSON = PROJECT_ROOT / "results_analysis" / "verification_metrics.json"
OUT_CSV_A = PROJECT_ROOT / "results_analysis" / "verification_stage1_table.csv"
OUT_CSV_B = PROJECT_ROOT / "results_analysis" / "verification_subgraph_table.csv"
SUBGRAPH_OPTIONAL_NOTE = 'attack_subgraph.v1.json is an optional diagnostic artifact and may not be written by default.'

SCENARIOS = [
    'python-demo',
    'juice-shop',
    'vulhub/gitlist/CVE-2018-1000533',
    'vulhub/geoserver/CVE-2023-25157',
    'vulhub/geoserver/CVE-2024-36401',
    'vulhub/adminer/CVE-2021-43008',
    'vulhub/metabase/CVE-2021-41277',
    'vulhub/metabase/CVE-2023-38646',
    'vulhub/solr/CVE-2017-12629-RCE',
    'vulhub/solr/CVE-2017-12629-XXE',
    'vulhub/solr/CVE-2019-0193',
    'vulhub/solr/CVE-2019-17558',
    'vulhub/cmsms/CVE-2019-9053',
    'vulhub/cmsms/CVE-2021-26120-lab',
    'vulhub/ofbiz/CVE-2020-9496',
    'vulhub/ofbiz/CVE-2023-49070',
    'vulhub/ofbiz/CVE-2024-38856',
    'vulhub/ofbiz/CVE-2024-45195',
    'vulhub/ofbiz/CVE-2024-45507',
    'vulhub/ofbiz/CVE-2023-51467',
    'vulhub/joomla/CVE-2015-8562',
    'vulhub/joomla/CVE-2017-8917',
    'vulhub/joomla/CVE-2023-23752',
    'vulhub/mongo-express/CVE-2019-10758',
    'vulhub/kibana/CVE-2018-17246',
    'vulhub/pgadmin/CVE-2022-4223',
    'vulhub/pgadmin/CVE-2023-5002',
    'sandworm',
    'multi-jump',
]


def detect_runtime(scene: str) -> str:
    if scene in {'python-demo'} or 'pgadmin' in scene:
        return 'python'
    if scene in {'juice-shop'} or 'kibana' in scene or 'mongo-express' in scene:
        return 'nodejs'
    if any(x in scene for x in ['gitlist', 'adminer', 'cmsms', 'joomla']):
        return 'php'
    if any(x in scene for x in ['geoserver', 'metabase', 'solr', 'ofbiz']):
        return 'java'
    if scene == 'sandworm':
        return 'mixed'
    if scene == 'multi-jump':
        return 'multi'
    return 'unknown'


def latest_timestamp_dir(scene: str) -> Path | None:
    base = ROOT / scene
    if not base.exists():
        return None
    cands = sorted([p for p in base.iterdir() if p.is_dir() and p.name.startswith('20')])
    return cands[-1] if cands else None


def load_status() -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    if not STATUS_PATH.exists():
        return out
    for line in STATUS_PATH.read_text(encoding='utf-8', errors='replace').splitlines():
        line = line.strip()
        if not line or line.startswith('====='):
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        scene = parts[0]
        gen = parts[1].split(':')[-1] if ':' in parts[1] else ''
        ext = parts[2].split(':')[-1] if ':' in parts[2] else ''
        build = parts[3].split(':')[-1] if ':' in parts[3] else ''
        path = parts[4]
        out[scene] = {'gen': gen, 'ext': ext, 'build': build, 'path': path}
    return out


def load_builder_modes() -> dict[str, str]:
    modes: dict[str, str] = {}
    if not LOG_PATH.exists():
        return modes
    current_scene = None
    for raw in LOG_PATH.read_text(encoding='utf-8', errors='replace').splitlines():
        line = raw.strip()
        if line.startswith('===== ') and ' @ ' in line:
            current_scene = line.replace('===== ', '').split(' @ ')[0].strip()
        elif 'builder_mode=' in line and current_scene:
            idx = line.find('builder_mode=')
            mode = line[idx + len('builder_mode='):].strip()
            modes[current_scene] = mode
    return modes


def line_count(path: Path) -> int:
    c = 0
    with path.open('r', encoding='utf-8', errors='replace') as f:
        for _ in f:
            c += 1
    return c


def load_unit_metrics(ts_dir: Path) -> dict:
    idx = ts_dir / 'index'
    unit_index = idx / 'unit_index.jsonl'
    attack = idx / 'attack_chains.jsonl'
    unit_event = idx / 'unit_event_index.jsonl'

    unit_total = 0
    if unit_index.exists():
        with unit_index.open('r', encoding='utf-8', errors='replace') as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    row = json.loads(line)
                except Exception:
                    continue
                if row.get('unit_id'):
                    unit_total += 1

    edges_with_unit = 0
    edges_total = 0
    distinct_units = set()
    unit_edge_counter = Counter()

    if attack.exists():
        with attack.open('r', encoding='utf-8', errors='replace') as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    ch = json.loads(line)
                except Exception:
                    continue
                for key in ('path_edges', 'anomaly_edges'):
                    for e in ch.get(key, []) or []:
                        edges_total += 1
                        uid = (e.get('unit_id') or '') if isinstance(e, dict) else ''
                        uid = str(uid).strip()
                        if uid:
                            edges_with_unit += 1
                            distinct_units.add(uid)
                            unit_edge_counter[uid] += 1

    valid_units = len(distinct_units)
    concentration = None
    if edges_with_unit > 0 and unit_edge_counter:
        concentration = max(unit_edge_counter.values()) / edges_with_unit

    diagnostics_positive = int(unit_event.exists())

    return {
        'unit_total': unit_total,
        'valid_units': valid_units,
        'edges_with_unit': edges_with_unit,
        'distinct_units': len(distinct_units),
        'vtid_concentration_proxy': concentration,
        'diagnostics_positive': diagnostics_positive,
        'edges_total': edges_total,
    }


def load_subgraph_metrics(ts_dir: Path, builder_mode: str | None) -> dict:
    cdir = scenario_chain_dir(ts_dir)
    triples = cdir / 'audit_triples.core.v1.jsonl'
    sub = cdir / 'attack_subgraph.v1.json'
    back = cdir / 'backbone_chain.v1.json'
    rel_csv = cdir / 'relation_stats.csv'

    out = {
        'triples': None,
        'subgraph': None,
        'backbone': None,
        'sub_ratio': None,
        'backbone_ratio': None,
        'backbone_over_triples': None,
        'builder_mode': builder_mode or 'N/A',
        'unit_strength': 'none',
        'major_issue': '',
        'conclusion': 'N/A',
        'dominant_relation': None,
        'seed_count': None,
        'sample_sub_rels': [],
        'sample_backbone_rels': [],
        'subgraph_status': 'unavailable',
        'subgraph_note': '',
        'skipped_metrics': [],
    }

    if not (triples.exists() and back.exists()):
        out['major_issue'] = 'Required chain files are missing (triples/backbone).'
        return out

    out['triples'] = line_count(triples)

    try:
        back_j = json.loads(back.read_text(encoding='utf-8', errors='replace'))
    except Exception:
        out['major_issue'] = 'The backbone JSON could not be parsed.'
        return out

    back_edges = int((back_j.get('chain_summary') or {}).get('edge_count') or len(back_j.get('edge_sequence', []) or []))
    out['backbone'] = back_edges
    if out['triples'] and out['triples'] > 0:
        out['backbone_over_triples'] = back_edges / out['triples']

    sub_j = None
    if sub.exists():
        try:
            sub_j = json.loads(sub.read_text(encoding='utf-8', errors='replace'))
            out['subgraph_status'] = 'available'
        except Exception:
            out['subgraph_status'] = 'unavailable'
            out['subgraph_note'] = f'{SUBGRAPH_OPTIONAL_NOTE}; the file exists but cannot be parsed; related metrics are unavailable.'
            out['skipped_metrics'] = ['sub_ratio', 'backbone_ratio', 'unit_strength', 'seed_count', 'sample_sub_rels']
    else:
        out['subgraph_status'] = 'missing_optional'
        out['subgraph_note'] = f'{SUBGRAPH_OPTIONAL_NOTE}; fell back to backbone/triples statistics.'
        out['skipped_metrics'] = ['sub_ratio', 'backbone_ratio', 'unit_strength', 'seed_count', 'sample_sub_rels']

    out['sample_backbone_rels'] = [e.get('relation') for e in (back_j.get('edge_sequence', []) or [])[:5] if isinstance(e, dict)]

    # dominant relation
    if rel_csv.exists():
        try:
            with rel_csv.open('r', encoding='utf-8', errors='replace') as f:
                reader = csv.DictReader(f)
                rows = [r for r in reader]
            if rows:
                top = rows[0]
                rel = top.get('relation')
                pct_s = (top.get('pct') or '').strip().rstrip('%')
                pct = float(pct_s) if pct_s else 0.0
                out['dominant_relation'] = f"{rel}:{pct:.2f}%"
        except Exception:
            pass

    if not isinstance(sub_j, dict):
        if out['backbone'] and out['backbone'] > 0:
            out['conclusion'] = 'WEAK'
            out['major_issue'] = (out['subgraph_note'] + '; subgraph metrics skipped') if out['subgraph_note'] else 'Subgraph metrics skipped.'
        else:
            out['conclusion'] = 'N/A'
            out['major_issue'] = (out['subgraph_note'] + '; insufficient backbone data for quality classification') if out['subgraph_note'] else 'Insufficient data for quality classification.'
        return out

    gs = sub_j.get('graph_summary', {}) if isinstance(sub_j, dict) else {}
    sub_edges = int(gs.get('edge_count') or len(sub_j.get('edges', []) or []))
    out['subgraph'] = sub_edges
    out['backbone'] = back_edges

    if out['triples'] and out['triples'] > 0:
        out['sub_ratio'] = sub_edges / out['triples']
    if sub_edges > 0:
        out['backbone_ratio'] = back_edges / sub_edges

    # unit strength from graph_summary
    u_with = int(gs.get('edges_with_unit') or 0)
    u_without = int(gs.get('edges_without_unit') or 0)
    if u_with + u_without > 0:
        r = u_with / (u_with + u_without)
        if r >= 0.6:
            out['unit_strength'] = 'strong'
        elif r >= 0.2:
            out['unit_strength'] = 'medium'
        elif r > 0:
            out['unit_strength'] = 'weak'
        else:
            out['unit_strength'] = 'none'

    out['seed_count'] = len(sub_j.get('seeds', []) or [])
    out['sample_sub_rels'] = [e.get('relation') for e in (sub_j.get('edges', []) or [])[:5] if isinstance(e, dict)]
    out['sample_backbone_rels'] = [e.get('relation') for e in (back_j.get('edge_sequence', []) or [])[:5] if isinstance(e, dict)]

    # issue + conclusion
    issues = []
    if out['sub_ratio'] is not None and out['sub_ratio'] > 0.9:
        issues.append('Subgraph is too broad.')
    if out['backbone_ratio'] is not None and out['backbone_ratio'] > 0.9:
        issues.append('Backbone compression is insufficient.')
    if out['dominant_relation']:
        try:
            pct = float(out['dominant_relation'].split(':')[-1].rstrip('%'))
            if pct >= 85.0:
                issues.append('Relation distribution is unbalanced.')
        except Exception:
            pass

    out['major_issue'] = '; '.join(issues) if issues else 'No obvious anomaly.'

    if out['sub_ratio'] is not None and out['backbone_ratio'] is not None:
        if out['sub_ratio'] <= 0.5 and out['backbone_ratio'] <= 0.75 and out['unit_strength'] in {'strong', 'medium'} and not issues:
            out['conclusion'] = 'GOOD'
        elif out['sub_ratio'] <= 0.9 and out['backbone'] and out['backbone'] > 0:
            out['conclusion'] = 'WEAK'
        else:
            out['conclusion'] = 'FAIL'

    out['subgraph_note'] = ''
    out['skipped_metrics'] = []

    return out


def stage1_conclusion(runtime: str, m: dict) -> str:
    if runtime not in {'php', 'java'}:
        return 'N/A'
    if m['unit_total'] <= 0:
        return 'FAIL'
    if m['edges_with_unit'] <= 0 or m['valid_units'] <= 0:
        return 'FAIL'
    c = m['vtid_concentration_proxy']
    if c is not None and c > 0.9:
        return 'WEAK PASS'
    return 'FULL PASS'


def main() -> None:
    status = load_status()
    modes = load_builder_modes()

    rows = []
    for s in SCENARIOS:
        runtime = detect_runtime(s)
        ts = latest_timestamp_dir(s)
        r = {
            'scenario': s,
            'runtime': runtime,
            'timestamp_dir': str(ts) if ts else None,
            'status': status.get(s, {}),
            'stage1': {},
            'subgraph': {},
        }
        if ts and ts.exists():
            st1 = load_unit_metrics(ts)
            st1['conclusion'] = stage1_conclusion(runtime, st1)
            r['stage1'] = st1
            r['subgraph'] = load_subgraph_metrics(ts, modes.get(s))
        rows.append(r)

    OUT_JSON.write_text(json.dumps({'rows': rows}, ensure_ascii=False, indent=2), encoding='utf-8')

    with OUT_CSV_A.open('w', encoding='utf-8', newline='') as f:
        w = csv.writer(f)
        w.writerow(['scene', 'runtime', 'unit_total', 'valid_units', 'vtid_concentration_proxy', 'attack_edges_unit_nonempty', 'distinct_units_in_chain', 'diagnostics_positive', 'conclusion'])
        for r in rows:
            s = r['stage1']
            w.writerow([
                r['scenario'], r['runtime'], s.get('unit_total'), s.get('valid_units'), s.get('vtid_concentration_proxy'),
                s.get('edges_with_unit'), s.get('distinct_units'), s.get('diagnostics_positive'), s.get('conclusion')
            ])

    with OUT_CSV_B.open('w', encoding='utf-8', newline='') as f:
        w = csv.writer(f)
        w.writerow(['scene', 'runtime', 'triples', 'subgraph', 'backbone', 'sub_ratio', 'backbone_ratio', 'backbone_over_triples', 'builder_mode', 'unit_strength', 'subgraph_status', 'subgraph_note', 'conclusion', 'major_issue', 'dominant_relation'])
        for r in rows:
            s = r['subgraph']
            w.writerow([
                r['scenario'], r['runtime'], s.get('triples'), s.get('subgraph'), s.get('backbone'), s.get('sub_ratio'), s.get('backbone_ratio'),
                s.get('backbone_over_triples'), s.get('builder_mode'), s.get('unit_strength'), s.get('subgraph_status'), s.get('subgraph_note'),
                s.get('conclusion'), s.get('major_issue'), s.get('dominant_relation')
            ])

    print(f'WROTE: {OUT_JSON}')
    print(f'WROTE: {OUT_CSV_A}')
    print(f'WROTE: {OUT_CSV_B}')


if __name__ == '__main__':
    main()
