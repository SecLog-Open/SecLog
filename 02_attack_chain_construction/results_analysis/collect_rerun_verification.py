#!/usr/bin/env python3
"""
Collect verification metrics from the current rerun results.

Outputs:
- verification_rerun_metrics.json
- verification_rerun_stage1.csv
- verification_rerun_quality.csv
"""

import json
import csv
from pathlib import Path
from collections import defaultdict, Counter

from pipeline.utils.common import scenario_chain_dir

PROJECT_ROOT = Path(__file__).resolve().parents[1]
RESULTS_BASE = PROJECT_ROOT / "results"
RERUN_SUMMARY = PROJECT_ROOT / 'results_rerun_2026_3_20' / 'quick_rerun_results.json'
SUBGRAPH_OPTIONAL_NOTE = 'attack_subgraph.v1.json is an optional diagnostic artifact and may not be written by default.'

TARGET_SCENARIOS = [
    "python-demo",
    "juice-shop",
    "vulhub/gitlist/CVE-2018-1000533",
    "vulhub/geoserver/CVE-2023-25157",
    "vulhub/geoserver/CVE-2024-36401",
    "vulhub/adminer/CVE-2021-43008",
    "vulhub/metabase/CVE-2021-41277",
    "vulhub/metabase/CVE-2023-38646",
    "vulhub/solr/CVE-2017-12629-RCE",
    "vulhub/solr/CVE-2017-12629-XXE",
    "vulhub/solr/CVE-2019-0193",
    "vulhub/solr/CVE-2019-17558",
    "vulhub/cmsms/CVE-2019-9053",
    "vulhub/cmsms/CVE-2021-26120-lab",
    "vulhub/ofbiz/CVE-2020-9496",
    "vulhub/ofbiz/CVE-2023-49070",
    "vulhub/ofbiz/CVE-2024-38856",
    "vulhub/ofbiz/CVE-2024-45195",
    "vulhub/ofbiz/CVE-2024-45507",
    "vulhub/ofbiz/CVE-2023-51467",
    "vulhub/joomla/CVE-2015-8562",
    "vulhub/joomla/CVE-2017-8917",
    "vulhub/joomla/CVE-2023-23752",
    "vulhub/mongo-express/CVE-2019-10758",
    "vulhub/kibana/CVE-2018-17246",
    "vulhub/pgadmin/CVE-2022-4223",
    "vulhub/pgadmin/CVE-2023-5002",
    "sandworm",
    "multi-jump"
]

def detect_runtime(scenario):
    if scenario == 'python-demo' or 'pgadmin' in scenario:
        return 'python'
    if scenario == 'juice-shop' or 'mongo-express' in scenario or 'kibana' in scenario:
        return 'nodejs'
    if any(x in scenario for x in ['gitlist', 'adminer', 'cmsms', 'joomla']):
        return 'php'
    if any(x in scenario for x in ['geoserver', 'metabase', 'solr', 'ofbiz']):
        return 'java'
    if scenario == 'sandworm':
        return 'mixed'
    if scenario == 'multi-jump':
        return 'multi'
    return 'unknown'

def get_latest_timestamp_dir(scenario):
    scenario_path = RESULTS_BASE / scenario
    if not scenario_path.exists():
        return None
    timestamps = [d for d in scenario_path.iterdir() if d.is_dir() and d.name.startswith('20')]
    if not timestamps:
        return None
    return max(timestamps, key=lambda x: x.name)

def load_rerun_status():
    if not RERUN_SUMMARY.exists():
        return {}
    data = json.load(open(RERUN_SUMMARY))
    status_map = {}
    for r in data.get('results', []):
        rel_path = r.get('rel_path', '')
        # Extract the scenario key (remove the timestamp).
        parts = rel_path.split('/')
        if len(parts) >= 2 and parts[-1].startswith('20'):
            scenario_key = '/'.join(parts[:-1])
            # Keep the latest state.
            status_map[scenario_key] = {
                'extract_ok': r.get('extract_ok', False),
                'build_ok': r.get('build_ok', False),
                'rel_path': rel_path,
                'errors': r.get('errors', [])
            }
    return status_map

def count_lines(file_path):
    if not file_path.exists():
        return 0
    with open(file_path) as f:
        return sum(1 for _ in f)

def collect_stage1_metrics(scenario_dir, runtime):
    """Collect Stage-1 metrics."""
    metrics = {
        'unit_total': 0,
        'valid_units': 0,
        'vtid_concentration': None,
        'attack_edges_with_unit': 0,
        'distinct_units_in_chain': 0,
        'diagnostics_positive': False,
        'conclusion': 'N/A',
        'note': ''
    }
    
    if not scenario_dir:
        metrics['note'] = 'Scenario result directory does not exist.'
        return metrics
    
    # unit_index
    unit_index = scenario_dir / 'index' / 'unit_index.jsonl'
    if unit_index.exists():
        metrics['unit_total'] = count_lines(unit_index)
    
    # unit_event_index (diagnostics)
    unit_event = scenario_dir / 'index' / 'unit_event_index.jsonl'
    if unit_event.exists():
        metrics['diagnostics_positive'] = True
    
    # Unit usage in attack chains.
    attack_chains = scenario_dir / 'index' / 'attack_chains.jsonl'
    unit_counter = Counter()
    if attack_chains.exists():
        with open(attack_chains) as f:
            for line in f:
                try:
                    chain = json.loads(line)
                    for edge_key in ['path_edges', 'anomaly_edges']:
                        for edge in chain.get(edge_key, []):
                            src_attrs = edge.get('src_attrs', {})
                            dst_attrs = edge.get('dst_attrs', {})
                            src_unit = src_attrs.get('unit_id')
                            dst_unit = dst_attrs.get('unit_id')
                            for uid in [src_unit, dst_unit]:
                                if uid and uid != 'null':
                                    metrics['attack_edges_with_unit'] += 1
                                    unit_counter[uid] += 1
                except:
                    pass
    
    metrics['distinct_units_in_chain'] = len(unit_counter)
    metrics['valid_units'] = len(unit_counter)
    
    # VTID concentration (use the distribution as a proxy when available and label it).
    if unit_counter and metrics['attack_edges_with_unit'] > 0:
        max_count = max(unit_counter.values())
        metrics['vtid_concentration'] = round(max_count / metrics['attack_edges_with_unit'], 3)
    
    # Conclusion logic.
    if runtime in ['php', 'java']:
        if metrics['unit_total'] > 0 and metrics['attack_edges_with_unit'] > 0:
            if metrics['vtid_concentration'] is not None and metrics['vtid_concentration'] < 0.8:
                metrics['conclusion'] = 'FULL PASS'
            else:
                metrics['conclusion'] = 'WEAK PASS'
        elif metrics['unit_total'] > 0:
            metrics['conclusion'] = 'WEAK PASS'
            metrics['note'] = 'Units exist but are not consumed significantly by the chain.'
        else:
            metrics['conclusion'] = 'N/A'
            metrics['note'] = 'The unit mechanism cannot be determined for this run.'
    else:
        metrics['conclusion'] = 'N/A'
        metrics['note'] = 'Outside the runtime-aware validation scope for this run.'
    
    return metrics

def collect_quality_metrics(scenario_dir, rerun_status):
    """Collect subgraph-quality metrics."""
    metrics = {
        'triples_total': None,
        'subgraph_edges': None,
        'backbone_edges': None,
        'sub_ratio': None,
        'backbone_ratio': None,
        'backbone_over_triples': None,
        'builder_mode': 'N/A',
        'unit_strength': 'none',
        'major_issue': '',
        'conclusion': 'N/A',
        'status': 'incomplete',
        'subgraph_status': 'unavailable',
        'subgraph_note': '',
        'skipped_metrics': []
    }
    
    if not scenario_dir:
        metrics['status'] = 'incomplete'
        metrics['major_issue'] = 'Scenario directory does not exist.'
        return metrics
    
    chain_dir = scenario_chain_dir(scenario_dir)
    triples = chain_dir / 'audit_triples.core.v1.jsonl'
    subgraph = chain_dir / 'attack_subgraph.v1.json'
    backbone = chain_dir / 'backbone_chain.v1.json'
    
    # Check rerun status.
    if rerun_status:
        if rerun_status.get('extract_ok'):
            metrics['status'] = 'triples extracted'
        if rerun_status.get('build_ok'):
            metrics['status'] = 'complete'
            metrics['builder_mode'] = 'C'  # Most previous observations used mode C.
    
    # Read metrics.
    if triples.exists():
        metrics['triples_total'] = count_lines(triples)
    
    if subgraph.exists():
        try:
            data = json.load(open(subgraph))
            if isinstance(data, dict) and 'edges' in data:
                metrics['subgraph_edges'] = len(data['edges'])
        except:
            pass
    
    if backbone.exists():
        try:
            data = json.load(open(backbone))
            if isinstance(data, dict):
                if 'edges' in data:
                    metrics['backbone_edges'] = len(data['edges'])
                elif 'edge_sequence' in data:
                    metrics['backbone_edges'] = len(data['edge_sequence'])
        except:
            pass

    if not subgraph.exists():
        metrics['subgraph_status'] = 'missing_optional'
        metrics['subgraph_note'] = f'{SUBGRAPH_OPTIONAL_NOTE}; fell back to backbone/triples statistics.'
        metrics['skipped_metrics'] = ['sub_ratio', 'backbone_ratio']
    elif metrics['subgraph_edges'] is None:
        metrics['subgraph_status'] = 'unavailable'
        metrics['subgraph_note'] = f'{SUBGRAPH_OPTIONAL_NOTE}; the file exists but cannot be parsed; related metrics are unavailable.'
        metrics['skipped_metrics'] = ['sub_ratio', 'backbone_ratio']
    else:
        metrics['subgraph_status'] = 'available'

    if metrics['triples_total'] and metrics['backbone_edges'] is not None:
        metrics['backbone_over_triples'] = round(metrics['backbone_edges'] / metrics['triples_total'], 4)
    
    # Compute ratios.
    if metrics['triples_total'] and metrics['subgraph_edges'] is not None:
        metrics['sub_ratio'] = round(metrics['subgraph_edges'] / metrics['triples_total'], 4)
    
    if metrics['subgraph_edges'] and metrics['backbone_edges'] is not None:
        metrics['backbone_ratio'] = round(metrics['backbone_edges'] / metrics['subgraph_edges'], 4)
    
    # Quality conclusion (missing files are not classified as FAIL).
    if not rerun_status or not rerun_status.get('build_ok'):
        metrics['conclusion'] = 'N/A'
        if not rerun_status or not rerun_status.get('extract_ok'):
            metrics['major_issue'] = 'Extraction was incomplete for this run.'
        else:
            metrics['major_issue'] = 'Build was incomplete for this run.'
        return metrics
    
    # Classify GOOD/WEAK/FAIL only after a successful build.
    if metrics['sub_ratio'] is not None:
        if metrics['sub_ratio'] <= 0.3 and metrics['backbone_ratio'] and metrics['backbone_ratio'] <= 0.6:
            metrics['conclusion'] = 'GOOD'
            metrics['major_issue'] = 'Good convergence.'
        elif metrics['sub_ratio'] <= 0.7:
            metrics['conclusion'] = 'WEAK'
            metrics['major_issue'] = 'A backbone exists, but the subgraph is broad.'
        else:
            metrics['conclusion'] = 'FAIL'
            metrics['major_issue'] = 'The subgraph is too broad.'
    else:
        if metrics['backbone_over_triples'] is not None and metrics['backbone_edges'] and metrics['backbone_edges'] > 0:
            metrics['conclusion'] = 'WEAK'
            metrics['major_issue'] = (metrics['subgraph_note'] + '; subgraph metrics skipped') if metrics['subgraph_note'] else 'Subgraph metrics skipped.'
        else:
            metrics['conclusion'] = 'N/A'
            metrics['major_issue'] = (metrics['subgraph_note'] + '; insufficient metrics for classification') if metrics['subgraph_note'] else 'Insufficient metrics for classification.'
    
    return metrics

def main():
    rerun_status_map = load_rerun_status()
    
    all_data = []
    for scenario in TARGET_SCENARIOS:
        runtime = detect_runtime(scenario)
        latest_dir = get_latest_timestamp_dir(scenario)
        scenario_key = scenario
        rerun_status = rerun_status_map.get(scenario_key)
        
        stage1 = collect_stage1_metrics(latest_dir, runtime)
        quality = collect_quality_metrics(latest_dir, rerun_status)
        
        all_data.append({
            'scenario': scenario,
            'runtime': runtime,
            'latest_dir': str(latest_dir) if latest_dir else None,
            'rerun_status': rerun_status,
            'stage1': stage1,
            'quality': quality
        })
    
    # Save JSON.
    out_json = PROJECT_ROOT / 'results_rerun_2026_3_20' / 'verification_rerun_metrics.json'
    with open(out_json, 'w') as f:
        json.dump(all_data, f, indent=2, ensure_ascii=False)
    
    # Save the Stage-1 CSV.
    out_stage1 = PROJECT_ROOT / 'results_rerun_2026_3_20' / 'verification_rerun_stage1.csv'
    with open(out_stage1, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['scenario', 'runtime', 'unit_total', 'valid_units', 'vtid_concentration', 
                        'attack_edges_with_unit', 'distinct_units_in_chain', 'diagnostics_positive', 
                        'conclusion', 'note'])
        for d in all_data:
            s = d['stage1']
            writer.writerow([
                d['scenario'], d['runtime'], s['unit_total'], s['valid_units'], 
                s['vtid_concentration'], s['attack_edges_with_unit'], s['distinct_units_in_chain'],
                s['diagnostics_positive'], s['conclusion'], s['note']
            ])
    
    # Save the quality CSV.
    out_quality = PROJECT_ROOT / 'results_rerun_2026_3_20' / 'verification_rerun_quality.csv'
    with open(out_quality, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['scenario', 'runtime', 'status', 'triples_total', 'subgraph_edges', 'backbone_edges',
                        'sub_ratio', 'backbone_ratio', 'backbone_over_triples', 'builder_mode', 'unit_strength',
                        'subgraph_status', 'subgraph_note', 'major_issue', 'conclusion'])
        for d in all_data:
            q = d['quality']
            writer.writerow([
                d['scenario'], d['runtime'], q['status'], q['triples_total'], q['subgraph_edges'],
                q['backbone_edges'], q['sub_ratio'], q['backbone_ratio'], q['backbone_over_triples'], q['builder_mode'],
                q['unit_strength'], q['subgraph_status'], q['subgraph_note'], q['major_issue'], q['conclusion']
            ])
    
    print(f"Saved: {out_json}")
    print(f"Saved: {out_stage1}")
    print(f"Saved: {out_quality}")

if __name__ == '__main__':
    main()
