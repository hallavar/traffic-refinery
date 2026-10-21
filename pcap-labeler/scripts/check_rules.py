#!/usr/bin/env python3
"""Validate both hostname packs, counterexamples and evidence snapshots offline."""
import copy
import hashlib
import json
from pathlib import Path

from hostname_rules import ROOT, DEFAULT_PACKS, classify, load_rules, normalize_hostname


def require(condition, message):
    if not condition:
        raise ValueError(message)


def main():
    rules = load_rules()
    inventory = json.loads((ROOT / 'target-applications.json').read_text())
    names = {name for category in inventory['categories'] for name in category['applications']}
    app_ids = {app['id'] for app in rules['applications']}
    rule_ids, pattern_count = set(), 0
    for filename in DEFAULT_PACKS:
        pack = json.loads((ROOT / 'rules' / filename).read_text())
        require(not pack['label_policy']['first_match_wins'], 'First-match attribution is unsafe')
        require(pack['activity_policy']['application_and_activity_are_independent'], 'Separate identity and activity')
    for app in rules['applications']:
        require('category' not in app and 'inventory_category' in app, 'Separate inventory category from activity')
        if app['enabled_by_default']:
            require(app['inventory_name'] in names, 'Default application outside agreed inventory: ' + app['id'])
        for group in app['rules']:
            pattern_count += len(group['values'])
    all_groups = [group for app in rules['applications'] for group in app['rules']] + rules['shared_rules']
    for group in all_groups:
        require(group['id'] not in rule_ids, 'Duplicate rule ID: ' + group['id'])
        rule_ids.add(group['id'])
        require(group['match'] in {'domain_suffix', 'exact_hostname'}, 'Unsupported matching mode')
        require(group['traffic_role_hint'] in {'browsing_or_api', 'media_delivery_candidate', 'static_assets', 'telemetry', 'unknown'}, 'Invalid role hint')
        require(group['sources'] and set(group['sources']) <= rules['sources'].keys(), 'Missing rule provenance: ' + group['id'])
        require(group['values'] and len(group['values']) == len(set(group['values'])), 'Empty/duplicate pattern list')
        for value in group['values']:
            require(normalize_hostname(value) == value, 'Noncanonical pattern: ' + value)
    for group in rules['shared_rules']:
        require(set(group['candidate_application_ids']) <= app_ids, 'Unknown shared-host candidate')
        require(group['candidate_application_ids'] or group['other_candidates'], 'Empty shared-host candidates')
        require(bool(group['reason']), 'Missing shared-host explanation')
        for value in group['values']:
            for optional in (False, True):
                result = classify(rules, value, optional)
                require(result['application'] == 'ambiguous', 'Shared host became exclusive: ' + value)
                require(set(group['candidate_application_ids']) <= set(result['application_candidate_ids']), 'Lost shared-host candidates')
    coverage = json.loads((ROOT / 'rules/coverage.json').read_text())['inventory_entries']
    require(len(coverage) == len(names) == 42, 'Inventory coverage must account for every target')
    require({row['inventory_name'] for row in coverage} == names, 'Incomplete inventory audit')
    apps = {app['id']: app for app in rules['applications']}
    for row in coverage:
        app = apps[row['application_id']]
        require(row['hostname_pattern_count'] == sum(len(g['values']) for g in app['rules']), 'Stale coverage pattern count')
        require(row['enabled_by_default'] == app['enabled_by_default'], 'Stale enabled status')
        require(not row['pcap_validated'], 'No capture validation has been performed')
    for source in rules['sources'].values():
        if source.get('path', '').startswith('research/evidence/'):
            require((ROOT / source['path']).is_file(), 'Missing source snapshot: ' + source['path'])

    cases = []
    for filename in ('hostname-checks.json', 'additional-hostname-checks.json'):
        cases.extend(json.loads((ROOT / 'rules' / filename).read_text()))
    # Reverse every rule order to catch accidental first-match and precedence dependencies.
    reversed_rules = copy.deepcopy(rules)
    reversed_rules['applications'].reverse()
    reversed_rules['shared_rules'].reverse()
    for app in reversed_rules['applications']:
        app['rules'].reverse()
    for case in cases:
        optional = case.get('include_optional', False)
        result = classify(rules, case['hostname'], optional)
        require(result['application'] == case['expected'], f'{case["hostname"]!r}: expected {case["expected"]}, got {result["application"]}')
        require(result['traffic_category'] == case['expected_traffic_category'] == 'unknown', 'Hostname-only activity overclaim')
        require(result['initiating_application'] == 'unknown' and result['video_payload_bytes'] is None and result['retain_record'], 'Payload/client identity overclaim or discarded record')
        if 'expected_role_hints' in case:
            require(result['traffic_role_hints'] == case['expected_role_hints'], 'Unexpected role hints: ' + str(case['hostname']))
        if 'candidate_ids_contain' in case:
            require(set(case['candidate_ids_contain']) <= set(result['application_candidate_ids']), 'Missing candidates: ' + str(case['hostname']))
        require(result == classify(reversed_rules, case['hostname'], optional), 'Order-dependent classification')
        dns = classify(rules, case['hostname'], optional, 'dns_hostname')
        sni = classify(rules, case['hostname'], optional, 'tls_sni')
        require(dns.pop('evidence_type') == 'dns_hostname' and sni.pop('evidence_type') == 'tls_sni' and dns == sni, 'DNS/SNI matching diverged')

    # Simulate a newly discovered overlapping application rule. It must retain both
    # candidates, even when one is an exact host and another is a broader suffix.
    conflicting = copy.deepcopy(rules)
    conflicting['applications'][1]['rules'].append({
        'id': 'test-conflict', 'match': 'exact_hostname', 'values': ['www.youtube.com'],
        'traffic_role_hint': 'unknown', 'sources': []})
    conflict = classify(conflicting, 'www.youtube.com')
    require(conflict['application'] == 'ambiguous' and {'youtube', 'netflix'} <= set(conflict['application_candidate_ids']), 'Conflict was silently resolved')
    for value in ('xn--bcher-kva.example', 'BÜCHER.example.'):
        require(normalize_hostname(value) == 'xn--bcher-kva.example', 'IDNA normalization failed')
    for bad in (None, 123, 'bad host.example', '-bad.example', 'a' * 64 + '.example', '127.0.0.1', 'www.youtube.com..'):
        require(normalize_hostname(bad) is None, 'Accepted malformed hostname')

    evidence_files = 0
    for directory in sorted((ROOT / 'research/evidence').iterdir()):
        manifest_path = directory / 'manifest.json'
        if not manifest_path.is_file():
            continue
        for item in json.loads(manifest_path.read_text())['files']:
            digest = hashlib.sha256((directory / item['path']).read_bytes()).hexdigest()
            require(digest == item['sha256'], 'Evidence modified: ' + str(directory / item['path']))
            evidence_files += 1
    print(f'OK: {len(app_ids)} application entries, {pattern_count} application patterns, {len(rules["shared_rules"])} shared-host guards.')
    print(f'{len(cases)} hostname cases; DNS/SNI equivalence, order independence and conflict checks passed; {evidence_files} evidence hashes verified.')
    print('All 42 inventory entries audited. Activity remains unknown; video payload byte counts remain unset.')
    print('These checks do not measure capture recall, endpoint exclusivity, packet parsing or flow-label accuracy.')


if __name__ == '__main__':
    main()
