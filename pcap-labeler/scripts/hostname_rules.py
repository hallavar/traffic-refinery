"""Offline hostname candidate matching; no packet parsing or activity inference."""
import ipaddress
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PACKS = ('existing-applications.json', 'additional-applications.json')


def normalize_hostname(value):
    if not isinstance(value, str):
        return None
    value = value.removesuffix('.').lower()
    try:
        value = value.encode('idna').decode('ascii')
        ipaddress.ip_address(value)
        return None
    except UnicodeError:
        return None
    except ValueError:
        pass
    if len(value) > 253 or '.' not in value:
        return None
    if not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', part)
               for part in value.split('.')):
        return None
    return value


def matching_values(host, rule):
    if rule['match'] == 'exact_hostname':
        return [value for value in rule['values'] if host == value]
    if rule['match'] == 'domain_suffix':
        return [value for value in rule['values']
                if host == value or host.endswith('.' + value)]
    raise ValueError('Unsupported hostname match type: ' + rule['match'])


def load_rules(root=ROOT):
    packs = [json.loads((root / 'rules' / name).read_text()) for name in DEFAULT_PACKS]
    applications, shared, sources = [], [], {}
    for pack in packs:
        if pack['schema_version'] not in (2, 3):
            raise ValueError('Unsupported rule pack schema')
        if pack['label_policy']['unmatched_label'] != 'unknown' or not pack['label_policy']['retain_unknown_flows']:
            raise ValueError('Unknown records must be retained')
        activity = pack['activity_policy']
        if (activity['hostname_only_traffic_category'] != 'unknown'
                or activity['inventory_category_is_flow_label']
                or activity['role_hints_are_labels']):
            raise ValueError('Hostname identity must not turn into an activity label')
        applications.extend(pack['applications'])
        shared.extend(pack.get('shared_rules', []))
        for id, source in pack['sources'].items():
            if id in sources and sources[id] != source:
                raise ValueError('Conflicting source ID: ' + id)
            sources[id] = source
    ids = [app['id'] for app in applications]
    if len(ids) != len(set(ids)):
        raise ValueError('Duplicate application IDs across packs')
    return {'applications': applications, 'shared_rules': shared, 'sources': sources}


def classify(rules, value, include_optional=False, evidence_type='hostname'):
    if evidence_type not in {'hostname', 'dns_hostname', 'tls_sni'}:
        raise ValueError('Unsupported evidence type')
    host = normalize_hostname(value)
    apps = {app['id']: app for app in rules['applications']}
    candidates, external, role_hints = set(), set(), set()
    evidence, guards = [], []
    if host:
        for app in apps.values():
            if not (app['enabled_by_default'] or include_optional):
                continue
            for rule in app['rules']:
                values = matching_values(host, rule)
                if values:
                    candidates.add(app['id'])
                    role_hints.add(rule['traffic_role_hint'])
                    evidence.append({'application_id': app['id'], 'rule_id': rule['id'],
                                     'matched_values': values, 'source_ids': rule['sources']})
        for rule in rules['shared_rules']:
            values = matching_values(host, rule)
            if values:
                # Product selection must never turn a shared endpoint into an exclusive one.
                candidates.update(rule['candidate_application_ids'])
                external.update(rule['other_candidates'])
                role_hints.add(rule['traffic_role_hint'])
                guards.append({'rule_id': rule['id'], 'matched_values': values,
                               'source_ids': rule['sources'], 'reason': rule['reason']})
    labels = {apps[id]['label'] for id in candidates} | external
    if guards or len(candidates) > 1:
        label, status = 'ambiguous', 'shared_or_conflicting_hostname'
    elif candidates:
        label, status = apps[next(iter(candidates))]['label'], 'hostname_service_candidate'
    else:
        label, status = 'unknown', 'unmatched' if host else 'invalid_hostname'
    return {
        'input_hostname': value, 'normalized_hostname': host, 'evidence_type': evidence_type,
        'application': label, 'application_candidate_ids': sorted(candidates),
        'application_candidates': sorted(labels), 'attribution_status': status,
        'candidate_inventory_categories': sorted({apps[id]['inventory_category'] for id in candidates}),
        'attribution_scope': 'contacted_service_candidate', 'initiating_application': 'unknown',
        'candidate_list_exhaustive': False,
        'traffic_category': 'unknown', 'traffic_role_hints': sorted(role_hints),
        'video_payload_bytes': None, 'retain_record': True,
        'matched_rules': sorted(evidence, key=lambda row: row['rule_id']),
        'shared_guards': sorted(guards, key=lambda row: row['rule_id']),
    }
