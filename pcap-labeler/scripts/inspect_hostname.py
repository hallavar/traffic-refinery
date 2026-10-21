#!/usr/bin/env python3
"""Inspect proposed DNS/SNI matches without reading a PCAP or making requests."""
import argparse
import json

from hostname_rules import classify, load_rules


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('hostnames', nargs='+', help='DNS names or SNI hostnames; not full URLs')
    parser.add_argument('--include-optional', action='store_true', help='Also inspect Hulu, Twitch, Bixby developer-only and GitHub Copilot candidates')
    parser.add_argument('--source', choices=['hostname', 'dns_hostname', 'tls_sni'], default='hostname')
    args = parser.parse_args()
    rules = load_rules()
    for name in args.hostnames:
        print(json.dumps(classify(rules, name, args.include_optional, args.source), indent=2))


if __name__ == '__main__':
    main()
