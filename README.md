# DNS/SNI application labeling

Application-domain rules and an offline hostname checker for the university traffic
dataset. Start here to review the rules before applying them to captures.

**Current status: this repository does not read or label PCAP files yet.** It can
classify DNS/SNI hostnames supplied as text. PCAP parsing, DNS-to-flow correlation
and activity classification are the next implementation step.

## Quick start

Requires Python 3.9 or later, with no external packages.

```sh
git clone https://github.com/hallavar/traffic-refinery.git
cd traffic-refinery
python3 scripts/check_rules.py
python3 scripts/inspect_hostname.py --source tls_sni copilot.microsoft.com graph.facebook.com
```

To inspect a DNS name instead, use `--source dns_hostname`. Pass hostnames, not
full URLs or PCAP paths. The inspection command makes no network requests.

```sh
python3 scripts/inspect_hostname.py --source dns_hostname api.openai.com
python3 scripts/inspect_hostname.py --include-optional api.githubcopilot.com
```

## Files to review

| File | Purpose |
| --- | --- |
| [rules/coverage.json](rules/coverage.json) | Status and limitations for all 42 inventory applications. |
| [rules/existing-applications.json](rules/existing-applications.json) | Reviewed candidates for the nine original application entries. |
| [rules/additional-applications.json](rules/additional-applications.json) | Additional application candidates and shared-host guards. |
| [target-applications.json](target-applications.json) | Target application inventory and descriptive families. |
| [scripts/hostname_rules.py](scripts/hostname_rules.py) | Reference matcher; loads both rule packs together. |
| [research/2026-10-21-additional-applications.md](research/2026-10-21-additional-applications.md) | Selections, sources, exclusions and remaining gaps. |
| [research/](research/) | Earlier review, pinned evidence snapshots and licenses. |

There are 218 application hostname patterns and 16 shared-host guard groups.
The 45 application entries include the 42 inventory targets plus optional Hulu,
Twitch and GitHub Copilot. These counts do not imply complete or unique detection.
The checker covers 180 hostname examples and verifies 49 evidence hashes.

## How to interpret a result

- An application name is a provisional **contacted-service candidate**. It does
  not establish which client application initiated the request.
- `ambiguous` retains candidates and reasons for shared or conflicting hostnames.
  Selecting fewer applications cannot make a shared endpoint exclusive.
- `unknown` retains unmatched or invalid hostname input.
- `traffic_category` stays `unknown`; the inventory family is metadata. YouTube
  searches/comments and video payload must eventually be distinguished using
  additional evidence. Whole-flow byte totals are not video payload byte totals.

Microsoft Copilot is enabled by default; GitHub Copilot is optional. Both belong
to the AI inventory family. Tencent START currently has only a provisional website
signal. Apple TV+ and Siri have shared signals; consumer Bixby and PlayStation
cloud-streaming detection remain deferred. No rules have been validated on the
university PCAPs.

## Next step for capture validation

Implement the offline PCAP reader and DNS/SNI extraction, associate DNS answers
with flows using client, capture time and TTL, then export labels with their
matching evidence. Retain unknown and ambiguous flows. Measure coverage and inspect
false positives on Francesco's captures before treating these rules as dataset
ground truth.

This fork contains only the labeling project. The inherited capture engine,
build files and unrelated configurations were removed. The default branch is
`main`; the original Traffic Refinery repository is unchanged. See
[ATTRIBUTION.md](ATTRIBUTION.md) for provenance and licenses.
