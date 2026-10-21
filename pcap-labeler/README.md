# Offline PCAP application labeler

This directory is the isolated home for the university traffic dataset labeling
work. It now contains researched draft hostname rules and offline rule checks.
The PCAP flow labeling implementation has not started; rules are not PCAP-validated.

## Workspace

- Worktree: `/Users/aschoen/Programs/traffic-refinery-labeling`
- Branch: `feat/pcap-labeling`
- Tool directory: `pcap-labeler/`
- Original checkout: `/Users/aschoen/Programs/traffic-refinery` on `main`

Keep new implementation, configuration, tests, and usage documentation under
`pcap-labeler/`. Leave the existing Traffic Refinery implementation available as
reference. Do not remove the rest of the repository.

## User objective and current state

Label flows in multiple university PCAPs using DNS and TLS SNI for an eventual
public dataset. The user's captures are not available on this computer yet.
The user authorized this isolated setup and research of existing and additional
application rules. The PCAP labeling implementation has not started.

The candidate application list has been recovered from the user's Slack DM with
Francesco and transcribed to `target-applications.json`. It is an inventory,
not an executable filtering configuration. The ten category percentages are
proposed benchmark composition targets, not observed traffic shares. Later
agreement on all candidates and percentages was not established. Slack research
is finished, and the user requested that Slack be closed.

Sources:
- Application table, September 16, 2026:
  https://enslnetsys.slack.com/archives/D08P2HN03C5/p1789550180072529
- Dataset requirements:
  https://enslnetsys.slack.com/archives/D08P2HN03C5/p1789546360703689

The requirements message specifies native PCAP, a release under 10 GB,
ENS-approved privacy-compatible release with CryptoPAN and payload removal or
randomization, contemporary heterogeneous applications, sufficient temporal
density, reproducible temporal train/test splits and preprocessing, and collection
context documentation. This records requirements, not proof that approval exists.

## Relevant repository findings

- `configs/trconfig_video.json`: `Services[].Name` and
  `Services[].Filter.{DomainsString,DomainsRegex,Prefixes}` define applications.
- `internal/servicemap/dnsmap.go`: DNS name matching currently uses substring
  matching or regexes, selects the first matching service and first answer IP,
  and does not follow CNAMEs for matching.
- `internal/servicemap/servicemap.go` and `ipcache.go`: global IP-to-service cache.
- `internal/cache/simpletimecache.go`: expiry uses wall time, which needs
  reconsidering for offline capture processing.
- `internal/flowstats/flowcache.go`: creates flows only for recognized services;
  exported `DomainName` is set to an empty string.
- `internal/network/pcap.go`: the production path captures a live interface.
- `internal/network/traffic_generator.go`: offline readers are testing helpers.
- `scripts/run_replay.sh`: existing replay runs `tcpreplay` on an interface.
- No SNI extraction implementation was found.

## Proposed implementation direction

Build a standalone offline command for multiple PCAP inputs, reusing the useful
JSON rule concepts. Keep application identity and observed traffic activity separate. Inventory category
is descriptive metadata and must not determine a flow category. Export auditable
flow labels with DNS/SNI source, hostname, matching rule, and capture timestamps;
retain unknown and ambiguous results. Improve domain boundary matching, handle
all relevant DNS answers and client/timestamp scope, and avoid blindly assigning
a single application to every connection sharing a server IP. Establish conflict
handling and flow/session boundaries during implementation. Extract labeling
evidence before payload removal.

Validate with focused synthetic captures and repository fixtures first, then
measure coverage and inspect conflicts on the user's captures when available.
At initial inspection, `go` and `tshark` were not on PATH, so runtime validation
has not been performed. No dependencies have been installed.

## Existing application rule review (2026-10-21)

- `rules/existing-applications.json`: 59 proposed hostname patterns for the nine
  applications in the original video and VoIP configs; seven enabled by default.
  Hulu and Twitch remain optional because they are absent from the target inventory.
- `rules/review-candidates.json`: unpromoted upstream entries and exclusion reasons.
- `research/2026-10-21-existing-applications.md`: changes, sources and limitations.
- `research/evidence/2026-10-21/`: dated public HTTP/DNS observations, pinned
  community lists with their MIT license, nDPI facts and evidence hashes.
- `scripts/check_rules.py`: offline pattern, scope, evidence and counterexample checks.

Run from this directory:

```sh
python3 scripts/check_rules.py
```

The packs use explicit exact-hostname and domain-suffix matching and are not
a drop-in configuration for the legacy substring matcher. Source-backed rules
are candidates for validation; landing-page checks did not include playback.
Unknown flows must receive `unknown` and be retained. No legacy code or configs
have been changed. Additional application research and its limitations follow below.

## Activity labeling clarification

The user requires search, comments and other non-media web activity to be browsing,
including when the application is YouTube. Video is reserved for video media data.
Schema v2 renames application-level `category` to `inventory_category` so it cannot
be mistaken for an observed activity label. Hostname rules provide application
identity and provisional role hints only. A media delivery hostname is a candidate
for further analysis, not proof that all packets or bytes are video payload.

Known application with unknown activity is valid and must be retained. Browsing
and media can share an encrypted or multiplexed connection; do not force the entire
connection into video. Video payload byte counts remain unset if unavailable.
The packet/request/stream activity classifier is not implemented yet.


## Additional applications and shared-host handling (2026-10-21)

The combined draft contains 45 application entries: all 42 inventory entries plus
optional Hulu, Twitch and GitHub Copilot. The additional pack has 159 application
patterns; together the packs have 218 patterns and 16 shared-host guard groups.
Forty entries are enabled by default; that is a configuration count, not a claim
that forty applications can be uniquely identified. Bixby consumer endpoints and
PlayStation cloud streaming remain deferred; Siri and Apple TV+ have shared signals.

- `rules/additional-applications.json`: curated additional service candidates,
  provenance, scope limits and shared-host guards.
- `rules/coverage.json`: status for every inventory entry, including incomplete ones.
- `rules/additional-review-candidates.json`: unpromoted upstream entries.
- `research/2026-10-21-additional-applications.md`: readable selections, evidence
  and remaining gaps.
- `research/evidence/2026-10-21-additional/`: pinned source lists with license,
  classifier domain facts, public probes and SHA-256 manifest.

**Load both packs together.** The executable reference matcher is
`scripts/hostname_rules.py`. Reading only the old pack would bypass the new shared
host protections, including the more conservative treatment of `googlevideo.com`.
Old fixture expectations for those shared hosts have been updated accordingly.

Inspect names without any network requests or capture files:

```sh
python3 scripts/inspect_hostname.py --source tls_sni copilot.microsoft.com api.openai.com graph.facebook.com
python3 scripts/inspect_hostname.py --include-optional api.githubcopilot.com
python3 scripts/check_rules.py
```

Unmatched names receive `unknown`. Shared or conflicting names receive `ambiguous`
with candidate IDs and source-backed explanations. Both results are retained.
Disabling one application never makes a known shared endpoint exclusive to another.
There is no first-match or longest-suffix rule that resolves ambiguity automatically.
Candidate lists are not exhaustive.

Microsoft Copilot is the inventory's Copilot entry. GitHub Copilot is separately
available with `--include-optional`; both carry the `AI services` inventory category.
`candidate_inventory_categories` is descriptive metadata, while `traffic_category`
remains `unknown`. Identifying an API host does not identify the client that used it.

GeForce NOW supplies a concrete cloud-gaming service candidate. Tencent START is a
provisional product choice and currently has only its exact website hostname.
Do not equate visits to either service with an active game stream. The sought
activity is interactive streamed gameplay, with downstream audio/video and upstream
controls; its packet directions and components still need capture validation.

The offline checks cover 180 hostname examples, shared-host behavior with optional
services disabled, exact/suffix boundaries, invalid input, DNS/SNI consistency,
rule-order independence, deliberately conflicting rules and 49 evidence hashes.
They do not establish recall, precision, endpoint exclusivity or PCAP-flow accuracy.
