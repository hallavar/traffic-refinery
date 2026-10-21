# Existing application filter review — 2026-10-21

This pass reviews the five video and four conferencing application entries in
`configs/trconfig_video.json` and `configs/trconfig_voip.json`. It does not add the
other applications from the Slack inventory. The resulting
[`existing-applications.json`](../rules/existing-applications.json) is a proposed
DNS/SNI rule pack, not a release-quality or exhaustive ground-truth classifier.

## Activity labeling correction

The user clarified that searches, comments and other non-media web activity must
be browsing even when the service is YouTube. Video means video media payload,
not all traffic belonging to a video service. This applies equally to Netflix,
Prime Video and conferencing applications.

Schema v2 therefore uses `inventory_category` only as historical service metadata.
Every hostname-only result has `traffic_category: unknown`; rule groups supply a
separate provisional role hint. For example, YouTube web/API names suggest browsing
or API traffic, `ytimg.com` suggests static assets, and `googlevideo.com` suggests a
media delivery candidate. No hint establishes the exact bytes' activity. In
particular, playback API names and subtitle/CDN hosts are not themselves proof of
video media payload. The existing filter review remains useful for application
identity; activity evidence requires an additional pass.

HTTP/2 and HTTP/3 allow concurrent streams on a connection
([RFC 9113](https://www.rfc-editor.org/rfc/rfc9113.html),
[RFC 9114](https://www.rfc-editor.org/rfc/rfc9114.html)). Thus a flow can carry more
than one kind of exchange. With DNS/SNI-only encrypted captures, request content
and exact video payload bytes may be unavailable. Keep application identity,
activity uncertainty, and role hints separate. Preserve mixed/unknown flows and
leave unobservable video-payload byte counts unset. Do not relabel ACKs, TLS/QUIC
handshakes, manifests, thumbnails, subtitles, comments or telemetry as video media
merely because they accompany a viewing session.

The 74 offline checks now verify that none of these hostname matches automatically
outputs a video category. No production activity classifier exists yet.

## Results

| Application | Proposed change | Evidence / practical limit |
| --- | --- | --- |
| YouTube | Preserve the three original domains. Add embeds, short links, Kids/Education and specific Google API hosts. | Google documents the two main API hosts and education/embed names. Current community/classifier sources cover further candidates. The live landing page also referenced `youtubei-att.googleapis.com`, absent from the pinned community list. |
| Netflix | Preserve all six original domains; add `netflix.net`, `netflix.ca`, `nflxsearch.net`, and exact `netflix.com.edgesuite.net`. | Current community list; `netflix.net` redirected to Netflix. `nflxsearch.net` resolved but the root HTTPS handshake failed, so its current use is not established by that probe. |
| Amazon Prime / Prime Video | Add `aiv-delivery.net`, `pv-cdn.net`, named API hosts, and two exact CloudFront hosts. Remove broad `amazon.com` and old regexes. | nDPI plus the community Prime Video list; DNS connected named API/subtitle endpoints to service-specific CNAME chains. Amazon shopping/assets must not all become video labels. |
| Hulu | Replace the `hulustream` substring with `hulustream.com`; add named playback and asset hosts. Replace loose CDN regexes. | Two upstream lists, partial live DNS checks. Preserve `hulu.conviva.com` only as an exact original hostname, not the shared CNAME target. Hold QA and regional branding candidates for review. |
| Twitch | Add `jtvnw.net`, `ext-twitch.tv`, `twitchsvc.net`; preserve the original three. | Twitch developer documentation, upstream sources and landing-page references. Do not take the upstream `live-video.net` rule: AWS also documents that namespace for general IVS streaming. |
| Zoom | Add `zoom.com` alongside `zoom.us`. | Current Zoom firewall documentation explicitly lists both. A match identifies Zoom-family traffic, not necessarily a call. |
| Microsoft Teams | Add the specific `teams.microsoft.com` and `teams.cloud.microsoft` namespaces. | Current Microsoft endpoint documentation. Do not map all Microsoft login, SharePoint, Skype or Office dependencies to Teams. |
| Google Meet | Add `meet.google.com`, exact `meetings.googleapis.com`, and exact media SNI `meet.turns.goog`. | Current Google network documentation explicitly supplies these. Keep `workspace.turns.goog` as a documented candidate needing session context before exclusive attribution. |
| Webex | Add `webex.com`, `wbx2.com`, `ciscospark.com`, `webexapis.com`, `webexcontent.com`. | Current Webex documentation. Do not copy general `cisco.com` or third-party CDN/analytics/certificate dependencies from a firewall allowlist. |

Hulu and Twitch are reviewed because they exist in the repository; they are marked
optional because they were absent from the recovered target inventory. Their
presence in the review does not change that inventory. Seven entries are enabled
by default. Application labels refer to a service family, including its website,
APIs, images and control traffic; they do not establish that the user watched a
video or joined a meeting. The historical inventory label `Amazon Prime` is
preserved, with scope explicitly restricted to Prime Video.

The original `googlevideo.com` rule is retained as an explicitly marked
YouTube-media heuristic, not proof of exclusive YouTube use or the initiating
application. Validate its false positives against other Google video services
before using it as dataset ground truth. The same evidence-first interpretation
applies to all service/CDN rules.

## Why not copy an exhaustive online list?

The pinned [V2Fly project](https://github.com/v2fly/domain-list-community) is a
community routing list. [nDPI](https://github.com/ntop/nDPI) is a classifier
implementation. Both are useful primary sources for what their maintainers
currently classify, not vendor guarantees of exclusive runtime use. Routing and
firewall allowlists can include shared infrastructure, marketing/redirect domains,
test endpoints and unrelated dependencies. Thus a larger list is not necessarily
a better application labeler.

The complete five small V2Fly source files are archived with their MIT license,
revision and hashes. The pack references the exact commit, not a moving branch.
The current nDPI file revision and relevant domain classification facts are also
recorded. All unpromoted V2Fly entries, including regional YouTube domains and
additional CloudFront hosts, remain visible in
[`review-candidates.json`](../rules/review-candidates.json), alongside reasons for
rejecting or holding particular rules. They are not silently activated.

## Live checks and their limits

Evidence is in [`evidence/2026-10-21/`](evidence/2026-10-21/).
Checks used public HTTPS GETs with certificate verification, static HTML hostname
extraction, and A/AAAA/CNAME lookups from the execution environment. No account
login, meeting join, media playback, JavaScript execution or packet capture was
performed. HTML references are leads, not observed subresource connections; links
to another service or shared assets are not imported as application rules.

- All five video landing-page requests completed with HTTP 200, but Hulu redirected
  to Disney+ in this probe. The returned page referenced multiple brands; none of
  those other domains was automatically labeled Hulu.
- Netflix and Prime Video returned substantial HTML; Netflix was capped at
  2,000,001 bytes and marked truncated. This is not exhaustive endpoint discovery.
- Zoom, Teams and Meet public requests returned HTTP 200. Teams returned an
  unsupported-browser page and Meet redirected to a product landing page. Webex
  returned HTTP 403. These are reachability observations, not client validation.
- `cf-timedtext.aux.pv-cdn.net` resolved through the named
  `dmqdd6hw24ucf.cloudfront.net` distribution, supporting that exact host as a
  candidate. It does not support labeling other CloudFront distributions.
- Some DNS answers contain special-use addresses such as `192.0.0.69` and
  `198.18.2.14`, and some query types returned inconsistent/no results. The local
  DNS path may synthesize or filter responses. These records are diagnostic only;
  no returned address has become an IP-prefix rule.
- An apex or `www` NXDOMAIN/no-answer result does not disprove other subdomains.
  An SNI hostname can be useful without a public A/AAAA record.

## Matching and integration

This is a new rule format. Do not paste it into the legacy `DomainsString` field:
that code performs substring matching. `domain_suffix` means an exact domain or a
subdomain at a dot boundary; `exact_hostname` means the one hostname only. Normalize
case and an optional trailing dot. The fixture checks reject false positives such
as `notyoutube.com`, `youtube.com.evil.example`, generic Amazon shopping, shared
Google/Microsoft services and unrelated CDN hosts.

The user has explicitly requested that unmatched flows be labeled `unknown` and
retained until a later decision. The pack records this. Conflicts should remain
`ambiguous` with their evidence, rather than being resolved by list order.

No old Netflix/conferencing IP ranges are migrated. This review focuses on DNS and
SNI; a separate address-based pass would need current service-specific sources,
timestamps and protocol/port context. No production packet parser has changed.
The offline flow labeler still needs client/TTL/capture-time DNS correlation and
shared-IP handling. Pure hostname rules cannot identify every flow when its
application evidence is unavailable.

Run the standard-library-only checks from `pcap-labeler/`:

```sh
python3 scripts/check_rules.py
```

These verify provenance references, canonical patterns, overlapping application
namespaces, evidence hashes, inventory scope and selected hostname counterexamples.
They do not measure recall or precision. Next validation should use controlled
sessions on relevant clients/regions and then the university PCAPs when available.

## Main vendor sources

- [YouTube network restrictions](https://knowledge.workspace.google.com/admin/youtube/control-youtube-content-available-to-users)
- [Meet network requirements](https://knowledge.workspace.google.com/admin/meet/prepare-your-network-for-meet-meetings-and-live-streams)
- [Microsoft 365 / Teams endpoints](https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges?view=o365-worldwide)
- [Zoom firewall requirements](https://support.zoom.com/hc/en/article?id=zm_kb&sysparm_article=KB0060548)
- [Webex network requirements](https://help.webex.com/en-us/article/WBX000028782/Network-Requirements-for-Webex-Services)
- [Twitch extension domains](https://dev.twitch.tv/docs/extensions/)
- [Amazon IVS network requirements](https://docs.aws.amazon.com/ivs/latest/RealTimeUserGuide/real-time-network-requirements.html)
