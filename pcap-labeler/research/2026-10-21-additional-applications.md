# Additional application hostname research — 2026-10-21

This is a candidate rule selection for DNS question names and TLS SNI. It is not
an exhaustive service allowlist, a PCAP classifier, or proof of endpoint exclusivity.
No university captures were available. The complete inventory has 42 named entries
in ten families; every entry now has a coverage status, including unsupported ones.

## Decision and matching contract

The additional pack adds 36 entries (35 inventory entries plus optional GitHub
Copilot), 159 application patterns and 16 shared-host guards. The earlier pack
has 9 entries and 59 patterns. Combined: 45 entries, 218 application patterns.
Bixby and PlayStation cloud streaming are disabled/incomplete; optional Hulu,
Twitch and GitHub Copilot are also disabled by default. Counts are not accuracy
or traffic-coverage estimates.

Use `scripts/hostname_rules.py` to load **both** packs. Matching is case-insensitive
with an optional final dot and IDNA normalization. Exact hosts stay exact; suffixes
match only the domain itself or a subdomain separated by a dot. URLs, paths, ports
and IP literals are not hostname input. HTTP paths are not observable in DNS/SNI;
services distinguished only by paths cannot be separated by this matcher.

Collect all matching candidates. A shared guard keeps the result ambiguous even
if only one of its known candidate applications is enabled. Retain the reason,
matched pattern, source IDs and evidence type. Do not resolve conflicts by list
order, longest suffix, session co-occurrence or a generic CDN/provider identity.
The possible clients/services listed for a shared host are conservative candidates,
not an exhaustive measured list of consumers.

A unique result means a **contacted-service candidate**. An embedded YouTube player,
a MusicKit integration or an AI-powered third-party client can contact a service
without being that service's own application. `initiating_application` therefore
stays `unknown`, including for exact API host matches.

## Inventory audit

The table gives representative selected hostnames, not all patterns. The JSON
contains exact-vs-suffix semantics, source references and notes for every group.
“Candidate namespaces” means a draft contacted-service signal with unknown activity.
“Shared guard” means some known hostnames cannot yield a unique product label.

| Family | Inventory application | Representative names | Status / limitation |
| --- | --- | --- | --- |
| Video streaming | YouTube | `youtube.com`, `youtube-nocookie.com`, `youtu.be` | Earlier reviewed candidate; shared guard |
| Video streaming | Netflix | `netflix.com`, `nflxvideo.net`, `nflximg.net` | Earlier reviewed candidate |
| Video streaming | Amazon Prime | `amazonvideo.com`, `primevideo.com`, `aiv-cdn.net` | Earlier reviewed candidate; shared guard |
| Video streaming | Disney+ | `disneyplus.com`, `disney-plus.net`, `disneyplus.net` | Candidate namespaces; shared guard |
| Social media | Facebook | `facebook.com`, `www.facebook.com`, `m.facebook.com` | Candidate namespaces; shared guard |
| Social media | Instagram | `instagram.com`, `ig.me`, `cdninstagram.com` | Candidate namespaces; shared guard |
| Social media | TikTok | `tiktok.com`, `tiktokv.com`, `tiktokv.us` | Candidate namespaces |
| Social media | Snapchat | `snapchat.com`, `sc-cdn.net`, `sc-gw.com` | Candidate namespaces |
| Social media | X | `x.com`, `twitter.com`, `t.co` | Candidate namespaces |
| Gaming / distribution | Xbox Live | `xbox.com`, `xboxlive.com`, `xboxservices.com` | Candidate namespaces |
| Gaming / distribution | Steam | `steampowered.com`, `steamcommunity.com`, `steamcontent.com` | Candidate namespaces |
| Gaming / distribution | PlayStation | `playstation.com`, `playstation.net`, `playstationnetwork.com` | Candidate namespaces |
| Gaming / distribution | Epic Games | `epicgames.com`, `epicgames.net`, `epicgames.dev` | Candidate namespaces |
| Communication / messaging | WhatsApp | `whatsapp.com`, `whatsapp.net`, `wa.me` | Candidate namespaces; shared guard |
| Communication / messaging | Messenger | `messenger.com`, `fbmessenger.com`, `m.me` | Candidate namespaces; shared guard |
| Communication / messaging | FaceTime | `facetime.apple.com` | Web signal only; call media incomplete |
| Communication / messaging | Discord | `discord.com`, `discord.gg`, `discordapp.com` | Candidate namespaces |
| Television / OTT | Tubi | `tubi.tv`, `tubitv.com`, `tubi.video` | Candidate namespaces |
| Television / OTT | Roku | `roku.com`, `rokutime.com` | Roku ecosystem, not proof of Roku Channel playback |
| Television / OTT | Apple TV+ | `tv.apple.com`, `uts-api.itunes.apple.com` | Shared with Apple TV store, rentals and channels; shared guard |
| Television / OTT | Pluto TV | `pluto.tv`, `plutotv.net` | Candidate namespaces |
| Television / OTT | Plex | `plex.tv`, `plexapp.com`, `plex.services` | Candidate namespaces |
| Audio streaming | Spotify | `spotify.com`, `scdn.co`, `pscdn.co` | Candidate namespaces |
| Audio streaming | Apple Music | `music.apple.com`, `applemusic.com`, `musickit.net` | Candidate namespaces; shared guard |
| Audio streaming | Amazon Music | `music.amazon.com`, `music.amazon.ca`, `api.music.amazon.dev` | Partial regional/web/API coverage; shared guard |
| Conferencing | Microsoft Teams | `teams.microsoft.com`, `teams.cloud.microsoft` | Earlier reviewed candidate; shared guard |
| Conferencing | Google Meet | `meet.google.com`, `meetings.googleapis.com`, `meet.turns.goog` | Earlier reviewed candidate |
| Conferencing | Zoom | `zoom.us`, `zoom.com` | Earlier reviewed candidate |
| Conferencing | WebEx | `webex.com`, `wbx2.com`, `ciscospark.com` | Earlier reviewed candidate |
| Cloud gaming | GeForce Now | `geforcenow.com`, `nvidiagrid.net` | Candidate namespaces |
| Cloud gaming | PlayStation Now | — | Disabled; no exclusive cloud-stream host rule established |
| Cloud gaming | Tencent | `start.qq.com` | Provisional Tencent product; website only |
| IoT / assistants | Alexa | `amazonalexa.com`, `alexa.amazon.com`, `avs-alexa-na.amazon.com` | API and legacy gateway signals; regional coverage incomplete; shared guard |
| IoT / assistants | Siri | `guzzoni.apple.com` | Shared with dictation; no exclusive Siri rule; shared guard |
| IoT / assistants | Bixby | `bixbydevelopers.com`, `bixby-client.aibixby.com` | Disabled; developer tools only, consumer runtime unverified |
| IoT / assistants | Philips Hue | `meethue.com` | Cloud discovery signal; local bridge activity not covered |
| IoT / assistants | SmartThings | `smartthings.com` | Candidate namespaces |
| AI services | ChatGPT | `chatgpt.com` | Candidate namespaces; shared guard |
| AI services | OpenAI API | `api.openai.com` | Candidate namespaces; shared guard |
| AI services | Copilot | `copilot.microsoft.com`, `copilot.cloud.microsoft` | Candidate namespaces; shared guard |
| AI services | Gemini | `gemini.google.com`, `generativelanguage.googleapis.com`, `geminiweb-pa.clients.google.com` | Candidate namespaces |
| AI services | Claude | `claude.ai`, `claude.com`, `api.anthropic.com` | Candidate namespaces |

## Ambiguity and exclusions

| Hostname or namespace | Handling / reason |
| --- | --- |
| `graph.facebook.com`, `fbcdn.net`, `fbsbx.com`, `facebook.net`, selected Facebook messaging hosts | Meta products and integrations overlap; retain multiple candidates. General `facebook.com` suffix was not imported. |
| `googlevideo.com` | Media delivery candidate, ambiguous client/service attribution. Replaces the earlier unique YouTube expectation; never labels bytes as video. |
| `bamgrid.com`, `bamgrid.net`, `bamtech.net`, `dmed.technology`, Disney account namespaces | Disney/Hulu and other properties share infrastructure. Even a branded subhost stays conservatively ambiguous in this draft. |
| `tv.apple.com`, `uts-api.itunes.apple.com` | Apple TV app/catalog also includes store/rentals/channels; cannot isolate TV+ subscription content. |
| `itunes.apple.com`, `mzstatic.com` | Apple content assets span Music, TV and other products. |
| `guzzoni.apple.com`, `smoot.apple.com` | Siri/dictation and broader Apple search infrastructure overlap. |
| Amazon image endpoints | Prime Video, Music, Alexa and shopping can overlap; no blanket `amazon.com` rule. |
| `oaistatic.com`, `oaiusercontent.com` | Shared OpenAI product assets; do not force ChatGPT identity. |
| `api.github.com`, `graph.microsoft.com` | Copilot shares API hosts with other clients/products; no path visibility in DNS/SNI. |
| Generic `cloudfront.net`, Akamai, AWS, Azure, Google, Apple, Samsung, Tencent namespaces | Not imported as unique application evidence. Selected branded third-party hosts are exact-only. |

The unpromoted-entry JSON preserves community-list candidates and exclusion
rationales. Parent-company scope, marketing, advertising/SDK integrations,
brand-defense domains, unrelated corporate products, shared authentication and
unscoped third-party hosting are not automatically promoted.

## Copilot and cloud gaming scope

Microsoft Copilot is the intended inventory target. GitHub Copilot is a separate,
optional service label in the same AI inventory family. Its documented suggestion
endpoints support narrow rules, while the GitHub API, authentication and generic
GitHub browsing do not prove Copilot use. A GitHub Copilot client can use different
models; hostname evidence does not reveal the exact model or operation.

The user wants interactive cloud gaming: downstream streamed audio/video plus
upstream user controls. Upstream byte volume is not guaranteed to be large, and
bidirectional traffic alone is not sufficient evidence of cloud gaming. NVIDIA's
GeForce NOW documentation describes streaming alongside keyboard/gamepad support;
it supplies a concrete candidate. `nvidiagrid.net` is retained as a community-list
candidate, not a vendor-certified complete gameplay endpoint list. Ordinary NVIDIA
websites, drivers and telemetry are excluded.

Tencent's product was unspecified. START is a provisional concrete choice; the
public `start.qq.com` site redirects to `/webgame/home`. That establishes a web
entry point only. No verified START media/control endpoint list was established;
never use all `qq.com`, Tencent games or `myqcloud.com` to fill the gap.

The inventory's PlayStation Now name is historical; Sony describes its merger into
PlayStation Plus. General PlayStation hostnames cannot separate cloud streaming
from downloads, store pages or multiplayer. The cloud-streaming entry has no rules
and is disabled pending better evidence. It is not counted as successfully detected.

## Evidence and limits

Selections combine vendor documentation/product sites, pinned community routing
lists, pinned nDPI domain facts and anonymous public landing-page/DNS observations.
A vendor firewall allowlist describes connectivity dependencies, not exclusive
application ownership. Community routing lists are candidate discovery aids;
corporate includes were inspected and not expanded blindly (e.g. Gemini/DeepMind,
Disney/Hulu/ESPN, NVIDIA/Hugging Face).

The additional evidence directory contains 34 anonymous HTTP probes and 49 local
DNS observations. No account login, paid session, game/video playback or AI
inference was performed. Some sites returned blocks/errors or JavaScript shells;
those outcomes do not establish that a service or hostname is invalid. Meta's
ordinary developer documentation was rate-limited, so its published API collections
were used for the shared Graph-host finding. Public landing-page availability does
not validate runtime endpoint coverage.

Some local resolver answers were synthesized special-use addresses. They are
recorded for reproducibility and are not used as IP-prefix or address ownership
rules. No global IP-to-application cache has been added. A future offline pipeline
must preserve client/time/TTL scope, all relevant DNS answers and CNAME evidence,
SNI-vs-DNS disagreement, and shared-IP uncertainty. Missing/ECH-protected SNI or
unobserved DNS can leave records unknown. DNS attribution must not blindly spread
one hostname to every client using an address.

Application family is descriptive metadata. Search/comments/navigation should be
browsing when independently identified. Hostnames alone do not implement that
activity classifier. Every matcher result currently has `traffic_category: unknown`,
`video_payload_bytes: null`, and `retain_record: true`. Mixed encrypted connections
must not turn whole-flow byte totals into video payload byte totals. Cloud-game
media and control components also need separate evidence before activity labeling.

## Offline validation

`python3 scripts/check_rules.py` checks both packs and all 42 inventory statuses.
The 180 hostname cases include positives, false-positive counterexamples, exact
hosts versus suffixes, optional-product selection, shared Meta/Apple/Amazon/AI
infrastructure and invalid input. Shared guard values are also checked with optional
services both enabled and disabled. DNS and SNI inputs give the same candidates
while retaining their evidence type. Reversing rule order changes no result; a
synthetic overlapping exact/suffix rule stays ambiguous. All 49 stored evidence
file hashes are checked. These are matcher/provenance checks, not measured accuracy.

## Selected primary sources

- [Apple enterprise network requirements](https://support.apple.com/en-us/101555): shared Siri/dictation, search and content endpoints.
- [Apple Music requests](https://developer.apple.com/documentation/applemusicapi/handling-requests-and-responses), [SmartThings API](https://developer.smartthings.com/docs/service-integrations/api-overview), [Hue discovery](https://developers.meethue.com/develop/get-started-2/).
- [Bixby Studio documentation](https://corp.bixbydevelopers.com/dev/docs/dev-guide/developers/ide): developer tooling only.
- [Alexa event gateways](https://www.developer.amazon.com/docs/alexaplus/smarthome/send-events) and [legacy Alexa SDK](https://alexa.github.io/avs-device-sdk/namespacealexa_client_s_d_k_1_1capability_agents_1_1api_gateway_1_1test.html).
- [Amazon Music V1 preview](https://developer.amazon.com/ja/docs/music/API_web_overview.html) and [V2 preview](https://d332qao9bxuj3h.cloudfront.net/docs/music/API_web_overview_v2.html): API hosts, not complete regional coverage.
- [GeForce NOW requirements](https://www.nvidia.com/en-gb/geforce-now/system-reqs/) and [Tencent START](https://start.qq.com/).
- [PlayStation Plus FAQ](https://www.playstation.com/en-us/ps-plus/getting-started/jcr%3Acontent/) and [PlayStation cloud streaming](https://www.playstation.com/ps5-game-cloud-streaming).
- [Microsoft Copilot requirements](https://learn.microsoft.com/en-us/microsoft-365/copilot/microsoft-copilot-requirements), [GitHub Copilot allowlist](https://docs.github.com/en/copilot/reference/copilot-allowlist-reference).
- [OpenAI API overview](https://developers.openai.com/api/reference/overview), [ChatGPT overview](https://learn.chatgpt.com/docs/overview), [Gemini API](https://ai.google.dev/api), [Claude network documentation](https://support.claude.com/en/articles/13198485-enforce-network-level-access-control-with-tenant-restrictions).
- [Meta Instagram collection](https://www.postman.com/meta/instagram/documentation/6yqw8pt/instagram-api), [Meta Messenger collection](https://www.postman.com/meta/messenger-platform-api/documentation/iyp204x/messenger-platform-api).

Per-rule source IDs in the JSON identify the relevant references. Community lists
are pinned to v2fly/domain-list-community revision
`e8f6d1e5c4a01cda943c0784ffa834340eeab5ae` with its MIT license; nDPI facts are pinned
to `2b8c2989f8c36f94a639057aeebd4fc71d841928`. Snapshot hashes are in the evidence
manifest. Sources reviewed on 2026-10-21 can change and must be revisited when
validation exposes missing or shared names.
