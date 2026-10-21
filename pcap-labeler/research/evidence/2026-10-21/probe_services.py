import concurrent.futures
import datetime
import html
import json
from pathlib import Path
import re
import subprocess
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parent
PAGES = [
    'https://www.youtube.com/', 'https://www.netflix.com/',
    'https://www.primevideo.com/', 'https://www.hulu.com/',
    'https://www.twitch.tv/', 'https://netflix.net/',
    'https://nflxsearch.net/', 'https://amazonvideo.com/',
]
HOSTS = [
    'www.youtube.com', 'youtubei.googleapis.com', 'youtube.googleapis.com',
    'youtubeembeddedplayer.googleapis.com', 'youtubeeducation.com',
    'youtube-nocookie.com', 'youtu.be', 'i.ytimg.com',
    'www.netflix.com', 'netflix.net', 'nflxsearch.net', 'assets.nflxext.com',
    'occ.a.nflxso.net', 'www.primevideo.com', 'amazonvideo.com',
    'api.eu-west-1.aiv-delivery.net', 'atv-ext.amazon.com',
    'cf-timedtext.aux.pv-cdn.net', 'avodassets-a.akamaihd.net',
    'www.hulu.com', 'www.huluim.com', 'hulustream.com',
    'hulu.playback.edge.bamgrid.com', 'hulu.conviva.com',
    'www.twitch.tv', 'static-cdn.jtvnw.net', 'static.twitchcdn.net',
    'usher.ttvnw.net', 'ext-twitch.tv', 'twitchsvc.net',
]
def page(url):
    result = {'requested_url': url, 'method': 'GET', 'tls_certificate_verification': True}
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 (compatible; PCAPDomainRuleReview/0.1)'})
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            body = response.read(2_000_001)
            result.update(status=response.status, final_url=response.url,
                          content_type=response.headers.get('Content-Type'),
                          response_bytes_read=len(body), truncated=len(body)>2_000_000)
            if 'html' in (response.headers.get('Content-Type') or '').lower():
                content = html.unescape(body.decode('utf-8', errors='replace')).replace('\\/', '/')
                hosts = set()
                for candidate in re.findall(r'https?://[^\s<>"\x27\\]+', content):
                    try:
                        host = urllib.parse.urlsplit(candidate).hostname
                        if host and re.fullmatch(r'[A-Za-z0-9.-]+',host):
                            hosts.add(host.lower())
                    except ValueError:
                        pass
                result['hostnames_referenced_in_static_html'] = sorted(hosts)
    except urllib.error.HTTPError as exc:
        result.update(status=exc.code, final_url=exc.url, error='HTTPError')
    except Exception as exc:
        result['error'] = type(exc).__name__ + ': ' + str(exc)
    return result

def dns(host):
    result = {'hostname': host, 'records': {}}
    for kind in ['A', 'AAAA', 'CNAME']:
        p = subprocess.run(['/usr/bin/dig', '+time=3', '+tries=1', '+noall', '+comments', '+answer', host, kind], capture_output=True, text=True, timeout=6)
        status = re.search(r'status: ([A-Z]+)',p.stdout)
        result['records'][kind] = {'status': status.group(1) if status else 'unknown',
                                  'answers': [x for x in p.stdout.splitlines() if x and not x.startswith(';')],
                                  'exit_code':p.returncode}
    return result

if __name__ == "__main__":
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        pages=list(pool.map(page,PAGES))
        records=list(pool.map(dns,HOSTS))
    report = {'started_from': 'local execution host; not a university capture vantage point',
              'recorded_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'method_limits': ['No login or playback was performed.', 'Static HTML references are not observed subresource connections.', 'HTTP status or DNS resolution alone does not prove application exclusivity.', 'NXDOMAIN or no address at a root name does not disprove live subdomains.'],
              'http':pages,'dns':records}
    (ROOT/'live-probes.json').write_text(json.dumps(report,indent=2)+'\n')
    for result in pages:
        print(json.dumps(result))
    print('DNS probes:',len(records))
