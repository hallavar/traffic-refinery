"""Public, anonymous landing-page and DNS observations; not playback validation."""
import concurrent.futures, datetime, hashlib, html, json, re, subprocess
import urllib.request, urllib.error, urllib.parse
from pathlib import Path
ROOT=Path(__file__).resolve().parent
URLS=[
'https://www.disneyplus.com/','https://www.facebook.com/','https://www.instagram.com/',
'https://www.tiktok.com/','https://www.snapchat.com/','https://x.com/',
'https://www.xbox.com/','https://store.steampowered.com/','https://www.playstation.com/',
'https://store.epicgames.com/','https://www.whatsapp.com/','https://www.messenger.com/',
'https://facetime.apple.com/','https://discord.com/','https://tubitv.com/',
'https://www.roku.com/','https://tv.apple.com/','https://pluto.tv/','https://www.plex.tv/',
'https://open.spotify.com/','https://music.apple.com/','https://music.amazon.com/',
'https://play.geforcenow.com/','https://start.qq.com/',
'https://alexa.amazon.com/','https://bixby.samsung.com/',
'https://bixbydevelopers.com/','https://www.philips-hue.com/','https://www.smartthings.com/',
'https://chatgpt.com/','https://api.openai.com/','https://copilot.microsoft.com/',
'https://gemini.google.com/','https://claude.ai/'
]
EXTRA_HOSTS=['graph.facebook.com','edge-mqtt.facebook.com','chat-e2ee-mini.facebook.com',
'api.music.apple.com','guzzoni.apple.com','api.music.amazon.dev',
'api.smartthings.com','discovery.meethue.com','api.amazonalexa.com',
'avs-alexa-na.amazon.com','bixby-client.aibixby.com','api.githubcopilot.com',
'copilot.cloud.microsoft','generativelanguage.googleapis.com','api.anthropic.com']
def page(url):
    result={'requested_url':url,'method':'GET','tls_verification':True}
    try:
        req=urllib.request.Request(url,headers={'User-Agent':'Mozilla/5.0 (compatible; PCAPDomainRuleReview/0.1)'})
        with urllib.request.urlopen(req,timeout=15) as response:
            body=response.read(350001)
            result.update(status=response.status,final_hostname=urllib.parse.urlsplit(response.url).hostname,
                          bytes_read=len(body),truncated=len(body)>350000,body_prefix_sha256=hashlib.sha256(body).hexdigest())
            if 'html' in (response.headers.get('Content-Type') or '').lower():
                content=html.unescape(body.decode('utf-8',errors='replace')).replace('\\/','/')
                hosts=set()
                for value in re.findall(r'https?://[^\s<>"\x27\\]+',content):
                    try:
                        host=urllib.parse.urlsplit(value).hostname
                        if host and re.fullmatch(r'[A-Za-z0-9.-]+',host): hosts.add(host.lower())
                    except ValueError: pass
                result['static_html_hostname_references']=sorted(hosts)
    except urllib.error.HTTPError as exc:
        result.update(status=exc.code,error='HTTPError',final_hostname=urllib.parse.urlsplit(exc.url).hostname)
    except Exception as exc:
        result['error']=type(exc).__name__+': '+str(exc)
    return result

def dns(host):
    result={'hostname':host,'records':{}}
    for kind in ['A','CNAME']:
        try:
            proc=subprocess.run(['/usr/bin/dig','+time=2','+tries=1','+noall','+comments','+answer',host,kind],capture_output=True,text=True,timeout=5)
            status=re.search(r'status: ([A-Z]+)',proc.stdout)
            result['records'][kind]={'status':status.group(1) if status else 'unknown','answers':[x for x in proc.stdout.splitlines() if x and not x.startswith(';')],'exit_code':proc.returncode}
        except Exception as exc: result['records'][kind]={'error':type(exc).__name__+': '+str(exc)}
    return result
if __name__=='__main__':
    started=datetime.datetime.now(datetime.timezone.utc).isoformat()
    hosts=sorted({urllib.parse.urlsplit(url).hostname for url in URLS}|set(EXTRA_HOSTS))
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        pages=list(pool.map(page,URLS))
        records=list(pool.map(dns,hosts))
    report={'started_at_utc':started,'finished_at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'limits':['No login, API keys, meeting join, streaming, gaming session or packet capture.','HTML references are not observed subresource connections or proof of exclusive use.','The execution resolver may synthesize special-use addresses. No IP rules are derived.','HTTP failures or absent root records do not rule out working app clients or subdomains.'],
            'http':pages,'dns':records}
    (ROOT/'live-additional-probes.json').write_text(json.dumps(report,indent=2)+'\n')
    for result in pages: print(result['requested_url'],result.get('status'),result.get('final_hostname'),result.get('error',''))
    print(len(hosts),'DNS hostnames checked')
