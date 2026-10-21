import concurrent.futures, hashlib, json, urllib.request
from pathlib import Path
ROOT=Path(__file__).resolve().parent
DEST=ROOT/'v2fly'
DEST.mkdir(exist_ok=True)
SHA='e8f6d1e5c4a01cda943c0784ffa834340eeab5ae'
NAMES=['disney','facebook','facebook-dev','instagram','tiktok','snap','twitter','xbox','steam','playstation','epicgames','whatsapp','messenger','discord','tubi','roku','apple','apple-music','apple-tvplus','plutotv','plex','spotify','amazon','nvidia','tencent','tencent-games','openai','github-copilot','google-gemini','anthropic','LICENSE']
def fetch(name):
    path=name if name=='LICENSE' else 'data/'+name
    url=f'https://raw.githubusercontent.com/v2fly/domain-list-community/{SHA}/{path}'
    with urllib.request.urlopen(url,timeout=25) as response:
        data=response.read()
    (DEST/name).write_bytes(data)
    return {'name':name,'url':url,'sha256':hashlib.sha256(data).hexdigest(),'lines':len(data.splitlines())}
with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
    rows=list(pool.map(fetch,NAMES))
(ROOT/'v2fly-manifest.json').write_text(json.dumps({'revision':SHA,'retrieved_on':'2026-10-21','files':rows},indent=2)+'\n')
for row in rows:
    print(row['name'],row['lines'])
