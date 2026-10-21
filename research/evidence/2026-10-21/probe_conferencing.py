import concurrent.futures
import json
from probe_services import page, dns, ROOT
PAGES=['https://zoom.us/','https://zoom.com/','https://teams.microsoft.com/','https://teams.cloud.microsoft/','https://meet.google.com/','https://www.webex.com/']
HOSTS=['zoom.us','zoom.com','teams.microsoft.com','teams.cloud.microsoft','meet.google.com','meetings.googleapis.com','meet.turns.goog','workspace.turns.goog','www.webex.com','webexapis.com','youtubei-att.googleapis.com','i.huluim.com','huluqa.com']
with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
    pages=list(pool.map(page,PAGES))
    records=list(pool.map(dns,HOSTS))
report={'method_limits':['No login, meeting join, or media playback was performed.','Static HTML references are not observed subresource connections.','The local resolver sometimes returns special-use IPs; answers are diagnostic only, not public IP ranges.'],'http':pages,'dns':records}
(ROOT/'conferencing-probes.json').write_text(json.dumps(report,indent=2)+'\n')
for item in pages:
    print(item['requested_url'],item.get('status'),item.get('final_url'),item.get('error'))
print('Additional DNS probes:',len(records))
