import requests
import json
from datetime import datetime,timedelta
def get_vulns():
    url = 'https://www.wordfence.com/api/intelligence/v2/vulnerabilities/production'
    response = requests.get(url, headers={"User-Agent": "curl/7.79.1"})
    response.raise_for_status()
    data = response.json()
    result = []
    now = datetime.now()
    for vuln in data.values():
        title = vuln.get("title")
        cwe = vuln.get("cwe") or {}
        references = vuln.get("references") or []
        url = references[0] if references else None
        published = vuln.get("published")
        plugin = vuln.get("software", [{}])[0]
        slug = plugin.get("slug")

        if not published or not slug:
            continue

        published_new = datetime.strptime(published, "%Y-%m-%d %H:%M:%S")
        if published_new >= now - timedelta(days=3):
            url2 = f'https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request[slug]={slug}&request[fields][active_installs]=true'
            try:
                response2 = requests.get(url2, headers={"User-Agent": "curl/7.79.1"})
                response2.raise_for_status()
                data2 = response2.json()
                active_installs = data2.get("active_installs")
                result.append({
                    "title" : title,
                    "install" : active_installs,
                    "url" : url,
                    "cwe" : cwe,
                    "newest": published_new
                })
            except requests.HTTPError as e:
                if e.response is not None and e.response.status_code == 404:
                    continue
                raise
    result = sorted(result,key=lambda d: d.get("install", 0), reverse=True)
    return result
