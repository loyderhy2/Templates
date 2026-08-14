#!/usr/bin/env bash
set -euo pipefail

H1_USERNAME="${H1_USERNAME:-trekmail}"
OUT="ripio-app-startup-chunks"
rm -rf "$OUT" && mkdir -p "$OUT/chunks" "$OUT/summary"

MAIN_URL="https://app.ripio.com/main5e2a276d601ef7357b7c.js"
MAIN="$OUT/main.js"
curl --location --compressed --silent --show-error \
  --connect-timeout 15 --max-time 90 --retry 1 \
  --header "X-H1-traffic: ${H1_USERNAME}" \
  --header "User-Agent: Mozilla/5.0 HackerOne-authorized-security-research/${H1_USERNAME}" \
  --output "$MAIN" "$MAIN_URL"

python3 - "$MAIN" "$OUT/summary/urls.txt" <<'PY'
from pathlib import Path
import re,sys
text=Path(sys.argv[1]).read_text('utf-8',errors='replace')
map_match=re.search(r'l\.u=e=>""\+e\+\{(.*?)\}\[e\]\+"\.js"',text)
if not map_match:
    raise SystemExit('runtime chunk map not found')
pairs=dict(re.findall(r'(\d+):"([0-9a-f]+)"',map_match.group(1)))
startup=[]
entry=re.search(r'Promise\.all\(\[(.*?)\]\)\.then\(f\.bind\(f,88335\)\)',text)
if entry:
    startup=re.findall(r'f\.e\((\d+)\)',entry.group(1))
# Runtime marks several shared chunks as already available; only mapped chunks require GETs.
urls=[]
for chunk_id in startup:
    digest=pairs.get(chunk_id)
    if digest:
        urls.append(f'https://app.ripio.com/{chunk_id}{digest}.js')
Path(sys.argv[2]).write_text('\n'.join(urls)+('\n' if urls else ''),encoding='utf-8')
print('startup_ids=' + ','.join(startup))
print('mapped_requests=' + str(len(urls)))
PY

count=0
while IFS= read -r url; do
  [ -n "$url" ] || continue
  count=$((count+1))
  curl --location --compressed --silent --show-error \
    --connect-timeout 15 --max-time 120 --retry 1 \
    --header "X-H1-traffic: ${H1_USERNAME}" \
    --header "User-Agent: Mozilla/5.0 HackerOne-authorized-security-research/${H1_USERNAME}" \
    --dump-header "$OUT/chunks/${count}.headers.txt" \
    --output "$OUT/chunks/${count}.js" \
    --write-out 'http_code=%{http_code}\neffective_url=%{url_effective}\nremote_ip=%{remote_ip}\ncontent_type=%{content_type}\nsize_download=%{size_download}\n' \
    "$url" > "$OUT/chunks/${count}.meta.txt"
done < "$OUT/summary/urls.txt"

python3 - "$OUT" <<'PY'
from pathlib import Path
from urllib.parse import urlparse
import json,re,sys
out=Path(sys.argv[1]); kw=re.compile(r'auth|login|logout|session|token|refresh|profile|user|account|wallet|balance|portfolio|asset|transfer|withdraw|deposit|transaction|security|2fa|mfa|otp|identity|kyc',re.I)
urls=set(); hosts=set(); routes=set(); contexts=[]; seen=set()
for p in sorted((out/'chunks').glob('*.js')):
    text=p.read_text('utf-8',errors='replace')
    for u in re.findall(r"https?://[^\s\"'<>\\)]+",text):
        u=u.rstrip(';,'); urls.add(u); h=urlparse(u).hostname
        if h: hosts.add(h)
    for r in re.findall(r'''["'](/[^"'\\\s]{2,700})["']''',text):
        if kw.search(r): routes.add(r)
    for m in kw.finditer(text):
        a=max(0,m.start()-300); b=min(len(text),m.end()+500)
        c=re.sub(r'\s+',' ',text[a:b])[:1200]
        if c not in seen:
            seen.add(c); contexts.append({'file':str(p),'keyword':m.group(0),'offset':m.start(),'context':c})
        if len(contexts)>=4000: break
(out/'summary/absolute-urls.txt').write_text('\n'.join(sorted(urls))+('\n' if urls else ''))
(out/'summary/hosts.txt').write_text('\n'.join(sorted(hosts))+('\n' if hosts else ''))
(out/'summary/routes.txt').write_text('\n'.join(sorted(routes))+('\n' if routes else ''))
(out/'summary/contexts.json').write_text(json.dumps(contexts,indent=2,ensure_ascii=False))
PY

{
 echo "h1_header=X-H1-traffic: ${H1_USERNAME}"
 echo "main_bundle_requests=1"
 echo "directly_referenced_startup_chunk_requests=${count}"
 echo "credentials_used=no"
 echo "otp_attempts=0"
 echo "state_changing_requests=0"
} > "$OUT/summary/safety.txt"

printf '\n===== CHUNK URLS =====\n'; cat "$OUT/summary/urls.txt"
printf '\n===== META =====\n'; cat "$OUT/chunks/"*.meta.txt 2>/dev/null || true
printf '\n===== HOSTS =====\n'; sed -n '1,300p' "$OUT/summary/hosts.txt"
printf '\n===== ROUTES =====\n'; sed -n '1,900p' "$OUT/summary/routes.txt"
printf '\n===== CONTEXTS =====\n'; sed -n '1,500p' "$OUT/summary/contexts.json"
printf '\n===== SAFETY =====\n'; cat "$OUT/summary/safety.txt"
