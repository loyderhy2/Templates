#!/usr/bin/env bash
set -euo pipefail
H1_USERNAME="${H1_USERNAME:-trekmail}"
OUT="ripio-auth-mfa-chunk"
rm -rf "$OUT" && mkdir -p "$OUT"
URL="https://auth.ripio.com/beda80af2e0f6b76e868.js"
curl --location --compressed --silent --show-error \
  --connect-timeout 15 --max-time 90 --retry 1 \
  --header "X-H1-traffic: ${H1_USERNAME}" \
  --header "User-Agent: Mozilla/5.0 HackerOne-authorized-security-research/${H1_USERNAME}" \
  --dump-header "$OUT/chunk.headers.txt" \
  --output "$OUT/chunk.js" \
  --write-out 'http_code=%{http_code}\neffective_url=%{url_effective}\nremote_ip=%{remote_ip}\ncontent_type=%{content_type}\nsize_download=%{size_download}\n' \
  "$URL" > "$OUT/chunk.meta.txt"
python3 - "$OUT/chunk.js" "$OUT" <<'PY'
from pathlib import Path
from urllib.parse import urlparse
import json, re, sys
src=Path(sys.argv[1]).read_text('utf-8',errors='replace'); out=Path(sys.argv[2])
urls=sorted(set(x.rstrip(';,') for x in re.findall(r"https?://[^\s\"'<>\\)]+",src)))
hosts=sorted(set(filter(None,(urlparse(x).hostname for x in urls))))
keywords=re.compile(r"mfa|otp|totp|passkey|challenge|verification|verify|proof|authflow|access_login_mfa|reset|recovery|token|session|device",re.I)
routes=sorted(set(x for x in re.findall(r'''["'](/[^"'\\\s]{2,500})["']''',src) if keywords.search(x)))
contexts=[]; seen=set()
for m in keywords.finditer(src):
    a=max(0,m.start()-300); b=min(len(src),m.end()+500)
    c=re.sub(r'\s+',' ',src[a:b])[:1200]
    if c not in seen:
        seen.add(c); contexts.append({'keyword':m.group(0),'offset':m.start(),'context':c})
    if len(contexts)>=4000: break
(out/'urls.txt').write_text('\n'.join(urls)+('\n' if urls else ''))
(out/'hosts.txt').write_text('\n'.join(hosts)+('\n' if hosts else ''))
(out/'routes.txt').write_text('\n'.join(routes)+('\n' if routes else ''))
(out/'contexts.json').write_text(json.dumps(contexts,indent=2,ensure_ascii=False))
(out/'safety.txt').write_text(f'h1_header=X-H1-traffic: {"trekmail"}\nrequests=1\ncredentials_used=no\notp_attempts=0\nstate_changing_requests=0\n')
PY
cat "$OUT/chunk.meta.txt"
printf '\n===== ROUTES =====\n'; sed -n '1,400p' "$OUT/routes.txt"
printf '\n===== HOSTS =====\n'; sed -n '1,200p' "$OUT/hosts.txt"
printf '\n===== CONTEXTS =====\n'; sed -n '1,500p' "$OUT/contexts.json"
printf '\n===== SAFETY =====\n'; cat "$OUT/safety.txt"
