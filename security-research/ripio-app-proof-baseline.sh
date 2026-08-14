#!/usr/bin/env bash
set -euo pipefail
H1_USERNAME="${H1_USERNAME:-trekmail}"
OUT="ripio-app-proof-baseline"
rm -rf "$OUT" && mkdir -p "$OUT"
for endpoint in accounts-me balance; do
  case "$endpoint" in
    accounts-me) url="https://app.ripio.com/api/v3/accounts/me/" ;;
    balance) url="https://app.ripio.com/api/v3/balance/" ;;
  esac
  curl --location --max-redirs 0 --compressed --silent --show-error \
    --connect-timeout 15 --max-time 60 --retry 1 \
    --header "X-H1-traffic: ${H1_USERNAME}" \
    --header "User-Agent: Mozilla/5.0 HackerOne-authorized-security-research/${H1_USERNAME}" \
    --header "Accept: application/json, text/plain, */*" \
    --dump-header "$OUT/${endpoint}.headers.txt" \
    --output "$OUT/${endpoint}.body" \
    --write-out 'http_code=%{http_code}\neffective_url=%{url_effective}\nredirect_url=%{redirect_url}\nremote_ip=%{remote_ip}\ncontent_type=%{content_type}\nsize_download=%{size_download}\n' \
    "$url" > "$OUT/${endpoint}.meta.txt" || true
done
python3 - "$OUT" <<'PY'
from pathlib import Path
import hashlib,json,sys
out=Path(sys.argv[1]); result={}
for name in ('accounts-me','balance'):
    body=(out/f'{name}.body').read_bytes() if (out/f'{name}.body').exists() else b''
    meta=(out/f'{name}.meta.txt').read_text('utf-8',errors='replace') if (out/f'{name}.meta.txt').exists() else ''
    item={'meta':dict(line.split('=',1) for line in meta.splitlines() if '=' in line),'body_length':len(body),'body_sha256':hashlib.sha256(body).hexdigest()}
    try:
        data=json.loads(body.decode('utf-8'))
        item['body_type']='json'
        item['json_shape']=sorted(data.keys()) if isinstance(data,dict) else {'type':type(data).__name__,'count':len(data) if isinstance(data,list) else None}
    except Exception:
        item['body_type']='text_or_binary'
        item['preview']=body[:200].decode('utf-8',errors='replace').replace('\n',' ')
    result[name]=item
(out/'redacted-baseline.json').write_text(json.dumps(result,indent=2,sort_keys=True),encoding='utf-8')
PY
cat "$OUT/redacted-baseline.json"
printf '\nX-H1-traffic: %s\ncredentials_used=no\nstate_changing_requests=0\n' "$H1_USERNAME"
