#!/usr/bin/env bash
set -uo pipefail

H1_USERNAME="${H1_USERNAME:-trekmail}"
OUT="${OUT:-ripio-auth-artifacts}"
mkdir -p "$OUT/root" "$OUT/static" "$OUT/summary"

fetch_target() {
  local url="$1" stem="$2"
  curl --location --compressed --silent --show-error \
    --connect-timeout 15 --max-time 60 --retry 1 --retry-delay 1 \
    --header "X-H1-traffic: ${H1_USERNAME}" \
    --header "User-Agent: Mozilla/5.0 HackerOne-authorized-security-research/${H1_USERNAME}" \
    --dump-header "$OUT/${stem}.headers.txt" \
    --output "$OUT/${stem}.body" \
    --write-out 'http_code=%{http_code}\neffective_url=%{url_effective}\nremote_ip=%{remote_ip}\ncontent_type=%{content_type}\nsize_download=%{size_download}\n' \
    "$url" > "$OUT/${stem}.meta.txt" 2>> "$OUT/summary/curl-errors.log" || true
}

fetch_target "https://auth.ripio.com/" "root/https-index"
fetch_target "http://auth.ripio.com/" "root/http-index"

python3 - "$OUT" <<'PY'
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlparse
import json, re, sys
out = Path(sys.argv[1]); root = 'https://auth.ripio.com/'
html_path = out/'root/https-index.body'
class P(HTMLParser):
    def __init__(self):
        super().__init__(); self.assets=set(); self.forms=[]; self.meta=[]; self.inline=[]; self.ins=False; self.buf=[]
    def handle_starttag(self, tag, attrs):
        d=dict(attrs)
        if tag=='script' and d.get('src'): self.assets.add(urljoin(root,d['src']))
        elif tag=='script': self.ins=True; self.buf=[]
        elif tag=='link' and d.get('href'): self.assets.add(urljoin(root,d['href']))
        elif tag in {'img','source'} and d.get('src'): self.assets.add(urljoin(root,d['src']))
        elif tag=='form': self.forms.append(d)
        elif tag=='meta': self.meta.append(d)
    def handle_data(self,data):
        if self.ins: self.buf.append(data)
    def handle_endtag(self,tag):
        if tag=='script' and self.ins:
            s=''.join(self.buf).strip()
            if s: self.inline.append(s)
            self.ins=False; self.buf=[]
p=P(); html=html_path.read_text('utf-8',errors='replace') if html_path.exists() else ''; p.feed(html)
same=[]; external=[]
for u in sorted(p.assets):
    q=urlparse(u)
    (same if q.scheme in {'http','https'} and q.hostname=='auth.ripio.com' else external).append(u)
(out/'summary/same-origin-assets.txt').write_text('\n'.join(same[:100])+('\n' if same else ''))
(out/'summary/external-assets.txt').write_text('\n'.join(external)+('\n' if external else ''))
(out/'summary/forms.json').write_text(json.dumps(p.forms,indent=2,ensure_ascii=False))
(out/'summary/meta.json').write_text(json.dumps(p.meta,indent=2,ensure_ascii=False))
(out/'summary/inline-scripts.txt').write_text('\n\n--- INLINE ---\n\n'.join(p.inline))
(out/'summary/html-absolute-urls.txt').write_text('\n'.join(sorted(set(re.findall(r'https?://[^\s\"\'<>\\)]+',html))))
PY

asset_count=0
while IFS= read -r url; do
  [ -n "$url" ] || continue
  asset_count=$((asset_count+1)); [ "$asset_count" -le 100 ] || break
  clean="$(printf '%s' "$url" | sed -E 's/[?#].*$//')"
  ext="$(printf '%s' "$clean" | sed -nE 's/.*\.([A-Za-z0-9]{1,10})$/\1/p')"
  case "$ext" in js|css|json|map|txt|xml|webmanifest|ico|svg|png|jpg|jpeg|woff|woff2|ttf) ;; *) ext=bin ;; esac
  printf '%04d\t%s\n' "$asset_count" "$url" >> "$OUT/summary/static-index.tsv"
  fetch_target "$url" "static/$(printf '%04d' "$asset_count").${ext}"
done < "$OUT/summary/same-origin-assets.txt"

find "$OUT/root" "$OUT/static" -type f -name '*.body' -print0 | xargs -0 grep -aEho "https?://[^\"'<> )]+" 2>/dev/null | sort -u > "$OUT/summary/all-absolute-urls.txt" || true
find "$OUT/root" "$OUT/static" -type f -name '*.body' -print0 | xargs -0 grep -aEin '2fa|two.?factor|totp|otp|challenge|refresh.?token|access.?token|id.?token|trusted.?device|remember.?device|recovery|password|authorize|oauth|openid|state|nonce|code.?verifier|code.?challenge|callback|session|login|logout|wallet|balance|transfer|withdraw|verify|verification|captcha|recaptcha|turnstile' 2>/dev/null | head -n 200000 > "$OUT/summary/high-value-hits.txt" || true

python3 - "$OUT" <<'PY'
from pathlib import Path
import re,sys
out=Path(sys.argv[1]); texts=[]
for p in list((out/'root').glob('*.body'))+list((out/'static').glob('*.body')):
    try:
        if p.stat().st_size<=30_000_000: texts.append(p.read_text('utf-8',errors='replace'))
    except OSError: pass
blob='\n'.join(texts); vals=set()
for pat in [r'https?://[^\s\"\'<>\\)]+',r'/(?:api|auth|oauth|login|logout|session|token|refresh|2fa|otp|totp|challenge|verify|verification|recovery|password|device|user|profile|wallet|balance|transfer|withdraw)[A-Za-z0-9_./?=&%{}:\-]*']:
    for m in re.findall(pat,blob,flags=re.I):
        if 3<=len(m)<=500: vals.add(m)
(out/'summary/route-candidates.txt').write_text('\n'.join(sorted(vals))+('\n' if vals else ''))
PY

{
 echo "h1_header=X-H1-traffic: ${H1_USERNAME}"
 echo "unauthenticated_root_requests=2"
 echo "same_origin_static_requests=${asset_count}"
 echo "credentials_used=no"
 echo "otp_attempts=0"
 echo "state_changing_requests=0"
} > "$OUT/summary/safety-accounting.txt"

printf '\n===== HTTPS META =====\n'; cat "$OUT/root/https-index.meta.txt" 2>/dev/null || true
printf '\n===== HTTPS HEADERS =====\n'; sed -n '1,120p' "$OUT/root/https-index.headers.txt" 2>/dev/null || true
printf '\n===== HTML =====\n'; sed -n '1,120p' "$OUT/root/https-index.body" 2>/dev/null || true
printf '\n===== ASSETS =====\n'; sed -n '1,160p' "$OUT/summary/same-origin-assets.txt" 2>/dev/null || true
printf '\n===== URLS =====\n'; sed -n '1,240p' "$OUT/summary/all-absolute-urls.txt" 2>/dev/null || true
printf '\n===== ROUTES =====\n'; sed -n '1,500p' "$OUT/summary/route-candidates.txt" 2>/dev/null || true
printf '\n===== HITS =====\n'; sed -n '1,700p' "$OUT/summary/high-value-hits.txt" 2>/dev/null || true
printf '\n===== SAFETY =====\n'; cat "$OUT/summary/safety-accounting.txt" 2>/dev/null || true
