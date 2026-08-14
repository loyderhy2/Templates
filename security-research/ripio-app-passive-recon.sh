#!/usr/bin/env bash
set -uo pipefail

H1_USERNAME="${H1_USERNAME:-trekmail}"
OUT="${OUT:-ripio-app-passive-recon}"
rm -rf "$OUT"
mkdir -p "$OUT/root" "$OUT/static" "$OUT/summary"

fetch_target() {
  local url="$1" stem="$2"
  curl --location --compressed --silent --show-error \
    --connect-timeout 15 --max-time 90 --retry 1 --retry-delay 1 \
    --header "X-H1-traffic: ${H1_USERNAME}" \
    --header "User-Agent: Mozilla/5.0 HackerOne-authorized-security-research/${H1_USERNAME}" \
    --dump-header "$OUT/${stem}.headers.txt" \
    --output "$OUT/${stem}.body" \
    --write-out 'http_code=%{http_code}\neffective_url=%{url_effective}\nremote_ip=%{remote_ip}\ncontent_type=%{content_type}\nsize_download=%{size_download}\n' \
    "$url" > "$OUT/${stem}.meta.txt" 2>> "$OUT/summary/curl-errors.log" || true
}

fetch_target "https://app.ripio.com/" "root/https-index"
fetch_target "http://app.ripio.com/" "root/http-index"

python3 - "$OUT" <<'PY'
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlparse
import json, re, sys

out = Path(sys.argv[1])
root = "https://app.ripio.com/"
html_path = out / "root/https-index.body"
html = html_path.read_text("utf-8", errors="replace") if html_path.exists() else ""

class Parser(HTMLParser):
    def __init__(self):
        super().__init__(); self.assets=set(); self.forms=[]; self.meta=[]
    def handle_starttag(self, tag, attrs):
        data=dict(attrs)
        if tag == "script" and data.get("src"):
            self.assets.add(urljoin(root, data["src"]))
        elif tag == "link" and data.get("href"):
            self.assets.add(urljoin(root, data["href"]))
        elif tag in {"img", "source"} and data.get("src"):
            self.assets.add(urljoin(root, data["src"]))
        elif tag == "form": self.forms.append(data)
        elif tag == "meta": self.meta.append(data)

p=Parser(); p.feed(html)
for value in re.findall(r'''(?:src|href)=["']([^"']+)["']''', html, flags=re.I):
    p.assets.add(urljoin(root, value))

same=[]; external=[]
for url in sorted(p.assets):
    parsed=urlparse(url)
    if parsed.scheme in {"http","https"} and parsed.hostname == "app.ripio.com": same.append(url)
    else: external.append(url)

(out/"summary/same-origin-assets.txt").write_text("\n".join(same[:120])+("\n" if same else ""), encoding="utf-8")
(out/"summary/external-assets.txt").write_text("\n".join(external)+( "\n" if external else ""), encoding="utf-8")
(out/"summary/forms.json").write_text(json.dumps(p.forms, indent=2, ensure_ascii=False), encoding="utf-8")
(out/"summary/meta.json").write_text(json.dumps(p.meta, indent=2, ensure_ascii=False), encoding="utf-8")
(out/"summary/html-absolute-urls.txt").write_text("\n".join(sorted(set(re.findall(r"https?://[^\s\"'<>\\)]+", html))))+"\n", encoding="utf-8")
PY

asset_count=0
while IFS= read -r url; do
  [ -n "$url" ] || continue
  asset_count=$((asset_count+1)); [ "$asset_count" -le 120 ] || break
  clean="$(printf '%s' "$url" | sed -E 's/[?#].*$//')"
  ext="$(printf '%s' "$clean" | sed -nE 's/.*\.([A-Za-z0-9]{1,10})$/\1/p')"
  case "$ext" in js|css|json|map|txt|xml|webmanifest|ico|svg|png|jpg|jpeg|woff|woff2|ttf) ;; *) ext="bin" ;; esac
  stem="static/$(printf '%04d' "$asset_count").${ext}"
  printf '%04d\t%s\t%s\n' "$asset_count" "$url" "$stem" >> "$OUT/summary/static-index.tsv"
  fetch_target "$url" "$stem"
done < "$OUT/summary/same-origin-assets.txt"

python3 - "$OUT" <<'PY'
from pathlib import Path
from urllib.parse import urlparse
import json, re, sys
out=Path(sys.argv[1])
texts=[]
for p in list((out/'root').glob('*.body'))+list((out/'static').glob('*.body')):
    try:
        if p.stat().st_size <= 45_000_000:
            texts.append((str(p),p.read_text('utf-8',errors='replace')))
    except OSError: pass

kw=re.compile(r'auth|login|logout|session|token|refresh|profile|user|account|wallet|balance|portfolio|asset|transfer|withdraw|deposit|transaction|security|2fa|mfa|otp|identity|kyc',re.I)
urls=set(); hosts=set(); routes=set(); contexts=[]; seen=set(); chunks=set()
for filename,text in texts:
    for u in re.findall(r"https?://[^\s\"'<>\\)]+",text):
        if len(u)<=1000:
            u=u.rstrip(';,'); urls.add(u)
            h=urlparse(u).hostname
            if h: hosts.add(h)
    for r in re.findall(r'''["'](/[^"'\\\s]{2,600})["']''',text):
        if kw.search(r): routes.add(r)
    for c in re.findall(r'''["']([^"'\\\s]{1,350}\.js(?:\?[^"']*)?)["']''',text): chunks.add(c)
    for m in kw.finditer(text):
        a=max(0,m.start()-260); b=min(len(text),m.end()+420)
        snip=re.sub(r'\s+',' ',text[a:b])[:1050]
        key=snip[:700]
        if key not in seen:
            seen.add(key); contexts.append({'file':filename,'keyword':m.group(0),'offset':m.start(),'context':snip})
        if len(contexts)>=3000: break

(out/'summary/all-absolute-urls.txt').write_text('\n'.join(sorted(urls))+('\n' if urls else ''),encoding='utf-8')
(out/'summary/all-hosts.txt').write_text('\n'.join(sorted(hosts))+('\n' if hosts else ''),encoding='utf-8')
(out/'summary/route-candidates.txt').write_text('\n'.join(sorted(routes))+('\n' if routes else ''),encoding='utf-8')
(out/'summary/js-file-candidates.txt').write_text('\n'.join(sorted(chunks))+('\n' if chunks else ''),encoding='utf-8')
(out/'summary/high-value-contexts.json').write_text(json.dumps(contexts,indent=2,ensure_ascii=False),encoding='utf-8')
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
printf '\n===== SAME-ORIGIN ASSETS =====\n'; sed -n '1,220p' "$OUT/summary/same-origin-assets.txt" 2>/dev/null || true
printf '\n===== HOSTS =====\n'; sed -n '1,350p' "$OUT/summary/all-hosts.txt" 2>/dev/null || true
printf '\n===== ROUTES =====\n'; sed -n '1,900p' "$OUT/summary/route-candidates.txt" 2>/dev/null || true
printf '\n===== CONTEXTS =====\n'; sed -n '1,280p' "$OUT/summary/high-value-contexts.json" 2>/dev/null || true
printf '\n===== SAFETY =====\n'; cat "$OUT/summary/safety-accounting.txt" 2>/dev/null || true
