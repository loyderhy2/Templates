#!/usr/bin/env bash
set -uo pipefail

H1_USERNAME="${H1_USERNAME:-trekmail}"
OUT="${OUT:-ripio-auth-artifacts}"
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

fetch_target "https://auth.ripio.com/" "root/https-index"
fetch_target "http://auth.ripio.com/" "root/http-index"

python3 - "$OUT" <<'PY'
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlparse
import json
import re
import sys

out = Path(sys.argv[1])
root = "https://auth.ripio.com/"
html_path = out / "root/https-index.body"

class Parser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.assets = set()
        self.forms = []
        self.meta = []
        self.inline = []
        self.in_script = False
        self.buf = []

    def handle_starttag(self, tag, attrs):
        data = dict(attrs)
        if tag == "script" and data.get("src"):
            self.assets.add(urljoin(root, data["src"]))
        elif tag == "script":
            self.in_script = True
            self.buf = []
        elif tag == "link" and data.get("href"):
            self.assets.add(urljoin(root, data["href"]))
        elif tag in {"img", "source"} and data.get("src"):
            self.assets.add(urljoin(root, data["src"]))
        elif tag == "form":
            self.forms.append(data)
        elif tag == "meta":
            self.meta.append(data)

    def handle_data(self, data):
        if self.in_script:
            self.buf.append(data)

    def handle_endtag(self, tag):
        if tag == "script" and self.in_script:
            text = "".join(self.buf).strip()
            if text:
                self.inline.append(text)
            self.in_script = False
            self.buf = []

html = html_path.read_text("utf-8", errors="replace") if html_path.exists() else ""
parser = Parser()
parser.feed(html)

same_origin = []
external = []
for url in sorted(parser.assets):
    parsed = urlparse(url)
    if parsed.scheme in {"http", "https"} and parsed.hostname == "auth.ripio.com":
        same_origin.append(url)
    else:
        external.append(url)

# Defensive fallback for compact/minified HTML.
for value in re.findall(r'''(?:src|href)=["']([^"']+)["']''', html, flags=re.I):
    url = urljoin(root, value)
    parsed = urlparse(url)
    if parsed.scheme in {"http", "https"} and parsed.hostname == "auth.ripio.com" and url not in same_origin:
        same_origin.append(url)

same_origin = sorted(set(same_origin))[:100]
(out / "summary/same-origin-assets.txt").write_text("\n".join(same_origin) + ("\n" if same_origin else ""), encoding="utf-8")
(out / "summary/external-assets.txt").write_text("\n".join(external) + ("\n" if external else ""), encoding="utf-8")
(out / "summary/forms.json").write_text(json.dumps(parser.forms, indent=2, ensure_ascii=False), encoding="utf-8")
(out / "summary/meta.json").write_text(json.dumps(parser.meta, indent=2, ensure_ascii=False), encoding="utf-8")
(out / "summary/inline-scripts.txt").write_text("\n\n--- INLINE ---\n\n".join(parser.inline), encoding="utf-8")
absolute = sorted(set(re.findall(r"https?://[^\s\"'<>\\)]+", html)))
(out / "summary/html-absolute-urls.txt").write_text("\n".join(absolute) + ("\n" if absolute else ""), encoding="utf-8")
PY

asset_count=0
while IFS= read -r url; do
  [ -n "$url" ] || continue
  asset_count=$((asset_count + 1))
  [ "$asset_count" -le 100 ] || break
  clean="$(printf '%s' "$url" | sed -E 's/[?#].*$//')"
  ext="$(printf '%s' "$clean" | sed -nE 's/.*\.([A-Za-z0-9]{1,10})$/\1/p')"
  case "$ext" in
    js|css|json|map|txt|xml|webmanifest|ico|svg|png|jpg|jpeg|woff|woff2|ttf) ;;
    *) ext="bin" ;;
  esac
  stem="static/$(printf '%04d' "$asset_count").${ext}"
  printf '%04d\t%s\t%s\n' "$asset_count" "$url" "$stem" >> "$OUT/summary/static-index.tsv"
  fetch_target "$url" "$stem"
done < "$OUT/summary/same-origin-assets.txt"

# Fetch same-origin source maps explicitly referenced by downloaded JS, capped at 20.
python3 - "$OUT" <<'PY'
from pathlib import Path
from urllib.parse import urljoin, urlparse
import re
import sys

out = Path(sys.argv[1])
index = out / "summary/static-index.tsv"
base_by_stem = {}
if index.exists():
    for line in index.read_text("utf-8", errors="replace").splitlines():
        parts = line.split("\t")
        if len(parts) == 3:
            base_by_stem[parts[2]] = parts[1]
urls = set()
for body in (out / "static").glob("*.js.body"):
    stem = body.name[:-5]
    source_url = base_by_stem.get("static/" + stem)
    if not source_url:
        continue
    text = body.read_text("utf-8", errors="replace")
    for rel in re.findall(r"sourceMappingURL=([^\s*]+)", text):
        url = urljoin(source_url, rel.strip())
        p = urlparse(url)
        if p.scheme == "https" and p.hostname == "auth.ripio.com":
            urls.add(url)
(out / "summary/source-map-urls.txt").write_text("\n".join(sorted(urls)[:20]) + ("\n" if urls else ""), encoding="utf-8")
PY

map_count=0
while IFS= read -r url; do
  [ -n "$url" ] || continue
  map_count=$((map_count + 1))
  fetch_target "$url" "static/map-$(printf '%02d' "$map_count").map"
done < "$OUT/summary/source-map-urls.txt"

python3 - "$OUT" <<'PY'
from pathlib import Path
from urllib.parse import urlparse
import json
import re
import sys

out = Path(sys.argv[1])
texts = []
for path in list((out / "root").glob("*.body")) + list((out / "static").glob("*.body")):
    try:
        if path.stat().st_size <= 40_000_000:
            texts.append((str(path), path.read_text("utf-8", errors="replace")))
    except OSError:
        pass

absolute_urls = set()
hosts = set()
routes = set()
js_files = set()
keywords = re.compile(r"2fa|two.?factor|totp|otp|challenge|refresh.?token|access.?token|id.?token|trusted.?device|remember.?device|recovery|password|authorize|oauth|openid|state|nonce|code.?verifier|code.?challenge|callback|session|login|logout|wallet|balance|transfer|withdraw|verify|verification|captcha|recaptcha|turnstile", re.I)
contexts = []
seen_contexts = set()

for filename, text in texts:
    for value in re.findall(r"https?://[^\s\"'<>\\)]+", text):
        if len(value) <= 1000:
            absolute_urls.add(value.rstrip(";,"))
            host = urlparse(value).hostname
            if host:
                hosts.add(host)
    for value in re.findall(r'''["'](/[^"'\\\s]{2,500})["']''', text):
        if keywords.search(value):
            routes.add(value)
    for value in re.findall(r'''["']([^"'\\\s]{1,300}\.js(?:\?[^"']*)?)["']''', text):
        js_files.add(value)
    for match in keywords.finditer(text):
        start = max(0, match.start() - 220)
        end = min(len(text), match.end() + 320)
        snippet = re.sub(r"\s+", " ", text[start:end])
        key = snippet[:600]
        if key not in seen_contexts:
            seen_contexts.add(key)
            contexts.append({"file": filename, "keyword": match.group(0), "context": snippet[:900]})
        if len(contexts) >= 2500:
            break

(out / "summary/all-absolute-urls.txt").write_text("\n".join(sorted(absolute_urls)) + ("\n" if absolute_urls else ""), encoding="utf-8")
(out / "summary/all-hosts.txt").write_text("\n".join(sorted(hosts)) + ("\n" if hosts else ""), encoding="utf-8")
(out / "summary/route-candidates.txt").write_text("\n".join(sorted(routes)) + ("\n" if routes else ""), encoding="utf-8")
(out / "summary/js-file-candidates.txt").write_text("\n".join(sorted(js_files)) + ("\n" if js_files else ""), encoding="utf-8")
(out / "summary/high-value-contexts.json").write_text(json.dumps(contexts, indent=2, ensure_ascii=False), encoding="utf-8")
PY

{
  echo "h1_header=X-H1-traffic: ${H1_USERNAME}"
  echo "unauthenticated_root_requests=2"
  echo "same_origin_static_requests=${asset_count}"
  echo "source_map_requests=${map_count}"
  echo "credentials_used=no"
  echo "otp_attempts=0"
  echo "state_changing_requests=0"
} > "$OUT/summary/safety-accounting.txt"

printf '\n===== HTTPS META =====\n'; cat "$OUT/root/https-index.meta.txt" 2>/dev/null || true
printf '\n===== HTTPS HEADERS =====\n'; sed -n '1,120p' "$OUT/root/https-index.headers.txt" 2>/dev/null || true
printf '\n===== SAME-ORIGIN ASSETS =====\n'; sed -n '1,180p' "$OUT/summary/same-origin-assets.txt" 2>/dev/null || true
printf '\n===== STATIC INDEX =====\n'; cat "$OUT/summary/static-index.tsv" 2>/dev/null || true
printf '\n===== SOURCE MAPS =====\n'; cat "$OUT/summary/source-map-urls.txt" 2>/dev/null || true
printf '\n===== HOSTS =====\n'; sed -n '1,300p' "$OUT/summary/all-hosts.txt" 2>/dev/null || true
printf '\n===== ABSOLUTE URLS =====\n'; sed -n '1,500p' "$OUT/summary/all-absolute-urls.txt" 2>/dev/null || true
printf '\n===== ROUTE CANDIDATES =====\n'; sed -n '1,700p' "$OUT/summary/route-candidates.txt" 2>/dev/null || true
printf '\n===== JS FILE CANDIDATES =====\n'; sed -n '1,500p' "$OUT/summary/js-file-candidates.txt" 2>/dev/null || true
printf '\n===== HIGH-VALUE CONTEXTS (FIRST 220 LINES) =====\n'; sed -n '1,220p' "$OUT/summary/high-value-contexts.json" 2>/dev/null || true
printf '\n===== SAFETY =====\n'; cat "$OUT/summary/safety-accounting.txt" 2>/dev/null || true
