#!/usr/bin/env python3
"""
nginx-log-analyzer.py — Ultimate nginx access log analyser
Produces a rich self-contained HTML dashboard.

Usage:
  # Snapshot mode (parse existing logs):
  python3 nginx-log-analyzer.py -l '/var/log/nginx/*_access.log' -o report.html

  # Live tail mode (collect N seconds then report):
  python3 nginx-log-analyzer.py -l '/var/log/nginx/*_access.log' -o report.html --tail --duration 60

  # Pipe from tail -f:
  tail -f /var/log/nginx/*_access.log | python3 nginx-log-analyzer.py --stdin -o report.html

Options:
  -l, --logs GLOB       Log file glob (default: /var/log/nginx/*_access.log)
  -o, --output FILE     HTML output path (default: /tmp/nginx-report.html)
  -n, --top N           Number of entries per table (default: 30)
  --tail                Run in live-tail mode, collect then report
  --duration SECS       How long to collect in tail mode (default: 60)
  --stdin               Read log lines from stdin
  --since MINUTES       Only analyse lines from last N minutes
  --open                Open report in browser after generating

  ls /var/www/void/ && nano nginx-log-analyzer.py && chmod +x nginx-log-analyzer.py && python3 nginx-log-analyzer.py -o /var/www/void/report.html 

# Snapshot of all nginx logs right now
python3 nginx-log-analyzer.py -o /tmp/report.html

# Custom glob
python3 nginx-log-analyzer.py -l '/var/log/nginx/*_access.log' -o report.html

# Only last 60 minutes
python3 nginx-log-analyzer.py --since 60 -o report.html

# Collect 2 minutes of live tail then report
python3 nginx-log-analyzer.py --tail --duration 120 -o report.html

# Pipe from tail -f manually
tail -f /var/log/nginx/*_access.log | python3 nginx-log-analyzer.py --stdin -o report.html

# Top 50 instead of 30
python3 nginx-log-analyzer.py -n 50 -o report.html

"""

import argparse
import collections
import datetime
import glob
import gzip
import html
import ipaddress
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from urllib.parse import unquote

# ─── CLI ──────────────────────────────────────────────────────────────────────
parser = argparse.ArgumentParser(description="nginx log analyser")
parser.add_argument("-l", "--logs",     default="/var/log/nginx/*_access.log")
parser.add_argument("-o", "--output",   default="/tmp/nginx-report.html")
parser.add_argument("-n", "--top",      type=int, default=30)
parser.add_argument("--tail",           action="store_true")
parser.add_argument("--duration",       type=int, default=60)
parser.add_argument("--stdin",          action="store_true")
parser.add_argument("--since",          type=int, default=0,
                    help="Only include lines from last N minutes (0=all)")
parser.add_argument("--open",           action="store_true")
args = parser.parse_args()

TOP_N = args.top

# ─── nginx combined log pattern ───────────────────────────────────────────────
# Handles: combined, combined_realip, custom with $http_x_forwarded_for
LOG_RE = re.compile(
    r'(?P<ip>\S+)\s+'           # remote_addr
    r'\S+\s+\S+\s+'             # ident, user
    r'\[(?P<time>[^\]]+)\]\s+'  # time
    r'"(?P<request>[^"]+)"\s+'  # request
    r'(?P<status>\d{3})\s+'     # status
    r'(?P<bytes>\d+|-)\s+'      # bytes
    r'"(?P<referrer>[^"]*)"\s+' # referrer
    r'"(?P<ua>[^"]*)"'          # user_agent
    r'(?:\s+"(?P<forwarded>[^"]*)")?'  # optional x-forwarded-for
)

TIME_FMT = "%d/%b/%Y:%H:%M:%S %z"

# ─── Bot / scanner / threat classification ───────────────────────────────────
BOT_SIGNATURES = {
    # Search engines (legitimate)
    "googlebot":         ("search",   "Googlebot"),
    "bingbot":           ("search",   "Bingbot"),
    "slurp":             ("search",   "Yahoo Slurp"),
    "duckduckbot":       ("search",   "DuckDuckBot"),
    "baiduspider":       ("search",   "Baiduspider"),
    "yandexbot":         ("search",   "YandexBot"),
    "applebot":          ("search",   "Applebot"),

    # SEO / monitoring (grey area)
    "semrushbot":        ("seo",      "SEMrush"),
    "ahrefsbot":         ("seo",      "Ahrefs"),
    "mj12bot":           ("seo",      "Majestic"),
    "dotbot":            ("seo",      "Moz DotBot"),
    "rogerbot":          ("seo",      "Moz Rogerbot"),
    "serpstatbot":       ("seo",      "SerpStat"),
    "linkresearchtools": ("seo",      "LinkResearchTools"),
    "seokicks":          ("seo",      "SEOkicks"),
    "blexbot":           ("seo",      "BLEXBot"),
    "petalbot":          ("seo",      "PetalBot"),

    # Social / preview
    "twitterbot":        ("social",   "Twitterbot"),
    "facebookexternalhit": ("social", "Facebook"),
    "linkedinbot":       ("social",   "LinkedIn"),
    "whatsapp":          ("social",   "WhatsApp"),
    "slackbot":          ("social",   "Slack"),
    "telegrambot":       ("social",   "Telegram"),
    "discordbot":        ("social",   "Discord"),

    # Monitoring / uptime
    "uptimerobot":       ("monitor",  "UptimeRobot"),
    "pingdom":           ("monitor",  "Pingdom"),
    "statuscake":        ("monitor",  "StatusCake"),
    "newrelic":          ("monitor",  "New Relic"),
    "datadog":           ("monitor",  "Datadog"),
    "site24x7":          ("monitor",  "Site24x7"),
    "hetrixtools":       ("monitor",  "HetrixTools"),

    # Scrapers / crawlers (suspicious)
    "python-requests":   ("scraper",  "Python requests"),
    "go-http-client":    ("scraper",  "Go HTTP client"),
    "curl/":             ("scraper",  "cURL"),
    "wget/":             ("scraper",  "Wget"),
    "libwww-perl":       ("scraper",  "libwww-perl"),
    "scrapy":            ("scraper",  "Scrapy"),
    "mechanize":         ("scraper",  "Mechanize"),
    "httpx":             ("scraper",  "HTTPX"),
    "java/":             ("scraper",  "Java HTTP"),
    "okhttp":            ("scraper",  "OkHttp"),
    "axios":             ("scraper",  "Axios"),
    "got/":              ("scraper",  "Node got"),
    "node-fetch":        ("scraper",  "node-fetch"),

    # Security scanners / attackers
    "nikto":             ("scanner",  "Nikto"),
    "masscan":           ("scanner",  "Masscan"),
    "nmap":              ("scanner",  "Nmap"),
    "zgrab":             ("scanner",  "ZGrab"),
    "sqlmap":            ("scanner",  "SQLMap"),
    "acunetix":          ("scanner",  "Acunetix"),
    "nessus":            ("scanner",  "Nessus"),
    "openvas":           ("scanner",  "OpenVAS"),
    "qualys":            ("scanner",  "Qualys"),
    "burpsuite":         ("scanner",  "Burp Suite"),
    "nuclei":            ("scanner",  "Nuclei"),
    "dirbuster":         ("scanner",  "DirBuster"),
    "gobuster":          ("scanner",  "GoBuster"),
    "wfuzz":             ("scanner",  "WFuzz"),
    "hydra":             ("scanner",  "Hydra"),
    "w3af":              ("scanner",  "w3af"),
    "appscan":           ("scanner",  "IBM AppScan"),
    "webinspect":        ("scanner",  "HP WebInspect"),
    "netsparker":        ("scanner",  "Netsparker"),
    "stretchoid":        ("scanner",  "Stretchoid"),
    "censys":            ("scanner",  "Censys"),
    "shodan":            ("scanner",  "Shodan"),
    "zoomeye":           ("scanner",  "ZoomEye"),
    "binaryedge":        ("scanner",  "BinaryEdge"),
}

# Suspicious URL patterns — things that should never hit a real site
THREAT_URL_PATTERNS = [
    (re.compile(r'\.php\?.*=http[s]?://', re.I),          "RFI attempt"),
    (re.compile(r'\.\./',                 re.I),           "Path traversal"),
    (re.compile(r'(union.*select|select.*from|insert.*into|drop.*table)', re.I), "SQLi probe"),
    (re.compile(r'(<script|javascript:|onerror=|onload=)', re.I), "XSS probe"),
    (re.compile(r'(wp-login\.php|xmlrpc\.php)',            re.I), "WordPress bruteforce target"),
    (re.compile(r'/admin|/administrator|/phpmyadmin|/pma', re.I), "Admin panel probe"),
    (re.compile(r'\.(env|git|svn|htpasswd|htaccess|bak|old|sql|tar|zip|gz)$', re.I), "Sensitive file probe"),
    (re.compile(r'/(etc/passwd|proc/self|win\.ini)',       re.I), "LFI attempt"),
    (re.compile(r'eval\(|base64_decode\(',                 re.I), "PHP injection probe"),
    (re.compile(r'/shell\.|/cmd\.|/c99|/r57|/webshell',   re.I), "Webshell probe"),
    (re.compile(r'(jndi:|ldap://|rmi://)',                 re.I), "Log4Shell probe"),
    (re.compile(r'/(actuator|metrics|health|env|beans|dump)/?$', re.I), "Spring/metrics probe"),
    (re.compile(r'/.well-known/(?!acme)',                  re.I), "Well-known probe"),
    (re.compile(r'/cgi-bin/',                              re.I), "CGI probe"),
    (re.compile(r'(config\.json|config\.yml|\.DS_Store)',  re.I), "Config file probe"),
]

# Private/reserved IP ranges
PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]

def is_private(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in net for net in PRIVATE_RANGES)
    except ValueError:
        return False

def classify_ua(ua):
    ua_lower = ua.lower()
    for sig, (cat, name) in BOT_SIGNATURES.items():
        if sig in ua_lower:
            return cat, name
    if ua in ("-", "", "–"):
        return "empty", "Empty UA"
    return "human", None

def classify_threat(url):
    for pattern, label in THREAT_URL_PATTERNS:
        if pattern.search(url):
            return label
    return None

# ─── Data structures ──────────────────────────────────────────────────────────
class Stats:
    def __init__(self):
        self.total           = 0
        self.total_bytes     = 0
        self.parse_errors    = 0
        self.ip_counts       = collections.Counter()
        self.ip_bytes        = collections.Counter()
        self.ip_status       = collections.defaultdict(collections.Counter)
        self.ip_ua           = collections.defaultdict(set)
        self.url_counts      = collections.Counter()
        self.url_status      = collections.defaultdict(collections.Counter)
        self.status_counts   = collections.Counter()
        self.method_counts   = collections.Counter()
        self.ua_counts       = collections.Counter()
        self.referrer_counts = collections.Counter()
        self.bot_counts      = collections.Counter()   # display_name → count
        self.bot_cat         = {}                       # display_name → category
        self.hour_counts     = collections.Counter()   # hour (0-23) → count
        self.day_counts      = collections.Counter()   # "YYYY-MM-DD" → count
        self.threat_counts   = collections.Counter()   # threat label → count
        self.threat_ips      = collections.defaultdict(set)
        self.threat_urls     = collections.Counter()   # url → count (threats only)
        self.ip_threat_count = collections.Counter()
        self.protocol_counts = collections.Counter()
        self.ext_counts      = collections.Counter()   # file extension → count
        self.not_found_urls  = collections.Counter()   # 404 URLs
        self.error_urls      = collections.Counter()   # 5xx URLs
        self.first_ts        = None
        self.last_ts         = None

stats = Stats()

# ─── Log line parser ──────────────────────────────────────────────────────────
SINCE_DT = None
if args.since > 0:
    SINCE_DT = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=args.since)

def parse_line(line):
    line = line.strip()
    if not line:
        return
    m = LOG_RE.match(line)
    if not m:
        stats.parse_errors += 1
        return

    ip        = m.group("ip")
    time_str  = m.group("time")
    request   = m.group("request")
    status    = int(m.group("status"))
    raw_bytes = m.group("bytes")
    referrer  = m.group("referrer")
    ua        = m.group("ua")
    forwarded = m.group("forwarded") or ""

    # Use X-Forwarded-For real IP if present and not spoofed-looking
    if forwarded and "," in forwarded:
        real_ip = forwarded.split(",")[0].strip()
        if real_ip:
            ip = real_ip

    # Timestamp
    try:
        dt = datetime.datetime.strptime(time_str, TIME_FMT)
        if SINCE_DT and dt < SINCE_DT:
            return
        if stats.first_ts is None or dt < stats.first_ts:
            stats.first_ts = dt
        if stats.last_ts is None or dt > stats.last_ts:
            stats.last_ts = dt
        stats.hour_counts[dt.hour] += 1
        stats.day_counts[dt.strftime("%Y-%m-%d")] += 1
    except ValueError:
        pass

    # Bytes
    nbytes = int(raw_bytes) if raw_bytes.isdigit() else 0

    # Request parts
    parts = request.split(" ")
    method   = parts[0] if len(parts) >= 1 else "-"
    url      = parts[1] if len(parts) >= 2 else "-"
    protocol = parts[2] if len(parts) >= 3 else "-"

    # Clean URL — strip query string for grouping
    url_path = url.split("?")[0]
    try:
        url_path = unquote(url_path)
    except Exception:
        pass

    # File extension
    ext = Path(url_path).suffix.lower()
    if ext:
        stats.ext_counts[ext] += 1

    stats.total += 1
    stats.total_bytes += nbytes
    stats.ip_counts[ip] += 1
    stats.ip_bytes[ip] += nbytes
    stats.ip_status[ip][status] += 1
    stats.ip_ua[ip].add(ua[:120])
    stats.url_counts[url_path] += 1
    stats.url_status[url_path][status] += 1
    stats.status_counts[status] += 1
    stats.method_counts[method] += 1
    stats.protocol_counts[protocol] += 1

    if referrer and referrer != "-":
        stats.referrer_counts[referrer] += 1

    # User-agent classification
    cat, name = classify_ua(ua)
    if cat != "human":
        display = name or ua[:60]
        stats.bot_counts[display] += 1
        stats.bot_cat[display] = cat
    stats.ua_counts[ua[:120]] += 1

    # Status grouping
    if status == 404:
        stats.not_found_urls[url_path] += 1
    if status >= 500:
        stats.error_urls[url_path] += 1

    # Threat detection
    threat = classify_threat(url)
    if threat:
        stats.threat_counts[threat] += 1
        stats.threat_ips[threat].add(ip)
        stats.threat_urls[url_path] += 1
        stats.ip_threat_count[ip] += 1

# ─── Input: files / stdin / tail ─────────────────────────────────────────────
def read_files():
    files = sorted(glob.glob(args.logs))
    if not files:
        print(f"WARNING: no files matched {args.logs}", file=sys.stderr)
        return
    for fpath in files:
        print(f"  Reading {fpath}…", file=sys.stderr)
        try:
            opener = gzip.open if fpath.endswith(".gz") else open
            with opener(fpath, "rt", encoding="utf-8", errors="replace") as f:
                for line in f:
                    parse_line(line)
        except Exception as e:
            print(f"  ERROR reading {fpath}: {e}", file=sys.stderr)

def read_stdin():
    print("Reading from stdin… (Ctrl+C to stop and generate report)", file=sys.stderr)
    try:
        for line in sys.stdin:
            parse_line(line)
    except KeyboardInterrupt:
        pass

def tail_mode():
    files = sorted(glob.glob(args.logs))
    if not files:
        print(f"ERROR: no files matched {args.logs}", file=sys.stderr)
        sys.exit(1)
    cmd = ["tail", "-F", "--quiet"] + files
    print(f"Tailing {len(files)} file(s) for {args.duration}s…", file=sys.stderr)
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    def stopper():
        time.sleep(args.duration)
        proc.terminate()
    t = threading.Thread(target=stopper, daemon=True)
    t.start()
    try:
        for line in proc.stdout:
            parse_line(line)
    except Exception:
        pass
    proc.wait()

# ─── Collect data ─────────────────────────────────────────────────────────────
print("Collecting log data…", file=sys.stderr)
if args.stdin:
    read_stdin()
elif args.tail:
    tail_mode()
else:
    read_files()

print(f"Parsed {stats.total:,} requests ({stats.parse_errors:,} errors)", file=sys.stderr)

# ─── Helpers for HTML ─────────────────────────────────────────────────────────
def e(s):
    return html.escape(str(s))

def fmt_bytes(n):
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"

def pct(n, total):
    if total == 0:
        return "0.0"
    return f"{100*n/total:.1f}"

def bar(n, max_n, width=80):
    if max_n == 0:
        return ""
    frac = n / max_n
    filled = int(frac * width)
    return "█" * filled + "░" * (width - filled)

def status_class(code):
    if code < 300:   return "s2xx"
    if code < 400:   return "s3xx"
    if code == 404:  return "s404"
    if code < 500:   return "s4xx"
    return "s5xx"

def status_summary(counter):
    parts = []
    for code, cnt in sorted(counter.items()):
        parts.append(f'<span class="{status_class(code)}">{code}×{cnt}</span>')
    return " ".join(parts)

def threat_score(ip):
    """0-100 threat score for an IP based on multiple signals."""
    score = 0
    tc = stats.ip_threat_count.get(ip, 0)
    score += min(tc * 10, 50)
    statuses = stats.ip_status.get(ip, {})
    s4xx = sum(v for k, v in statuses.items() if 400 <= k < 500)
    s5xx = sum(v for k, v in statuses.items() if k >= 500)
    total = stats.ip_counts.get(ip, 1)
    if total > 0:
        score += min(int(s4xx / total * 40), 30)
        score += min(s5xx * 5, 20)
    return min(score, 100)

def threat_badge(score):
    if score >= 70:
        return f'<span class="tbadge t-high">{score}</span>'
    if score >= 30:
        return f'<span class="tbadge t-med">{score}</span>'
    if score > 0:
        return f'<span class="tbadge t-low">{score}</span>'
    return f'<span class="tbadge t-none">{score}</span>'

def bot_cat_badge(cat):
    colors = {
        "search":  ("badge-search",  "Search"),
        "seo":     ("badge-seo",     "SEO"),
        "social":  ("badge-social",  "Social"),
        "monitor": ("badge-monitor", "Monitor"),
        "scraper": ("badge-scraper", "Scraper"),
        "scanner": ("badge-scanner", "Scanner"),
        "empty":   ("badge-empty",   "Empty UA"),
    }
    cls, label = colors.get(cat, ("badge-unknown", cat))
    return f'<span class="badge {cls}">{label}</span>'

# ─── Build HTML ───────────────────────────────────────────────────────────────
generated = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
span_str = ""
if stats.first_ts and stats.last_ts:
    span_str = f"{stats.first_ts.strftime('%Y-%m-%d %H:%M')} → {stats.last_ts.strftime('%Y-%m-%d %H:%M')}"

# Heatmap data (24 hours)
max_hour = max(stats.hour_counts.values(), default=1)
heatmap_cells = ""
for h in range(24):
    cnt = stats.hour_counts.get(h, 0)
    intensity = cnt / max_hour if max_hour > 0 else 0
    # Map intensity to colour opacity
    heatmap_cells += (
        f'<div class="hm-cell" style="--i:{intensity:.3f}" title="{h:02d}:00 — {cnt:,} reqs">'
        f'<span class="hm-label">{h:02d}</span>'
        f'</div>'
    )

# Status code summary bar data
status_total = sum(stats.status_counts.values())
status_groups = {"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0}
for code, cnt in stats.status_counts.items():
    if 200 <= code < 300:   status_groups["2xx"] += cnt
    elif 300 <= code < 400: status_groups["3xx"] += cnt
    elif 400 <= code < 500: status_groups["4xx"] += cnt
    elif code >= 500:       status_groups["5xx"] += cnt

# Threat summary
total_threats = sum(stats.threat_counts.values())
threat_ips_count = len(set().union(*stats.threat_ips.values()) if stats.threat_ips else set())

# Top IPs table
top_ips = stats.ip_counts.most_common(TOP_N)
max_ip_reqs = top_ips[0][1] if top_ips else 1

# Top URLs
top_urls = stats.url_counts.most_common(TOP_N)
max_url_reqs = top_urls[0][1] if top_urls else 1

# Top bots
top_bots = stats.bot_counts.most_common(TOP_N)
max_bot_reqs = top_bots[0][1] if top_bots else 1

# Top UAs (human-only)
top_uas = [(ua, cnt) for ua, cnt in stats.ua_counts.most_common(TOP_N * 3)
           if classify_ua(ua)[0] == "human"][:TOP_N]

# Top referrers
top_refs = stats.referrer_counts.most_common(TOP_N)

# Top 404s
top_404 = stats.not_found_urls.most_common(TOP_N)

# Top threat URLs
top_threat_urls = stats.threat_urls.most_common(TOP_N)

# Recommendations
recommendations = []
scanner_ips = set()
for cat in ("scanner", "scraper"):
    for name, cnt in stats.bot_counts.items():
        if stats.bot_cat.get(name) == cat and cnt > 10:
            recommendations.append({
                "severity": "high",
                "title": f"Block {name} ({cnt:,} requests)",
                "detail": f'Add <code>if ($http_user_agent ~* "{name}") {{ return 403; }}</code> to nginx, or use a Cloudflare WAF rule.',
            })

if stats.threat_counts.get("WordPress bruteforce target", 0) > 20:
    recommendations.append({
        "severity": "high",
        "title": "wp-login.php / xmlrpc.php under attack",
        "detail": "Block xmlrpc.php entirely. Rate-limit wp-login.php with fail2ban or Cloudflare. Consider moving wp-admin to a custom URL.",
    })

if stats.threat_counts.get("SQLi probe", 0) > 0:
    recommendations.append({
        "severity": "high",
        "title": f'SQLi probes detected ({stats.threat_counts["SQLi probe"]:,})',
        "detail": "Enable Cloudflare WAF OWASP ruleset or ModSecurity. Review application input sanitisation.",
    })

if stats.threat_counts.get("Path traversal", 0) > 0:
    recommendations.append({
        "severity": "high",
        "title": f'Path traversal attempts ({stats.threat_counts["Path traversal"]:,})',
        "detail": "Ensure nginx does not serve files outside document root. Review alias directives.",
    })

top_threat_ip_list = sorted(stats.ip_threat_count.items(), key=lambda x: -x[1])[:5]
if top_threat_ip_list:
    ips_str = ", ".join(ip for ip, _ in top_threat_ip_list)
    recommendations.append({
        "severity": "medium",
        "title": f"High-threat IPs to block: {ips_str}",
        "detail": f'Add to nginx: <code>deny {top_threat_ip_list[0][0]};</code> in the geo block, or add to Cloudflare IP rules.',
    })

if stats.status_counts.get(404, 0) / max(stats.total, 1) > 0.3:
    recommendations.append({
        "severity": "medium",
        "title": f'High 404 rate ({pct(stats.status_counts.get(404,0), stats.total)}%)',
        "detail": "Review top 404 URLs — many may be scanner probes. Add rate limiting on 404 responses.",
    })

high_vol_ips = [(ip, cnt) for ip, cnt in top_ips if cnt > stats.total * 0.05]
for ip, cnt in high_vol_ips[:3]:
    recommendations.append({
        "severity": "medium",
        "title": f"High-volume IP: {ip} ({cnt:,} reqs, {pct(cnt, stats.total)}% of traffic)",
        "detail": "Investigate whether this is a legitimate user, monitor, or scraper. Consider rate limiting.",
    })

if not recommendations:
    recommendations.append({
        "severity": "ok",
        "title": "No major threats detected",
        "detail": "Traffic looks relatively clean. Keep monitoring regularly.",
    })

# ── CSS ───────────────────────────────────────────────────────────────────────
CSS = """
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;700&display=swap');

:root {
  --bg:       #080c14;
  --surface:  #0d1220;
  --surface2: #111827;
  --surface3: #1a2235;
  --border:   #1e2d45;
  --border2:  #253552;
  --cyan:     #00d4ff;
  --cyan-dim: rgba(0,212,255,0.15);
  --red:      #ff4757;
  --red-dim:  rgba(255,71,87,0.15);
  --green:    #2ed573;
  --green-dim:rgba(46,213,115,0.12);
  --yellow:   #ffa502;
  --yellow-dim:rgba(255,165,2,0.12);
  --purple:   #a29bfe;
  --text:     #cdd6f4;
  --muted:    #6272a4;
  --mono:     'JetBrains Mono', 'Fira Code', monospace;
  --sans:     'Inter', system-ui, sans-serif;
}
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
html { scroll-behavior: smooth; }
body {
  font-family: var(--sans);
  background: var(--bg);
  color: var(--text);
  font-size: 13px;
  line-height: 1.6;
  min-height: 100vh;
}

/* ── layout ── */
.topbar {
  background: var(--surface);
  border-bottom: 1px solid var(--border);
  padding: 0 32px;
  display: flex;
  align-items: center;
  gap: 24px;
  height: 52px;
  position: sticky; top: 0; z-index: 100;
}
.topbar-brand {
  font-family: var(--mono);
  font-size: 13px;
  font-weight: 700;
  color: var(--cyan);
  letter-spacing: 1px;
  white-space: nowrap;
}
.topbar-meta {
  font-family: var(--mono);
  font-size: 11px;
  color: var(--muted);
  flex: 1;
}
.topbar-nav {
  display: flex; gap: 4px;
}
.topbar-nav a {
  color: var(--muted);
  text-decoration: none;
  font-size: 11px;
  padding: 4px 10px;
  border-radius: 4px;
  border: 1px solid transparent;
  transition: all .15s;
}
.topbar-nav a:hover {
  color: var(--cyan);
  border-color: var(--border2);
  background: var(--cyan-dim);
}

main { max-width: 1400px; margin: 0 auto; padding: 28px 32px 60px; }

/* ── heatmap ── */
.heatmap-wrap {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 20px 24px;
  margin-bottom: 28px;
}
.heatmap-title {
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 1px;
  color: var(--muted);
  margin-bottom: 14px;
}
.heatmap {
  display: grid;
  grid-template-columns: repeat(24, 1fr);
  gap: 4px;
  height: 52px;
}
.hm-cell {
  background: rgba(0,212,255, calc(0.08 + var(--i) * 0.85));
  border-radius: 3px;
  display: flex;
  align-items: flex-end;
  justify-content: center;
  padding-bottom: 4px;
  cursor: default;
  transition: transform .1s;
  position: relative;
}
.hm-cell:hover { transform: scaleY(1.05); }
.hm-label {
  font-family: var(--mono);
  font-size: 9px;
  color: rgba(255,255,255,.5);
  line-height: 1;
}

/* ── stat cards ── */
.cards {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: 12px;
  margin-bottom: 28px;
}
.card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 16px 18px;
  position: relative;
  overflow: hidden;
}
.card::before {
  content: '';
  position: absolute;
  top: 0; left: 0; right: 0;
  height: 2px;
  background: var(--card-accent, var(--cyan));
}
.card-num {
  font-family: var(--mono);
  font-size: 26px;
  font-weight: 700;
  line-height: 1;
  margin-bottom: 4px;
  color: var(--card-accent, var(--cyan));
}
.card-label {
  font-size: 10px;
  text-transform: uppercase;
  letter-spacing: .8px;
  color: var(--muted);
}

/* ── status bar ── */
.status-bar-wrap {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 18px 24px;
  margin-bottom: 28px;
}
.status-bar {
  display: flex;
  height: 24px;
  border-radius: 4px;
  overflow: hidden;
  margin: 12px 0;
}
.sb-seg { transition: opacity .2s; cursor: default; }
.sb-seg:hover { opacity: .8; }
.sb-2xx { background: var(--green); }
.sb-3xx { background: var(--cyan); }
.sb-4xx { background: var(--yellow); }
.sb-5xx { background: var(--red); }
.sb-legend {
  display: flex; gap: 20px; flex-wrap: wrap; margin-top: 8px;
}
.sb-item {
  display: flex; align-items: center; gap: 6px;
  font-family: var(--mono); font-size: 11px;
}
.sb-dot { width: 8px; height: 8px; border-radius: 2px; }

/* ── section ── */
.section {
  margin-bottom: 32px;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 10px;
  overflow: hidden;
}
.section-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 14px 20px;
  background: var(--surface2);
  border-bottom: 1px solid var(--border);
}
.section-title {
  font-size: 11px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 1px;
  color: var(--cyan);
  display: flex;
  align-items: center;
  gap: 8px;
}
.section-count {
  font-family: var(--mono);
  font-size: 11px;
  color: var(--muted);
  background: var(--surface3);
  border: 1px solid var(--border);
  padding: 2px 8px;
  border-radius: 99px;
}

/* ── tables ── */
table { width: 100%; border-collapse: collapse; }
thead tr { background: var(--surface2); }
th {
  padding: 9px 14px;
  text-align: left;
  font-size: 10px;
  text-transform: uppercase;
  letter-spacing: .7px;
  color: var(--muted);
  font-weight: 600;
  white-space: nowrap;
}
td {
  padding: 8px 14px;
  border-bottom: 1px solid var(--border);
  vertical-align: middle;
  max-width: 500px;
  word-break: break-all;
}
tr:last-child td { border-bottom: none; }
tr:hover td { background: var(--surface3); }

/* ── bar spark ── */
.bar-wrap {
  display: flex;
  align-items: center;
  gap: 8px;
  min-width: 160px;
}
.bar-fill {
  height: 6px;
  border-radius: 3px;
  background: var(--bar-color, var(--cyan));
  min-width: 2px;
  transition: width .3s;
}
.bar-pct {
  font-family: var(--mono);
  font-size: 10px;
  color: var(--muted);
  white-space: nowrap;
}

/* ── mono cells ── */
.mono { font-family: var(--mono); font-size: 12px; }
.muted { color: var(--muted); }
.num  { font-family: var(--mono); font-size: 12px; text-align: right; white-space: nowrap; }

/* ── status spans ── */
.s2xx { color: var(--green); font-family: var(--mono); font-size: 11px; }
.s3xx { color: var(--cyan);  font-family: var(--mono); font-size: 11px; }
.s4xx { color: var(--yellow);font-family: var(--mono); font-size: 11px; }
.s404 { color: var(--yellow);font-family: var(--mono); font-size: 11px; font-weight:700; }
.s5xx { color: var(--red);   font-family: var(--mono); font-size: 11px; }

/* ── badges ── */
.badge {
  display: inline-block;
  padding: 2px 7px;
  border-radius: 99px;
  font-size: 10px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: .4px;
  white-space: nowrap;
}
.badge-search  { background: rgba(46,213,115,.15); color: var(--green);  border: 1px solid var(--green); }
.badge-seo     { background: rgba(162,155,254,.15);color: var(--purple); border: 1px solid var(--purple); }
.badge-social  { background: rgba(0,212,255,.12);  color: var(--cyan);   border: 1px solid var(--cyan); }
.badge-monitor { background: rgba(255,165,2,.12);  color: var(--yellow); border: 1px solid var(--yellow); }
.badge-scraper { background: rgba(255,165,2,.15);  color: var(--yellow); border: 1px solid var(--yellow); }
.badge-scanner { background: rgba(255,71,87,.15);  color: var(--red);    border: 1px solid var(--red); }
.badge-empty   { background: rgba(98,114,164,.15); color: var(--muted);  border: 1px solid var(--muted); }
.badge-unknown { background: rgba(98,114,164,.1);  color: var(--muted);  border: 1px solid var(--border2); }

/* ── threat badge ── */
.tbadge {
  display: inline-block;
  font-family: var(--mono);
  font-size: 11px;
  font-weight: 700;
  padding: 2px 7px;
  border-radius: 4px;
  min-width: 32px;
  text-align: center;
}
.t-high { background: var(--red-dim);    color: var(--red);    border: 1px solid var(--red); }
.t-med  { background: var(--yellow-dim); color: var(--yellow); border: 1px solid var(--yellow); }
.t-low  { background: var(--cyan-dim);   color: var(--cyan);   border: 1px solid var(--cyan); }
.t-none { background: var(--green-dim);  color: var(--green);  border: 1px solid var(--green); }

/* ── recommendations ── */
.rec-list { padding: 16px 20px; display: flex; flex-direction: column; gap: 12px; }
.rec {
  display: grid;
  grid-template-columns: 8px 1fr;
  gap: 12px;
  align-items: start;
}
.rec-bar {
  width: 3px;
  align-self: stretch;
  border-radius: 3px;
  margin-top: 2px;
}
.rec-high .rec-bar  { background: var(--red); }
.rec-medium .rec-bar { background: var(--yellow); }
.rec-ok .rec-bar    { background: var(--green); }
.rec-title {
  font-weight: 600;
  font-size: 13px;
  margin-bottom: 3px;
}
.rec-high .rec-title  { color: var(--red); }
.rec-medium .rec-title { color: var(--yellow); }
.rec-ok .rec-title    { color: var(--green); }
.rec-detail { color: var(--muted); font-size: 12px; line-height: 1.5; }
.rec-detail code {
  font-family: var(--mono);
  background: var(--surface3);
  border: 1px solid var(--border2);
  padding: 1px 5px;
  border-radius: 3px;
  font-size: 11px;
  color: var(--cyan);
}

/* ── threat grid ── */
.threat-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
  gap: 12px;
  padding: 16px 20px;
}
.threat-item {
  background: var(--surface3);
  border: 1px solid var(--border2);
  border-radius: 8px;
  padding: 14px 16px;
}
.threat-name {
  font-size: 12px;
  font-weight: 600;
  color: var(--red);
  margin-bottom: 4px;
}
.threat-count {
  font-family: var(--mono);
  font-size: 20px;
  font-weight: 700;
  color: var(--text);
}
.threat-ips {
  font-size: 10px;
  color: var(--muted);
  margin-top: 4px;
  font-family: var(--mono);
}

/* ── footer ── */
footer {
  text-align: center;
  padding: 24px;
  color: var(--muted);
  font-size: 11px;
  border-top: 1px solid var(--border);
  font-family: var(--mono);
}
"""

# ── HTML sections helper ──────────────────────────────────────────────────────
def section_open(id_, icon, title, count=None):
    count_html = f'<span class="section-count">{count}</span>' if count is not None else ""
    return (
        f'<div class="section" id="{id_}">'
        f'<div class="section-header">'
        f'<div class="section-title">{icon} {e(title)}</div>'
        f'{count_html}'
        f'</div>'
    )

def bar_cell(n, max_n, color="var(--cyan)"):
    pct_val = n / max_n * 100 if max_n > 0 else 0
    width   = max(int(pct_val * 1.2), 2)
    return (
        f'<div class="bar-wrap">'
        f'<div class="bar-fill" style="width:{width}px;--bar-color:{color}"></div>'
        f'<span class="bar-pct">{pct_val:.1f}%</span>'
        f'</div>'
    )

# ─── Render ───────────────────────────────────────────────────────────────────
out = []
W = out.append

W(f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>nginx traffic — {e(generated)}</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>{CSS}</style>
</head>
<body>

<div class="topbar">
  <div class="topbar-brand">◈ NGINX LOG ANALYSER</div>
  <div class="topbar-meta">{e(span_str)} &nbsp;·&nbsp; {stats.total:,} requests &nbsp;·&nbsp; generated {e(generated)}</div>
  <nav class="topbar-nav">
    <a href="#ips">IPs</a>
    <a href="#urls">URLs</a>
    <a href="#bots">Bots</a>
    <a href="#uas">UAs</a>
    <a href="#threats">Threats</a>
    <a href="#404s">404s</a>
    <a href="#refs">Referrers</a>
    <a href="#recs">Actions</a>
  </nav>
</div>

<main>
""")

# ── Heatmap ──────────────────────────────────────────────────────────────────
W(f"""
<div class="heatmap-wrap">
  <div class="heatmap-title">Requests by hour of day</div>
  <div class="heatmap">{heatmap_cells}</div>
</div>
""")

# ── Summary cards ─────────────────────────────────────────────────────────────
bot_total = sum(stats.bot_counts.values())
scanner_total = sum(cnt for name, cnt in stats.bot_counts.items()
                    if stats.bot_cat.get(name) in ("scanner", "scraper"))

W('<div class="cards">')
cards = [
    (f"{stats.total:,}",         "Total Requests",   "var(--cyan)"),
    (fmt_bytes(stats.total_bytes),"Total Bandwidth",  "var(--purple)"),
    (f"{len(stats.ip_counts):,}", "Unique IPs",        "var(--cyan)"),
    (f"{len(stats.url_counts):,}","Unique URLs",       "var(--cyan)"),
    (f"{bot_total:,}",            "Bot Requests",      "var(--yellow)"),
    (f"{scanner_total:,}",        "Scanner/Scraper",   "var(--red)"),
    (f"{total_threats:,}",        "Threat Signals",    "var(--red)"),
    (f"{status_groups['4xx']:,}", "4xx Errors",        "var(--yellow)"),
    (f"{status_groups['5xx']:,}", "5xx Errors",        "var(--red)"),
]
for num, label, accent in cards:
    W(f'<div class="card" style="--card-accent:{accent}">'
      f'<div class="card-num">{e(num)}</div>'
      f'<div class="card-label">{e(label)}</div>'
      f'</div>')
W('</div>')

# ── Status bar ────────────────────────────────────────────────────────────────
W('<div class="status-bar-wrap">')
W('<div class="heatmap-title">HTTP Status Distribution</div>')
W('<div class="status-bar">')
for grp, cls, col in [("2xx","sb-2xx",None),("3xx","sb-3xx",None),("4xx","sb-4xx",None),("5xx","sb-5xx",None)]:
    cnt = status_groups[grp]
    if cnt > 0:
        pct_w = cnt / max(status_total, 1) * 100
        W(f'<div class="sb-seg {cls}" style="flex:{pct_w}" title="{grp}: {cnt:,} ({pct_w:.1f}%)"></div>')
W('</div>')
W('<div class="sb-legend">')
for grp, cls, color in [("2xx","sb-2xx","var(--green)"),("3xx","sb-3xx","var(--cyan)"),("4xx","sb-4xx","var(--yellow)"),("5xx","sb-5xx","var(--red)")]:
    cnt = status_groups[grp]
    W(f'<div class="sb-item"><div class="sb-dot" style="background:{color}"></div>'
      f'<span>{grp}: {cnt:,} ({pct(cnt, status_total)}%)</span></div>')
W('</div>')
# Breakdown of each status code
W('<div style="margin-top:12px;display:flex;flex-wrap:wrap;gap:8px;">')
for code, cnt in sorted(stats.status_counts.items()):
    W(f'<span class="{status_class(code)}" style="background:var(--surface3);border:1px solid var(--border2);padding:3px 10px;border-radius:4px;">'
      f'{code}: {cnt:,}</span>')
W('</div>')
W('</div>')

# ── Top IPs ───────────────────────────────────────────────────────────────────
W(section_open("ips", "◎", f"Top {TOP_N} IP Addresses", f"{len(stats.ip_counts):,} unique"))
W('<table><thead><tr>'
  '<th>#</th><th>IP Address</th><th>Requests</th><th>Traffic</th>'
  '<th>Threat</th><th>Status codes</th><th>User-Agent (sample)</th>'
  '</tr></thead><tbody>')
for rank, (ip, cnt) in enumerate(top_ips, 1):
    ts  = threat_score(ip)
    priv = " 🏠" if is_private(ip) else ""
    ua_sample = next(iter(stats.ip_ua.get(ip, {"—"})))[:80]
    W(f'<tr>'
      f'<td class="num muted">{rank}</td>'
      f'<td class="mono">{e(ip)}{priv}</td>'
      f'<td>{bar_cell(cnt, max_ip_reqs)}</td>'
      f'<td class="num">{fmt_bytes(stats.ip_bytes.get(ip, 0))}</td>'
      f'<td>{threat_badge(ts)}</td>'
      f'<td>{status_summary(stats.ip_status.get(ip, {}))}</td>'
      f'<td class="muted" style="font-size:11px;max-width:300px">{e(ua_sample)}</td>'
      f'</tr>')
W('</tbody></table></div>')

# ── Top URLs ──────────────────────────────────────────────────────────────────
W(section_open("urls", "◈", f"Top {TOP_N} URLs", f"{len(stats.url_counts):,} unique"))
W('<table><thead><tr>'
  '<th>#</th><th>URL</th><th>Requests</th><th>Status codes</th>'
  '</tr></thead><tbody>')
for rank, (url, cnt) in enumerate(top_urls, 1):
    threat = classify_threat(url)
    threat_html = f' &nbsp;<span class="badge badge-scanner">{e(threat)}</span>' if threat else ""
    W(f'<tr>'
      f'<td class="num muted">{rank}</td>'
      f'<td class="mono">{e(url)}{threat_html}</td>'
      f'<td>{bar_cell(cnt, max_url_reqs)}</td>'
      f'<td>{status_summary(stats.url_status.get(url, {}))}</td>'
      f'</tr>')
W('</tbody></table></div>')

# ── Top Bots ──────────────────────────────────────────────────────────────────
W(section_open("bots", "⬡", f"Top {TOP_N} Bots & Automated Clients", f"{len(stats.bot_counts):,} distinct"))
W('<table><thead><tr>'
  '<th>#</th><th>Bot / Client</th><th>Category</th><th>Requests</th>'
  '</tr></thead><tbody>')
for rank, (name, cnt) in enumerate(top_bots, 1):
    cat = stats.bot_cat.get(name, "unknown")
    bar_color = {
        "scanner": "var(--red)",
        "scraper": "var(--yellow)",
        "seo":     "var(--purple)",
        "search":  "var(--green)",
        "monitor": "var(--cyan)",
    }.get(cat, "var(--muted)")
    W(f'<tr>'
      f'<td class="num muted">{rank}</td>'
      f'<td class="mono">{e(name)}</td>'
      f'<td>{bot_cat_badge(cat)}</td>'
      f'<td>{bar_cell(cnt, max_bot_reqs, bar_color)}</td>'
      f'</tr>')
W('</tbody></table></div>')

# ── Top User-Agents (human) ───────────────────────────────────────────────────
W(section_open("uas", "◇", f"Top {TOP_N} Human User-Agents"))
max_ua = top_uas[0][1] if top_uas else 1
W('<table><thead><tr><th>#</th><th>User-Agent</th><th>Requests</th></tr></thead><tbody>')
for rank, (ua, cnt) in enumerate(top_uas, 1):
    W(f'<tr>'
      f'<td class="num muted">{rank}</td>'
      f'<td class="mono" style="font-size:11px">{e(ua)}</td>'
      f'<td>{bar_cell(cnt, max_ua)}</td>'
      f'</tr>')
W('</tbody></table></div>')

# ── Threat Signals ────────────────────────────────────────────────────────────
W(section_open("threats", "⚠", "Threat Signals Detected", f"{total_threats:,} total"))
if stats.threat_counts:
    W('<div class="threat-grid">')
    for threat_name, cnt in sorted(stats.threat_counts.items(), key=lambda x: -x[1]):
        ip_count = len(stats.threat_ips.get(threat_name, set()))
        W(f'<div class="threat-item">'
          f'<div class="threat-name">{e(threat_name)}</div>'
          f'<div class="threat-count">{cnt:,}</div>'
          f'<div class="threat-ips">{ip_count} unique IP(s)</div>'
          f'</div>')
    W('</div>')

    # Top threat URLs
    if top_threat_urls:
        W('<div style="padding:0 20px 16px">')
        W('<div style="font-size:10px;text-transform:uppercase;letter-spacing:.8px;color:var(--muted);margin-bottom:8px">Top Threat URLs</div>')
        W('<table><thead><tr><th>URL</th><th>Hits</th><th>Pattern matched</th></tr></thead><tbody>')
        for url, cnt in top_threat_urls:
            threat = classify_threat(url) or "—"
            W(f'<tr><td class="mono">{e(url)}</td>'
              f'<td class="num"><span class="s5xx">{cnt:,}</span></td>'
              f'<td><span class="badge badge-scanner">{e(threat)}</span></td></tr>')
        W('</tbody></table></div>')
else:
    W('<div style="padding:20px;color:var(--muted)">No threat signals detected in this log window.</div>')
W('</div>')

# ── Top 404s ──────────────────────────────────────────────────────────────────
W(section_open("404s", "✕", f"Top {TOP_N} Not Found (404) URLs", f"{len(stats.not_found_urls):,} unique"))
if top_404:
    max_404 = top_404[0][1]
    W('<table><thead><tr><th>#</th><th>URL</th><th>Hits</th><th>Likely cause</th></tr></thead><tbody>')
    for rank, (url, cnt) in enumerate(top_404, 1):
        threat = classify_threat(url)
        cause = f'<span class="badge badge-scanner">{e(threat)}</span>' if threat else '<span class="muted">Broken link / missing asset</span>'
        W(f'<tr>'
          f'<td class="num muted">{rank}</td>'
          f'<td class="mono">{e(url)}</td>'
          f'<td>{bar_cell(cnt, max_404, "var(--yellow)")}</td>'
          f'<td>{cause}</td>'
          f'</tr>')
    W('</tbody></table>')
else:
    W('<div style="padding:20px;color:var(--muted)">No 404s in this log window.</div>')
W('</div>')

# ── Top 5xx errors ────────────────────────────────────────────────────────────
if stats.error_urls:
    W(section_open("5xx", "⚡", f"Top Server Errors (5xx)", f"{len(stats.error_urls):,} URLs affected"))
    top_errors = stats.error_urls.most_common(TOP_N)
    max_err = top_errors[0][1]
    W('<table><thead><tr><th>#</th><th>URL</th><th>Hits</th></tr></thead><tbody>')
    for rank, (url, cnt) in enumerate(top_errors, 1):
        W(f'<tr><td class="num muted">{rank}</td>'
          f'<td class="mono">{e(url)}</td>'
          f'<td>{bar_cell(cnt, max_err, "var(--red)")}</td></tr>')
    W('</tbody></table>')
    W('</div>')

# ── Top Referrers ─────────────────────────────────────────────────────────────
W(section_open("refs", "↗", f"Top {TOP_N} Referrers", f"{len(stats.referrer_counts):,} unique"))
if top_refs:
    max_ref = top_refs[0][1]
    W('<table><thead><tr><th>#</th><th>Referrer</th><th>Requests</th></tr></thead><tbody>')
    for rank, (ref, cnt) in enumerate(top_refs, 1):
        W(f'<tr>'
          f'<td class="num muted">{rank}</td>'
          f'<td class="mono" style="font-size:11px"><a href="{e(ref)}" target="_blank" rel="noopener">{e(ref[:120])}</a></td>'
          f'<td>{bar_cell(cnt, max_ref, "var(--purple)")}</td>'
          f'</tr>')
    W('</tbody></table>')
else:
    W('<div style="padding:20px;color:var(--muted)">No referrer data.</div>')
W('</div>')

# ── Methods + Protocols + Extensions ─────────────────────────────────────────
W('<div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px;margin-bottom:32px">')

for sid, icon, title, counter in [
    ("methods",   "⊕", "HTTP Methods",   stats.method_counts),
    ("protocols", "⊞", "Protocols",      stats.protocol_counts),
    ("exts",      "⊟", "File Extensions",stats.ext_counts),
]:
    top = counter.most_common(15)
    max_v = top[0][1] if top else 1
    W(f'<div class="section" style="margin-bottom:0">'
      f'<div class="section-header"><div class="section-title">{icon} {e(title)}</div></div>'
      f'<table><thead><tr><th>Value</th><th>Count</th></tr></thead><tbody>')
    for val, cnt in top:
        W(f'<tr><td class="mono">{e(val)}</td>'
          f'<td>{bar_cell(cnt, max_v, "var(--purple)")}</td></tr>')
    W('</tbody></table></div>')

W('</div>')

# ── Recommendations ───────────────────────────────────────────────────────────
W(section_open("recs", "▸", "Recommendations & Actions"))
W('<div class="rec-list">')
for rec in recommendations:
    sev = rec["severity"]
    W(f'<div class="rec rec-{sev}">'
      f'<div class="rec-bar"></div>'
      f'<div><div class="rec-title">{e(rec["title"])}</div>'
      f'<div class="rec-detail">{rec["detail"]}</div>'
      f'</div></div>')
W('</div></div>')

W(f'</main>')
W(f'<footer>nginx-log-analyzer &nbsp;·&nbsp; {e(generated)} &nbsp;·&nbsp; {stats.total:,} requests analysed</footer>')
W('</body></html>')

# ─── Write output ─────────────────────────────────────────────────────────────
output_path = args.output
os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
with open(output_path, "w", encoding="utf-8") as f:
    f.write("\n".join(out))

print(f"Report written → {output_path}", file=sys.stderr)

if args.open:
    import subprocess
    subprocess.Popen(["xdg-open" if sys.platform != "darwin" else "open", output_path])
