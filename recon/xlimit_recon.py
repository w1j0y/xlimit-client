#!/usr/bin/env python3
"""
xLimit - Automated Bug Bounty Recon & Triage Pipeline
Author: w1j0y

Phases:
    1. Subdomain Enumeration  (subfinder, amass)
    2. Live Host Detection     (httpx w/ tech + headers + response analysis)
    3. Screenshots             (gowitness)
    4. Technology Fingerprint  (whatweb, httpx tech-detect)
    5. JS Source Map Scanning  (integrated secret scanner w/ entropy + dedup)
    6. Port Scanning           (nmap, selective per-host based on triage rules)
    7. Triage & Playbooks      (rules engine -> ready-to-run commands per host)
    8. Reports                 (TXT, JSON, HTML dashboard w/ playbook)

Usage:
    python3 recon.py -d example.com
    python3 recon.py -d example.com --deep --run-nmap
    python3 recon.py --scope scope.csv --bounty-only
    python3 recon.py -d example.com --monitor
"""

import subprocess, json, os, sys, argparse, shutil, datetime, time, csv, re, shlex
import math, hashlib, logging
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from functools import lru_cache
from typing import Optional, List, Dict, Set, Tuple, Sequence, Union, Any
from urllib.parse import urljoin, urlparse
from collections import Counter, defaultdict

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

# ===========================================================================
# CONFIGURATION
# ===========================================================================

BANNER = r"""
+==============================================================+
|    __  __ _     _           _ _                              |
|    \/ /| |   (_)_ __ ___ (_| |_)                            |
|     \  / | |   | | '_ ` _ \| | __|                           |
|     /  \ | |___| | | | | | | | |_                            |
|    /_/\_\|_____|_|_| |_| |_|_|\__|                           |
|                                                              |
|   xLimit Recon                                               |
|   Automated Bug Bounty Recon & Triage Pipeline               |
|   by w1j0y                                                   |
+==============================================================+
"""

BASE_OUTPUT_DIR = Path("./recon_output")
TOOLS_REQUIRED = ["subfinder", "httpx"]
TOOLS_OPTIONAL = [
    "amass", "gowitness", "whatweb", "nmap",
    "feroxbuster", "ffuf", "gobuster", "nuclei",
    "paramspider", "dirsearch", "wpscan",
]
WORDLISTS = {
    "dir_common":    "/usr/share/wordlists/dirb/common.txt",
    "dir_medium":    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    "dir_small":     "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
    "seclists_raft": "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
    "seclists_api":  "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt",
    "fuzz_params":   "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt",
}

CUSTOM_HEADER = ""

def set_custom_header(header_value: str):
    """Set the global custom header from a single 'Header-Name: value' string."""
    global CUSTOM_HEADER

    header_value = (header_value or "").strip()
    if not header_value:
        CUSTOM_HEADER = ""
        return

    if ":" not in header_value:
        raise ValueError("Custom header must be provided as 'Header-Name: value'")

    name, value = header_value.split(":", 1)
    name = name.strip()
    value = value.strip()
    if not name or not value:
        raise ValueError("Custom header must include both a header name and value")

    CUSTOM_HEADER = f"{name}: {value}"

# ===========================================================================
# UTILITIES
# ===========================================================================

class Colors:
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    RED     = "\033[91m"
    CYAN    = "\033[96m"
    MAGENTA = "\033[95m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    END     = "\033[0m"

def log_info(msg):    print(f"{Colors.CYAN}[*]{Colors.END} {msg}")
def log_success(msg): print(f"{Colors.GREEN}[+]{Colors.END} {msg}")
def log_warning(msg): print(f"{Colors.YELLOW}[!]{Colors.END} {msg}")
def log_error(msg):   print(f"{Colors.RED}[-]{Colors.END} {msg}")

def log_phase(msg):
    print(f"\n{Colors.BOLD}{Colors.GREEN}{'='*60}")
    print(f"  {msg}")
    print(f"{'='*60}{Colors.END}\n")

Command = Union[str, Sequence[str]]


@lru_cache(maxsize=None)
def check_tool(name):
    return shutil.which(name) is not None


def _command_repr(cmd: Command) -> str:
    if isinstance(cmd, str):
        return cmd
    return shlex.join(str(part) for part in cmd)


def read_nonempty_lines(path: Path) -> List[str]:
    if not path.exists():
        return []
    return [line.strip() for line in path.read_text().splitlines() if line.strip()]


def read_jsonl(path: Path) -> List[dict]:
    rows = []
    for line in read_nonempty_lines(path):
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def run_command(cmd: Command, timeout=600):
    cmd_text = _command_repr(cmd)
    try:
        r = subprocess.run(
            cmd,
            shell=isinstance(cmd, str),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if r.returncode != 0 and r.stderr:
            log_warning(f"stderr: {r.stderr.strip()[:200]}")
        return [l.strip() for l in r.stdout.strip().split("\n") if l.strip()]
    except subprocess.TimeoutExpired:
        log_warning(f"Timed out ({timeout}s): {cmd_text[:80]}")
        return []
    except Exception as e:
        log_error(f"Command failed: {e}")
        return []

def ensure_output_dir(domain):
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    d = BASE_OUTPUT_DIR / f"{domain}_{ts}"
    d.mkdir(parents=True, exist_ok=True)
    return d

def get_best_wordlist(category="dir_common"):
    fallbacks = {
        "dir_common": ["dir_common", "seclists_raft", "dir_small"],
        "dir_medium": ["dir_medium", "seclists_raft", "dir_common"],
        "api":        ["seclists_api", "dir_common"],
        "params":     ["fuzz_params", "dir_common"],
    }
    for key in fallbacks.get(category, [category]):
        p = WORDLISTS.get(key, "")
        if p and Path(p).exists():
            return p
    return None

def shannon_entropy(data: str) -> float:
    if not data: return 0.0
    freq = Counter(data)
    n = len(data)
    return -sum((c/n) * math.log2(c/n) for c in freq.values())


def custom_header_arg() -> str:
    return CUSTOM_HEADER

def curl_header_args(extra_headers: Optional[List[str]] = None) -> str:
    headers = []
    if CUSTOM_HEADER:
        headers.append(f'-H "{CUSTOM_HEADER}"')
    for header in (extra_headers or []):
        headers.append(f'-H "{header}"')
    return " ".join(headers)

def shell_single_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"

def inject_header_into_command(command: str, tool: str) -> str:
    if CUSTOM_HEADER and CUSTOM_HEADER in command:
        return command

    stripped = command.lstrip()

    if not CUSTOM_HEADER:
        return command

    if tool == "curl" and stripped.startswith("curl "):
        return command.replace("curl ", f'curl -H "{CUSTOM_HEADER}" ', 1)

    if tool == "ffuf" and stripped.startswith("ffuf "):
        return command.replace("ffuf ", f'ffuf -H "{CUSTOM_HEADER}" ', 1)

    if tool == "feroxbuster" and stripped.startswith("feroxbuster "):
        return command.replace("feroxbuster ", f'feroxbuster -H "{CUSTOM_HEADER}" ', 1)

    if tool == "httpx" and stripped.startswith("httpx "):
        return command.replace("httpx ", f'httpx -H "{CUSTOM_HEADER}" ', 1)

    if tool == "nuclei" and stripped.startswith("nuclei "):
        return command.replace("nuclei ", f'nuclei -H "{CUSTOM_HEADER}" ', 1)

    if tool == "dirsearch" and stripped.startswith("dirsearch "):
        return command.replace("dirsearch ", f'dirsearch -H "{CUSTOM_HEADER}" ', 1)

    if tool == "gobuster" and stripped.startswith("gobuster "):
        return command.replace("gobuster ", f'gobuster -H "{CUSTOM_HEADER}" ', 1)

    return command

def normalize_action_command(command: str, tool: str) -> str:
    lines = []
    for line in command.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            lines.append(line)
            continue
        lines.append(inject_header_into_command(line, tool))
    return "\n".join(lines)

# ===========================================================================
# HACKERONE SCOPE PARSER
# ===========================================================================

def parse_hackerone_scope(csv_path, bounty_only=False):
    log_phase("PARSING HACKERONE SCOPE")
    csv_path = Path(csv_path)
    if not csv_path.exists():
        log_error(f"Scope CSV not found: {csv_path}"); sys.exit(1)

    targets = {"domains": set(), "urls": set(), "wildcards": [],
               "out_of_scope": [], "all_raw": []}

    delimiter = ","
    with open(csv_path, "r", encoding="utf-8-sig") as f:
        fl = f.readline()
        if ";" in fl and "," not in fl: delimiter = ";"

    with open(csv_path, "r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f, delimiter=delimiter)
        if reader.fieldnames:
            reader.fieldnames = [h.strip().lower().replace(" ", "_") for h in reader.fieldnames]
        for row in reader:
            row = {k: v.strip() if v else "" for k, v in row.items()}
            targets["all_raw"].append(row)
            ident = row.get("identifier", "").strip()
            atype = row.get("asset_type", "").strip().upper()
            esub  = row.get("eligible_for_submission", "").strip().lower()
            ebty  = row.get("eligible_for_bounty", "").strip().lower()
            if not ident: continue
            if esub == "false":
                targets["out_of_scope"].append(ident); continue
            if bounty_only and ebty != "true": continue
            if atype == "URL":
                clean = ident.rstrip("/")
                dom = re.sub(r'^https?://', '', clean).split("/")[0].split(":")[0]
                targets["urls"].add(clean); targets["domains"].add(dom)
            elif atype == "WILDCARD":
                targets["wildcards"].append(ident)
                dom = re.sub(r'^\*\.', '', ident)
                dom = re.sub(r'^https?://', '', dom).split("/")[0].split(":")[0]
                if dom: targets["domains"].add(dom)
            elif atype == "CIDR":
                log_info(f"  CIDR scope (manual): {ident}")
            elif atype in ("GOOGLE_PLAY_APP_ID", "APPLE_STORE_APP_ID"):
                log_info(f"  Mobile app (skipping): {ident}")
            else:
                log_info(f"  Other asset ({atype}): {ident}")

    log_success(f"Parsed: {csv_path.name}")
    log_success(f"  Domains: {len(targets['domains'])} | URLs: {len(targets['urls'])} | "
                f"Wildcards: {len(targets['wildcards'])} | OOS: {len(targets['out_of_scope'])}")
    for d in sorted(targets["domains"]): print(f"    -> {d}")
    print()
    return targets

def filter_out_of_scope(results, oos):
    if not oos: return results
    filtered = [r for r in results if not any(
        re.sub(r'^https?://', '', e.lower()).rstrip("/") in r.lower() for e in oos)]
    diff = len(results) - len(filtered)
    if diff: log_warning(f"Filtered {diff} out-of-scope results")
    return filtered

# ===========================================================================
# PHASE 1: SUBDOMAIN ENUMERATION
# ===========================================================================

def subdomain_enumeration(domain, output_dir, deep=False):
    log_phase("PHASE 1: Subdomain Enumeration")
    all_subs = set()

    normalized_domain = (domain or "").strip().lower().lstrip("*.").rstrip(".")
    if normalized_domain and "." in normalized_domain:
        all_subs.add(normalized_domain)

    log_info("Running subfinder...")
    sf = output_dir / "subfinder.txt"
    cmd = ["subfinder", "-d", domain, "-silent", "-o", str(sf)]
    if deep:
        cmd.append("-all")
    run_command(cmd, timeout=300)
    s = read_nonempty_lines(sf)
    if s:
        all_subs.update(s)
        log_success(f"Subfinder: {len(s)} subdomains")

    if deep and check_tool("amass"):
        log_info("Running amass (deep passive)...")
        af = output_dir / "amass.txt"
        run_command(["amass", "enum", "-passive", "-d", domain, "-o", str(af)], timeout=600)
        s = read_nonempty_lines(af)
        if s:
            new = set(s) - all_subs
            all_subs.update(s)
            log_success(f"Amass: {len(new)} additional")

    combined = output_dir / "subdomains_all.txt"
    sorted_subs = sorted(all_subs)
    combined.write_text("\n".join(sorted_subs))
    log_success(f"Total unique subdomains: {len(sorted_subs)}")
    return sorted_subs

# ===========================================================================
# PHASE 2: LIVE HOST DETECTION
# ===========================================================================

def live_host_detection(subdomains, output_dir):
    log_phase("PHASE 2: Live Host Detection")
    if not subdomains:
        log_warning("No subdomains to probe."); return [], []

    sf = output_dir / "subdomains_all.txt"
    if not sf.exists(): sf.write_text("\n".join(subdomains))

    log_info(f"Probing {len(subdomains)} subdomains with httpx...")
    jf = output_dir / "httpx_results.json"
    cmd = [
        "httpx", "-silent", "-l", str(sf),
        "-status-code", "-title", "-tech-detect", "-content-length", "-content-type",
        "-web-server", "-follow-redirects", "-method", "-response-time",
        "-json", "-o", str(jf),
    ]
    if custom_header_arg():
        cmd.extend(["-H", custom_header_arg()])
    run_command(cmd, timeout=600)

    httpx_data = read_jsonl(jf)
    live_hosts = [entry["url"] for entry in httpx_data if entry.get("url")]

    (output_dir / "live_hosts.txt").write_text("\n".join(live_hosts))
    log_success(f"Found {len(live_hosts)} live hosts")

    for e in httpx_data:
        st = e.get("status_code", "?"); url = e.get("url", "?")
        title = e.get("title", ""); srv = e.get("webserver", "")
        tech = ", ".join(e.get("tech", []))
        if st in [200, 301, 302, 403, 500]:
            c = Colors.GREEN if st == 200 else Colors.YELLOW
            extras = f" ({srv})" if srv else ""
            extras += f" [{tech}]" if tech else ""
            print(f"  {c}[{st}]{Colors.END} {url} - {title}{extras}")

    return live_hosts, httpx_data

# ===========================================================================
# PHASE 3: SCREENSHOTS
# ===========================================================================

def take_screenshots(live_hosts, output_dir):
    log_phase("PHASE 3: Screenshots")
    if not check_tool("gowitness"):
        log_warning("gowitness not installed, skipping."); return
    if not live_hosts:
        log_warning("No live hosts to screenshot."); return

    lf = output_dir / "live_hosts.txt"
    sd = output_dir / "screenshots"; sd.mkdir(exist_ok=True)
    log_info(f"Screenshotting {len(live_hosts)} hosts...")
    run_command(
        ["gowitness", "scan", "file", "-f", str(lf), "--screenshot-path", str(sd)],
        timeout=900,
    )
    if not list(sd.glob("*.png")):
        run_command(["gowitness", "file", "-f", str(lf), "-P", str(sd), "--no-http"], timeout=900)
    log_success(f"Captured {len(list(sd.glob('*.png')))} screenshots")

# ===========================================================================
# PHASE 4: TECHNOLOGY FINGERPRINTING
# ===========================================================================

def technology_fingerprint(live_hosts, output_dir):
    log_phase("PHASE 4: Technology Fingerprinting")
    if not check_tool("whatweb"):
        log_warning("whatweb not installed, skipping."); return {}
    if not live_hosts: return {}

    lf = output_dir / "live_hosts.txt"
    wf = output_dir / "whatweb_results.json"
    run_command(
        ["whatweb", f"--input-file={lf}", f"--log-json={wf}", "--quiet"],
        timeout=600,
    )

    tech = {}
    for e in read_jsonl(wf):
        try:
            tech[e.get("target", "unknown")] = list(e.get("plugins", {}).keys())
        except TypeError:
            continue
    log_success(f"Fingerprinted {len(tech)} hosts")
    return tech

# ===========================================================================
# PHASE 5: JS SOURCE MAP SECRET SCANNING
# ===========================================================================

SECRET_PATTERNS = [
    # AWS
    ("AWS Access Key ID",       r'AKIA[0-9A-Z]{16}', "AWS Access Key", "critical"),
    ("AWS Secret Access Key",   r'(?:aws_secret_access_key|aws_secret|secret_key)\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40})["\']?', "AWS Secret Key", "critical"),
    # Stripe - SECRET keys only (pk_live/pk_test are public by design)
    ("Stripe Live Secret Key",  r'sk_live_[0-9a-zA-Z]{24,}', "Stripe Live Secret Key", "critical"),
    ("Stripe Test Secret Key",  r'sk_test_[0-9a-zA-Z]{24,}', "Stripe Test Secret Key", "low"),
    # GitHub
    ("GitHub PAT (ghp)",        r'ghp_[0-9a-zA-Z]{36}', "GitHub Personal Access Token", "critical"),
    ("GitHub OAuth (gho)",      r'gho_[0-9a-zA-Z]{36}', "GitHub OAuth Token", "critical"),
    ("GitHub App (ghs)",        r'ghs_[0-9a-zA-Z]{36}', "GitHub App Installation Token", "high"),
    # Slack
    ("Slack Bot Token",         r'xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}', "Slack Bot Token", "critical"),
    ("Slack User Token",        r'xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-f0-9]{32}', "Slack User Token", "critical"),
    ("Slack Webhook",           r'https://hooks\.slack\.com/services/T[0-9A-Z]{8,}/B[0-9A-Z]{8,}/[a-zA-Z0-9]{24}', "Slack Webhook URL", "high"),
    # Private keys
    ("RSA Private Key",         r'-----BEGIN RSA PRIVATE KEY-----', "RSA Private Key", "critical"),
    ("EC Private Key",          r'-----BEGIN EC PRIVATE KEY-----', "EC Private Key", "critical"),
    ("Generic Private Key",     r'-----BEGIN PRIVATE KEY-----', "Private Key (PKCS8)", "critical"),
    # SendGrid
    ("SendGrid API Key",        r'SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}', "SendGrid API Key", "critical"),
    # Twilio
    ("Twilio API Key",          r'SK[0-9a-fA-F]{32}', "Twilio API Key", "high"),
    # Shopify
    ("Shopify Admin Token",     r'shpat_[a-fA-F0-9]{32}', "Shopify Admin Access Token", "critical"),
    ("Shopify Shared Secret",   r'shpss_[a-fA-F0-9]{32}', "Shopify Shared Secret", "critical"),
    # Square
    ("Square Access Token",     r'sq0atp-[0-9A-Za-z\-_]{22}', "Square Access Token", "critical"),
    # Database URIs (only with credentials embedded)
    ("Database URL w/ Creds",   r'(?:postgres|mysql|mongodb)(?:ql)?:\/\/[^:]+:[^@]+@[^\s"\'<>]{5,}', "Database URI with credentials", "critical"),
    # Hardcoded auth headers
    ("Hardcoded Auth Header",   r'(?:Authorization|authorization)\s*[:=]\s*["\'](?:Bearer|Basic)\s+([A-Za-z0-9_\-\.=+/]{20,})["\']', "Hardcoded Auth Header", "high"),
]

FALSE_POSITIVE_PATTERNS = [
    r'EXAMPLE', r'example\.com', r'your[-_]?api[-_]?key', r'INSERT[-_]?HERE',
    r'xxx+', r'TODO', r'CHANGEME', r'placeholder', r'test[-_]?key',
    r'dummy', r'sample', r'\*{3,}', r'\.{3,}', r'<[A-Z_]+>',
    r'process\.env', r'ENV\[', r'os\.environ',
    r'your[-_]?secret', r'replace[-_]?me', r'fill[-_]?in',
    r'SECRET_KEY_HERE', r'API_KEY_HERE', r'0{10,}', r'1{10,}',
    r'abcdef', r'123456',
]

ENTROPY_THRESHOLDS = {"critical": 3.0, "high": 3.0, "medium": 3.5, "low": 2.5}


@dataclass
class SecretFinding:
    url: str
    source_map_url: str
    secret_type: str
    severity: str
    description: str
    matched_value: str   # masked
    raw_hash: str        # SHA256 prefix for dedup
    source_file: str
    line_number: Optional[int] = None
    context: str = ""
    entropy: float = 0.0


@dataclass
class JSMapScanResult:
    target: str
    js_files_found: int = 0
    source_maps_found: int = 0
    secrets_found: int = 0
    findings: list = field(default_factory=list)
    errors: list = field(default_factory=list)


def _is_false_positive(val: str) -> bool:
    for fp in FALSE_POSITIVE_PATTERNS:
        if re.search(fp, val, re.IGNORECASE): return True
    if len(set(val)) < 5: return True
    return False


def _mask_secret(v: str) -> str:
    if len(v) > 16:   return v[:6] + "..." + v[-4:]
    elif len(v) > 8:  return v[:4] + "..." + v[-3:]
    else:              return v[:3] + "..."


def scan_source_for_secrets(src_name, src_content, map_url, target_url, seen_hashes):
    """Scan a source file for secrets. Deduplicates via seen_hashes set."""
    findings = []
    lines = src_content.split('\n')
    for pat_name, pat_re, desc, sev in SECRET_PATTERNS:
        for lnum, line in enumerate(lines, 1):
            for m in re.finditer(pat_re, line):
                raw = m.group(1) if m.lastindex and m.lastindex >= 1 else m.group(0)
                if _is_false_positive(raw): continue
                ent = shannon_entropy(raw)
                thr = ENTROPY_THRESHOLDS.get(sev, 3.0)
                if "Private Key" not in pat_name and ent < thr: continue
                h = hashlib.sha256(raw.encode()).hexdigest()[:16]
                if h in seen_hashes: continue
                seen_hashes.add(h)
                ctx = line.strip()
                if len(ctx) > 200:
                    s = max(0, m.start()-60); e = min(len(line), m.end()+60)
                    ctx = "..." + line[s:e].strip() + "..."
                findings.append(SecretFinding(
                    url=target_url, source_map_url=map_url,
                    secret_type=pat_name, severity=sev, description=desc,
                    matched_value=_mask_secret(raw), raw_hash=h,
                    source_file=src_name, line_number=lnum,
                    context=ctx, entropy=round(ent, 2),
                ))
    return findings


def js_map_scan_phase(live_hosts, output_dir, threads=10, timeout=10):
    """Phase 5: Scan live hosts for exposed JS source maps and extract secrets."""
    log_phase("PHASE 5: JS Source Map Secret Scanning")

    if not HAS_REQUESTS:
        log_warning("'requests' not installed. Skipping JS map scanning.")
        log_warning("Install: pip install requests"); return []
    if not live_hosts:
        log_warning("No live hosts for JS scan."); return []

    log_info(f"Scanning {len(live_hosts)} hosts for source maps ({threads} threads)...")

    session = requests.Session()
    retry = Retry(total=2, backoff_factor=0.3, status_forcelist=[429, 500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry, pool_connections=threads, pool_maxsize=threads)
    session.mount("http://", adapter); session.mount("https://", adapter)
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "*/*",
    })
    session.verify = False
    seen_hashes = set()
    all_results = []

    def _fetch(url):
        try:
            r = session.get(url, timeout=timeout, allow_redirects=True)
            return r if r.status_code == 200 else None
        except requests.RequestException: return None

    def _extract_js_urls(base, html):
        urls = set()
        if HAS_BS4:
            soup = BeautifulSoup(html, 'html.parser')
            for s in soup.find_all('script', src=True):
                full = urljoin(base, s['src'])
                if '.js' in full.split('?')[0]: urls.add(full)
        else:
            for m in re.finditer(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', html, re.I):
                urls.add(urljoin(base, m.group(1)))
        for m in re.finditer(r'["\']([^"\']+(?:chunk|bundle|vendor|main|app)[^"\']*\.js)["\']', html):
            c = m.group(1)
            if c.startswith(('http://', 'https://', '//', '/')): urls.add(urljoin(base, c))
        return list(urls)

    def _scan_host(target):
        result = JSMapScanResult(target=target)
        if not target.startswith(('http://', 'https://')): target = f"https://{target}"

        resp = _fetch(target)
        if not resp:
            result.errors.append(f"Could not fetch {target}"); return result

        js_urls = _extract_js_urls(target, resp.text)
        result.js_files_found = len(js_urls)

        for js_url in js_urls:
            js_resp = _fetch(js_url)
            if not js_resp: continue

            # Find source map reference
            map_url = None
            sm = re.search(r'//[#@]\s*sourceMappingURL\s*=\s*(\S+)', js_resp.text)
            if sm:
                ref = sm.group(1)
                if ref.startswith('data:'): continue
                map_url = ref if ref.startswith('http') else urljoin(js_url, ref)
            else:
                probe = js_url.split('?')[0] + '.map'
                pr = _fetch(probe)
                if pr and 'mappings' in pr.text[:500]: map_url = probe

            if not map_url: continue
            result.source_maps_found += 1

            mr = _fetch(map_url)
            if not mr: continue
            try: md = mr.json()
            except (json.JSONDecodeError, ValueError): continue

            names = md.get('sources', [])
            contents = md.get('sourcesContent', [])
            if not contents: continue

            for i, name in enumerate(names):
                if i < len(contents) and contents[i]:
                    result.findings.extend(
                        scan_source_for_secrets(name, contents[i], map_url, target, seen_hashes)
                    )

        result.secrets_found = len(result.findings)
        return result

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(_scan_host, u): u for u in live_hosts}
        for f in as_completed(futs):
            try:
                r = f.result(); all_results.append(r)
                if r.source_maps_found > 0:
                    log_success(f"  {r.target}: {r.source_maps_found} maps, {r.secrets_found} secrets")
            except Exception as e:
                log_error(f"  Error: {futs[f]}: {e}")

    total_maps = sum(r.source_maps_found for r in all_results)
    total_secrets = sum(r.secrets_found for r in all_results)
    log_success(f"JS scan: {total_maps} source maps, {total_secrets} secrets")

    all_findings = [f for r in all_results for f in r.findings]
    if all_findings:
        ff = output_dir / "js_map_secrets.json"
        ff.write_text(json.dumps([asdict(f) for f in all_findings], indent=2))
        log_success(f"Secrets saved: {ff}")
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        all_findings.sort(key=lambda f: sev_order.get(f.severity, 99))
        print()
        for f in all_findings:
            icons = {"critical": "!!", "high": "! ", "medium": "? ", "low": ". "}
            print(f"  [{icons.get(f.severity,'  ')}] [{f.severity.upper()}] {f.secret_type}")
            print(f"       Host: {f.url}  |  File: {f.source_file}:{f.line_number}")
            print(f"       Value: {f.matched_value}  (entropy: {f.entropy})")
            print(f"       Context: {f.context[:120]}")
            print()

    return all_results


# ===========================================================================
# PHASE 6: SELECTIVE PORT SCANNING
# ===========================================================================

def selective_port_scan(httpx_data, output_dir, aggressive=False):
    """Run nmap selectively on hosts that look interesting based on httpx data."""
    log_phase("PHASE 6: Selective Port Scanning")
    if not check_tool("nmap"):
        log_warning("nmap not installed, skipping."); return {}

    hosts_to_scan = set()
    reasons = {}

    for e in httpx_data:
        url = e.get("url", ""); status = e.get("status_code", 0)
        tech = [t.lower() for t in e.get("tech", [])]
        server = (e.get("webserver", "") or "").lower()
        parsed = urlparse(url); hostname = parsed.hostname
        if not hostname: continue

        scan_reasons = []
        port = parsed.port
        if port and port not in (80, 443):
            scan_reasons.append(f"non-standard port :{port}")
        if 500 <= status < 600:
            scan_reasons.append(f"server error ({status})")
        if status == 403:
            scan_reasons.append("403 forbidden")

        interesting_tech = ["jenkins", "tomcat", "jboss", "weblogic", "elasticsearch",
                           "kibana", "grafana", "phpmyadmin", "couchdb", "redis",
                           "mongodb", "memcached", "rabbitmq", "solr"]
        for t in interesting_tech:
            if any(t in ti for ti in tech) or t in server:
                scan_reasons.append(f"interesting tech: {t}")

        if scan_reasons:
            hosts_to_scan.add(hostname)
            reasons[hostname] = scan_reasons

    if not hosts_to_scan:
        log_info("No hosts warranted port scanning."); return {}

    log_info(f"Scanning {len(hosts_to_scan)} hosts:")
    for h in sorted(hosts_to_scan):
        print(f"  -> {h}: {', '.join(reasons.get(h, []))}")

    nmap_results = {}
    nmap_dir = output_dir / "nmap"; nmap_dir.mkdir(exist_ok=True)

    for host in sorted(hosts_to_scan):
        log_info(f"  nmap -> {host}")
        safe = re.sub(r'[^a-zA-Z0-9._-]', '_', host)
        xf = nmap_dir / f"{safe}.xml"
        if aggressive:
            cmd = ["nmap", "-sV", "-sC", "-T4", "-Pn", "--top-ports", "1000", "-oX", str(xf), host]
        else:
            cmd = ["nmap", "-sV", "-T3", "-Pn", "--top-ports", "200", "-oX", str(xf), host]
        output = run_command(cmd, timeout=300)
        nmap_results[host] = {"raw": output, "xml": str(xf), "reasons": reasons.get(host, [])}
        for line in output:
            if '/tcp' in line and 'open' in line:
                log_success(f"    {line.strip()}")

    return nmap_results

# ===========================================================================
# PHASE 7: TRIAGE ENGINE - THE CORE UPGRADE
# ===========================================================================

@dataclass
class TriageAction:
    """A concrete next-step command or recommendation for a host."""
    host: str
    category: str       # dir_bruteforce, api_fuzz, vuln_scan, manual, etc.
    priority: int       # 1=highest
    tool: str           # feroxbuster, ffuf, nuclei, wpscan, manual, etc.
    command: str        # ready-to-run command
    reason: str         # why this was triggered
    notes: str = ""     # extra context




def _looks_like_data_exposure_candidate(profile: dict) -> bool:
    """Return True only for large responses that also look like sensitive app/API/admin surfaces."""
    url = (profile.get("url") or "").lower()
    title = (profile.get("title") or "").lower()
    tech = {str(t).lower() for t in (profile.get("tech") or set())}
    ctype = (profile.get("content_type") or "").lower()
    clen = int(profile.get("content_length", 0) or 0)
    server = (profile.get("server") or "").lower()

    if clen < 900000:
        return False

    auth_front_titles = [
        "sign in - google accounts",
        "google accounts",
        "authentication required",
        "vercel security checkpoint",
        "access denied",
    ]
    if any(x in title for x in auth_front_titles):
        return False

    if "vercel" in tech and ("authentication required" in title or "security checkpoint" in title):
        return False

    sensitive_url_bits = [
        "/api/", "/v1/", "/v2/", "swagger", "openapi", "graphql",
        "admin", "debug", "trace", "report", "export", "internal",
        "actuator", "portal", "dashboard"
    ]
    sensitive_tech_bits = [
        "jenkins", "grafana", "kibana", "elasticsearch",
        "tomcat", "spring", "jboss", "weblogic", "wildfly", "jetty", "java"
    ]
    sensitive_ctypes = ["json", "xml", "text", "csv"]

    if any(bit in url or bit in title for bit in sensitive_url_bits):
        return True
    if any(any(bit in t for bit in sensitive_tech_bits) for t in tech):
        return True
    if any(bit in server for bit in sensitive_tech_bits):
        return True
    if any(ct in ctype for ct in sensitive_ctypes):
        return True

    return False

def triage_engine(httpx_data, tech_results, nmap_results, js_findings, output_dir):
    """
    Phase 7: Analyze all collected data and produce per-host playbooks.
    Maps (technology + status + response data) -> concrete commands.
    """
    log_phase("PHASE 7: Triage & Attack Playbooks")

    actions: List[TriageAction] = []
    host_categories: Dict[str, Set[str]] = defaultdict(set)
    nuclei_installed = check_tool("nuclei")
    wpscan_installed = check_tool("wpscan")

    def _wl(cat):
        w = get_best_wordlist(cat)
        return w or "/path/to/your/wordlist.txt"

    def add_action(action: TriageAction):
        action.command = normalize_action_command(action.command, action.tool)
        actions.append(action)
        host_categories[action.host].add(action.category)

    whatweb_by_host: Dict[str, Set[str]] = defaultdict(set)
    for ww_url, ww_techs in tech_results.items():
        hostname = urlparse(ww_url).hostname
        if hostname:
            whatweb_by_host[hostname].update(t.lower() for t in ww_techs)

    # Build merged host profiles
    host_profiles = {}
    for entry in httpx_data:
        url = entry.get("url", "")
        if not url: continue
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        tech = set(t.lower() for t in entry.get("tech", []))
        server = (entry.get("webserver", "") or "").lower()
        title = (entry.get("title", "") or "").lower()
        status = entry.get("status_code", 0)
        clen = entry.get("content_length", 0)
        ctype = (entry.get("content_type", "") or "").lower()

        tech.update(whatweb_by_host.get(hostname, set()))

        host_profiles[url] = {
            "url": url, "hostname": hostname, "status": status,
            "title": title, "tech": tech, "server": server,
            "content_length": clen, "content_type": ctype,
            "nmap": nmap_results.get(hostname, {}),
        }

    # ==== TRIAGE RULES ====

    for url, p in host_profiles.items():
        tech   = p["tech"]
        status = p["status"]
        server = p["server"]
        title  = p["title"]

        # ---- WordPress ----
        if any("wordpress" in t for t in tech) or "wp-" in title:
            if wpscan_installed:
                add_action(TriageAction(
                    host=url, category="cms_scan", priority=1, tool="wpscan",
                    command=f"wpscan --url {url} --enumerate vp,vt,u --api-token $WPSCAN_TOKEN",
                    reason="WordPress detected",
                    notes="Set WPSCAN_TOKEN env var for vulnerability data.",
                ))
            add_action(TriageAction(
                host=url, category="dir_bruteforce", priority=2, tool="feroxbuster",
                command=f"feroxbuster -u {url} -w {_wl('dir_common')} -x php,txt,bak,old,zip -t 50 -d 2 --smart",
                reason="WordPress - hunt for exposed backups, configs, debug files",
            ))

        # ---- Joomla ----
        if any("joomla" in t for t in tech):
            add_action(TriageAction(
                host=url, category="dir_bruteforce", priority=2, tool="feroxbuster",
                command=f"feroxbuster -u {url} -w {_wl('dir_common')} -x php,txt,bak,sql,zip -t 50 -d 2",
                reason="Joomla detected - check admin panel, backups, configuration.php~",
            ))

        # ---- API / Swagger / GraphQL ----
        api_ind = ["swagger", "graphql", "openapi", "/api/", "/v1/", "/v2/", "/rest/"]
        if any(ind in url.lower() or ind in title for ind in api_ind):
            add_action(TriageAction(
                host=url, category="api_fuzz", priority=1, tool="ffuf",
                command=f"ffuf -u {url}/FUZZ -w {_wl('api')} -mc 200,201,301,302,401,403,405 -t 40",
                reason="API endpoint detected - fuzz for undocumented routes",
            ))
            if "graphql" in url.lower() or "graphql" in title:
                add_action(TriageAction(
                    host=url, category="manual", priority=1, tool="curl",
                    command=(
                        f'curl -s -X POST {shell_single_quote(url)} '
                        f'-H "Content-Type: application/json" '
                        f'--data {shell_single_quote('{"query":"{__schema{types{name}}}"}')}'
                    ),
                    reason="GraphQL detected - run introspection query",
                    notes="If works, use graphql-voyager or InQL for full schema.",
                ))

        # ---- 403 Forbidden - bypass attempts ----
        if status == 403:
            add_action(TriageAction(
                host=url, category="dir_bruteforce", priority=2, tool="feroxbuster",
                command=f"feroxbuster -u {url} -w {_wl('dir_common')} -t 50 -d 2 --dont-filter",
                reason="403 Forbidden - brute-force may find accessible paths",
            ))
            add_action(TriageAction(
                host=url, category="bypass_403", priority=2, tool="curl",
                command=(
                    f'# 403 bypass for {url}\n'
                    f'curl -s -o /dev/null -w "%{{http_code}}" -H "{CUSTOM_HEADER}" -H "X-Original-URL: /" {shell_single_quote(url)}\n'
                    f'curl -s -o /dev/null -w "%{{http_code}}" -H "{CUSTOM_HEADER}" -H "X-Forwarded-For: 127.0.0.1" {shell_single_quote(url)}\n'
                    f'curl -s -o /dev/null -w "%{{http_code}}" -H "{CUSTOM_HEADER}" {shell_single_quote(url + "/..;/")}\n'
                    f'curl -s -o /dev/null -w "%{{http_code}}" -H "{CUSTOM_HEADER}" {shell_single_quote(url + "/%2e/")}'
                ),
                reason="403 - try common bypass techniques",
            ))

        # ---- Server errors (5xx) ----
        if 500 <= status < 600:
            add_action(TriageAction(
                host=url, category="error_probe", priority=1, tool="curl",
                command=(
                    f'# Probe error behavior\n'
                    f'curl -v -H "{CUSTOM_HEADER}" {shell_single_quote(url)} 2>&1 | head -50\n'
                    f'curl -s -H "{CUSTOM_HEADER}" -H "Content-Type: application/json" --data \'{{}}\' {shell_single_quote(url)}\n'
                    f'curl -s -H "{CUSTOM_HEADER}" {shell_single_quote(url + "/?debug=true&trace=true")}'
                ),
                reason=f"HTTP {status} - may leak stack traces or internal paths",
            ))

        # ---- Admin/login panels ----
        admin_kw = ["admin", "dashboard", "panel", "manage", "cms", "login", "portal", "backoffice"]
        if any(kw in url.lower() or kw in title for kw in admin_kw):
            add_action(TriageAction(
                host=url, category="auth_test", priority=2, tool="curl",
                command=(
                    f'# Default creds check\n'
                    f'curl -s -o /dev/null -w "%{{http_code}}" -X POST -H "{CUSTOM_HEADER}" '
                    f'--data "username=admin&password=admin" {shell_single_quote(url)}\n'
                    f'curl -s -o /dev/null -w "%{{http_code}}" -X POST -H "{CUSTOM_HEADER}" '
                    f'--data "username=admin&password=password" {shell_single_quote(url)}'
                ),
                reason="Admin/login panel detected",
                notes="Also try: admin:admin123, admin:<blank>, test:test",
            ))

        # ---- Open redirect candidates (3xx) ----
        if status in [301, 302, 307, 308]:
            add_action(TriageAction(
                host=url, category="open_redirect", priority=3, tool="curl",
                command=(
                    f'# Open redirect tests\n'
                    f'curl -s -o /dev/null -w "%{{http_code}} %{{redirect_url}}" -H "{CUSTOM_HEADER}" {shell_single_quote(url + "?next=https://evil.com")}\n'
                    f'curl -s -o /dev/null -w "%{{http_code}} %{{redirect_url}}" -H "{CUSTOM_HEADER}" {shell_single_quote(url + "?url=https://evil.com")}\n'
                    f'curl -s -o /dev/null -w "%{{http_code}} %{{redirect_url}}" -H "{CUSTOM_HEADER}" {shell_single_quote(url + "?redirect=//evil.com")}'
                ),
                reason="Redirect - test for open redirect",
            ))

        # ---- Java / Tomcat / Spring ----
        java_ind = ["tomcat", "spring", "java", "jboss", "weblogic", "wildfly", "jetty"]
        if any(j in t for t in tech for j in java_ind) or any(j in server for j in java_ind):
            add_action(TriageAction(
                host=url, category="dir_bruteforce", priority=2, tool="feroxbuster",
                command=f"feroxbuster -u {url} -w {_wl('dir_common')} -x jsp,do,action,json,xml -t 50 -d 2",
                reason="Java stack - look for servlets, actuator, debug pages",
            ))
            add_action(TriageAction(
                host=url, category="actuator_probe", priority=1, tool="curl",
                command=(
                    f'# Spring Boot Actuator probe\n'
                    f'for ep in actuator env health info beans mappings trace configprops heapdump; do\n'
                    f'  echo -n "$ep: "; curl -s -o /dev/null -w "%{{http_code}}" -H "{CUSTOM_HEADER}" {shell_single_quote(url + "/")}"$ep"; echo\n'
                    f'done'
                ),
                reason="Java/Spring - check exposed actuator endpoints",
            ))

        # ---- Node.js / Express / Next.js ----
        node_ind = ["node.js", "express", "next.js", "nuxt", "koa"]
        if any(n in t for t in tech for n in node_ind) or any(n in server for n in node_ind):
            add_action(TriageAction(
                host=url, category="dir_bruteforce", priority=2, tool="feroxbuster",
                command=f"feroxbuster -u {url} -w {_wl('dir_common')} -x js,json,map,env -t 50 -d 2",
                reason="Node.js - hunt for .env, source maps, API routes",
            ))

        # ---- PHP ----
        php_ind = ["php", "laravel", "symfony", "codeigniter"]
        if any(p in t for t in tech for p in php_ind) or "php" in server:
            add_action(TriageAction(
                host=url, category="dir_bruteforce", priority=2, tool="feroxbuster",
                command=f"feroxbuster -u {url} -w {_wl('dir_common')} -x php,php.bak,php~,inc,conf,sql,zip,tar.gz -t 50 -d 2",
                reason="PHP - check for backup files, configs, common vulns",
            ))

        # ---- Jenkins ----
        if "jenkins" in str(tech) or "jenkins" in title:
            add_action(TriageAction(
                host=url, category="jenkins_probe", priority=1, tool="curl",
                command=(
                    f'# Jenkins probe\n'
                    f'curl -s -o /dev/null -w "%{{http_code}}" -H "{CUSTOM_HEADER}" {shell_single_quote(url + "/script")}\n'
                    f'curl -s -o /dev/null -w "%{{http_code}}" -H "{CUSTOM_HEADER}" {shell_single_quote(url + "/asynchPeople/")}\n'
                    f'curl -s -o /dev/null -w "%{{http_code}}" -H "{CUSTOM_HEADER}" {shell_single_quote(url + "/systemInfo")}'
                ),
                reason="Jenkins - check for unauthenticated script console",
            ))

        # ---- Elasticsearch / Kibana ----
        if any(x in str(tech) or x in title for x in ["elasticsearch", "kibana"]):
            add_action(TriageAction(
                host=url, category="data_exposure", priority=1, tool="curl",
                command=(
                    f'# Elasticsearch probe\n'
                    f'curl -s -H "{CUSTOM_HEADER}" {shell_single_quote(url + "/_cat/indices?v")}\n'
                    f'curl -s -H "{CUSTOM_HEADER}" {shell_single_quote(url + "/_cluster/health")}\n'
                    f'curl -s -H "{CUSTOM_HEADER}" {shell_single_quote(url + "/_search?size=1")}'
                ),
                reason="Elasticsearch/Kibana - check unauthenticated access",
            ))

        # ---- Large response ----
        if _looks_like_data_exposure_candidate(p):
            add_action(TriageAction(
                host=url, category="data_exposure", priority=3, tool="curl",
                command=f'curl -s -H "{CUSTOM_HEADER}" {shell_single_quote(url)} | head -c 5000',
                reason=f"Large response ({p['content_length']} bytes) on potentially sensitive surface",
            ))

        # ---- Nuclei (if installed, selective) ----
        if nuclei_installed:
            if status == 200 or any(t in str(tech) for t in [
                "jenkins", "tomcat", "jira", "confluence", "gitlab"]):
                add_action(TriageAction(
                    host=url, category="vuln_scan", priority=3, tool="nuclei",
                    command=f"nuclei -u {url} -as -rl 50",
                    reason="Nuclei auto-selected templates based on detected tech",
                    notes="Focus with: -severity critical,high",
                ))

        # ---- General 200 OK hosts: always run basic dir brute ----
        if status == 200 and "dir_bruteforce" not in host_categories[url]:
            # Only if no tech-specific rule already added a dir brute for this host
            add_action(TriageAction(
                host=url, category="dir_bruteforce", priority=3, tool="feroxbuster",
                command=f"feroxbuster -u {url} -w {_wl('dir_common')} -t 50 -d 1 --smart",
                reason="Live host (200) - baseline directory discovery",
            ))

    # ---- JS source map secrets -> follow-up actions ----
    for scan_result in (js_findings or []):
        for finding in getattr(scan_result, 'findings', []):
            add_action(TriageAction(
                host=finding.url, category="secret_followup", priority=1, tool="curl",
                command=(
                    f'# LEAKED SECRET: {finding.secret_type}\n'
                    f'# Source: {finding.source_file}:{finding.line_number}\n'
                    f'# Value:  {finding.matched_value}\n'
                    f'# Validate:\n'
                    f'curl -sI -H "{CUSTOM_HEADER}" {shell_single_quote(finding.source_map_url)}'
                ),
                reason=f"Leaked {finding.severity} secret: {finding.secret_type}",
                notes=f"Entropy: {finding.entropy}",
            ))

    # ---- Deduplicate ----
    seen = set()
    unique = []
    for a in actions:
        key = (a.host, hashlib.md5(a.command.encode()).hexdigest()[:12])
        if key not in seen:
            seen.add(key); unique.append(a)
    unique.sort(key=lambda a: (a.priority, a.host))

    if not unique:
        log_info("No actionable items. Hosts look well-hardened.")
        return unique

    log_success(f"Generated {len(unique)} actions across {len(set(a.host for a in unique))} hosts")

    # Group & print
    grouped = {}
    for a in unique: grouped.setdefault(a.host, []).append(a)

    print()
    for host, host_actions in grouped.items():
        host_actions.sort(key=lambda a: a.priority)
        print(f"  {Colors.BOLD}{Colors.CYAN}+-- {host}{Colors.END}")
        for a in host_actions:
            pc = {1: Colors.RED, 2: Colors.YELLOW, 3: Colors.DIM}.get(a.priority, "")
            print(f"  {Colors.CYAN}|{Colors.END}  {pc}[P{a.priority}]{Colors.END} "
                  f"{Colors.BOLD}{a.category}{Colors.END}: {a.reason}")
            for cmd_line in a.command.split('\n'):
                cl = cmd_line.strip()
                if cl and not cl.startswith('#'):
                    print(f"  {Colors.CYAN}|{Colors.END}      {Colors.GREEN}$ {cl}{Colors.END}")
                elif cl.startswith('#'):
                    print(f"  {Colors.CYAN}|{Colors.END}      {Colors.DIM}{cl}{Colors.END}")
            if a.notes:
                print(f"  {Colors.CYAN}|{Colors.END}      {Colors.DIM}i {a.notes}{Colors.END}")
        print(f"  {Colors.CYAN}+{'─'*50}{Colors.END}\n")

    # Save playbook JSON
    pf = output_dir / "playbook.json"
    pf.write_text(json.dumps([asdict(a) for a in unique], indent=2))
    log_success(f"Playbook JSON: {pf}")

    # Save as runnable shell script
    sf = output_dir / "playbook_commands.sh"
    lines = ["#!/bin/bash",
             f"# xLimit Recon Playbook by w1j0y - {datetime.datetime.now().isoformat()}", ""]
    for host, ha in grouped.items():
        lines.append(f"\n# {'='*50}")
        lines.append(f"# TARGET: {host}")
        lines.append(f"# {'='*50}")
        for a in ha:
            lines.append(f"\n# [{a.category}] P{a.priority} - {a.reason}")
            if a.notes: lines.append(f"# Note: {a.notes}")
            for cl in a.command.split('\n'): lines.append(cl)
    sf.write_text("\n".join(lines))
    sf.chmod(0o755)
    log_success(f"Playbook script: {sf}")

    return unique

# ===========================================================================
# PHASE 8: REPORT GENERATION
# ===========================================================================

def generate_text_report(domain, subdomains, live_hosts, httpx_data,
                         triage_actions, tech_results, js_findings, output_dir):
    log_info("Generating text report...")
    rf = output_dir / "report.txt"
    L = []
    L.append("=" * 70)
    L.append(f"  xLimit Recon Report - {domain}")
    L.append(f"  Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    L.append("=" * 70)
    L.append("")
    L.append("SUMMARY")
    L.append("-" * 40)
    L.append(f"  Target:           {domain}")
    L.append(f"  Subdomains:       {len(subdomains)}")
    L.append(f"  Live Hosts:       {len(live_hosts)}")
    L.append(f"  Triage Actions:   {len(triage_actions)}")
    tsec = sum(r.secrets_found for r in js_findings) if js_findings else 0
    L.append(f"  JS Map Secrets:   {tsec}")
    L.append("")

    L.append("LIVE HOSTS")
    L.append("-" * 40)
    for e in httpx_data:
        L.append(f"  [{e.get('status_code','?')}] {e.get('url','?')}")
        L.append(f"        Title:  {e.get('title','N/A')}")
        L.append(f"        Server: {e.get('webserver','N/A')}")
        L.append(f"        Tech:   {', '.join(e.get('tech',[])) or 'N/A'}")
        L.append("")

    if triage_actions:
        L.append("TRIAGE PLAYBOOK")
        L.append("-" * 40)
        for a in triage_actions:
            L.append(f"  [P{a.priority}] {a.host}")
            L.append(f"        Category: {a.category} | Tool: {a.tool}")
            L.append(f"        Reason:   {a.reason}")
            L.append(f"        Command:  {a.command.split(chr(10))[0]}")
            if a.notes: L.append(f"        Notes:    {a.notes}")
            L.append("")

    if js_findings:
        L.append("JS SOURCE MAP SECRETS")
        L.append("-" * 40)
        for r in js_findings:
            for f in r.findings:
                L.append(f"  [{f.severity.upper()}] {f.secret_type}")
                L.append(f"        Host:  {f.url}")
                L.append(f"        File:  {f.source_file}:{f.line_number}")
                L.append(f"        Value: {f.matched_value} (entropy: {f.entropy})")
                L.append("")

    L.append("ALL SUBDOMAINS")
    L.append("-" * 40)
    for s in subdomains: L.append(f"  {s}")

    rf.write_text("\n".join(L))
    log_success(f"Text report: {rf}")


def generate_json_report(domain, subdomains, live_hosts, httpx_data,
                         triage_actions, tech_results, js_findings,
                         nmap_results, output_dir):
    log_info("Generating JSON report...")
    rf = output_dir / "report.json"
    tsec = sum(r.secrets_found for r in js_findings) if js_findings else 0
    report = {
        "metadata": {"target": domain,
                     "timestamp": datetime.datetime.now().isoformat(),
                     "tool": "xLimit Recon"},
        "summary": {"subdomains": len(subdomains), "live_hosts": len(live_hosts),
                     "triage_actions": len(triage_actions), "js_secrets": tsec},
        "subdomains": subdomains,
        "live_hosts_detail": httpx_data,
        "triage_playbook": [asdict(a) for a in triage_actions],
        "js_findings": [asdict(f) for r in (js_findings or []) for f in r.findings],
        "technologies": tech_results,
        "nmap": {h: {"reasons": v.get("reasons", [])} for h, v in nmap_results.items()},
    }
    rf.write_text(json.dumps(report, indent=2))
    log_success(f"JSON report: {rf}")


def _html_escape(s):
    return str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace('"',"&quot;")


def generate_html_report(domain, subdomains, live_hosts, httpx_data,
                         triage_actions, tech_results, js_findings, output_dir):
    log_info("Generating HTML dashboard...")
    rf = output_dir / "dashboard.html"
    sd = output_dir / "screenshots"

    screenshots = {}
    if sd.exists():
        for img in sd.glob("*.png"):
            screenshots[img.stem] = f"screenshots/{img.name}"

    tsec = sum(r.secrets_found for r in js_findings) if js_findings else 0
    status_counts = Counter(str(e.get("status_code","?")) for e in httpx_data)
    tech_summary = Counter(t for e in httpx_data for t in e.get("tech",[]))
    p1 = [a for a in triage_actions if a.priority == 1]
    all_secrets = [f for r in (js_findings or []) for f in r.findings]

    def _action_html(a):
        pc = {1:"critical",2:"high",3:"medium"}.get(a.priority,"low")
        return f'''<div class="action-card {pc}">
<div class="ah"><span class="pb p{a.priority}">P{a.priority}</span>
<span class="ac">{_html_escape(a.category)}</span>
<span class="at">{_html_escape(a.tool)}</span></div>
<div class="ahost">{_html_escape(a.host)}</div>
<div class="ar">{_html_escape(a.reason)}</div>
<pre class="acmd">{_html_escape(a.command)}</pre>
{"<div class='an'>i "+_html_escape(a.notes)+"</div>" if a.notes else ""}
</div>'''

    html = f'''<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>xLimit Recon - {_html_escape(domain)}</title>
<style>
:root{{--bg:#0d1117;--bg2:#161b22;--card:#1c2333;--bdr:#30363d;--t1:#e6edf3;--t2:#8b949e;
--grn:#3fb950;--blu:#58a6ff;--ylw:#d29922;--red:#f85149;--pur:#bc8cff;--org:#f0883e;}}
*{{margin:0;padding:0;box-sizing:border-box;}}
body{{background:var(--bg);color:var(--t1);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;line-height:1.6;}}
.ctr{{max-width:1400px;margin:0 auto;padding:20px;}}
header{{background:var(--bg2);border-bottom:1px solid var(--bdr);padding:24px 0;margin-bottom:24px;}}
header .ctr{{display:flex;justify-content:space-between;align-items:center;}}
h1{{font-size:24px;}} h1 span{{color:var(--blu);}}
.ts{{color:var(--t2);font-size:14px;}}
.sg{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:16px;margin-bottom:24px;}}
.sc{{background:var(--card);border:1px solid var(--bdr);border-radius:8px;padding:20px;text-align:center;}}
.sc .n{{font-size:36px;font-weight:700;margin-bottom:4px;}}
.sc .l{{color:var(--t2);font-size:12px;text-transform:uppercase;letter-spacing:.5px;}}
.sc.grn .n{{color:var(--grn);}} .sc.blu .n{{color:var(--blu);}}
.sc.ylw .n{{color:var(--ylw);}} .sc.red .n{{color:var(--red);}}
.sc.pur .n{{color:var(--pur);}} .sc.org .n{{color:var(--org);}}
.sec{{background:var(--card);border:1px solid var(--bdr);border-radius:8px;margin-bottom:24px;overflow:hidden;}}
.sh{{padding:16px 20px;border-bottom:1px solid var(--bdr);font-size:16px;font-weight:600;display:flex;align-items:center;gap:8px;cursor:pointer;}}
.badge{{background:var(--blu);color:#fff;border-radius:12px;padding:2px 10px;font-size:12px;}}
.scon{{padding:16px 20px;}} .scon.hide{{display:none;}}
table{{width:100%;border-collapse:collapse;}}
th,td{{text-align:left;padding:10px 12px;border-bottom:1px solid var(--bdr);font-size:14px;}}
th{{color:var(--t2);font-weight:500;text-transform:uppercase;font-size:12px;}}
.sb{{display:inline-block;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:600;font-family:monospace;}}
.s2{{background:rgba(63,185,80,.15);color:var(--grn);}}
.s3{{background:rgba(88,166,255,.15);color:var(--blu);}}
.s4{{background:rgba(210,153,34,.15);color:var(--ylw);}}
.s5{{background:rgba(248,81,73,.15);color:var(--red);}}
.tt{{display:inline-block;background:rgba(188,140,255,.15);color:var(--pur);border-radius:4px;padding:2px 8px;font-size:11px;margin:2px;}}
.action-card{{background:var(--bg2);border:1px solid var(--bdr);border-radius:6px;padding:14px;margin-bottom:12px;border-left:3px solid var(--bdr);}}
.action-card.critical{{border-left-color:var(--red);}}
.action-card.high{{border-left-color:var(--org);}}
.action-card.medium{{border-left-color:var(--ylw);}}
.ah{{display:flex;gap:8px;align-items:center;margin-bottom:6px;}}
.pb{{padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;font-family:monospace;}}
.p1{{background:rgba(248,81,73,.2);color:var(--red);}}
.p2{{background:rgba(240,136,62,.2);color:var(--org);}}
.p3{{background:rgba(210,153,34,.2);color:var(--ylw);}}
.ac{{font-weight:600;font-size:13px;}} .at{{color:var(--t2);font-size:12px;}}
.ahost{{font-family:monospace;font-size:12px;color:var(--blu);margin-bottom:4px;word-break:break-all;}}
.ar{{font-size:13px;color:var(--t2);margin-bottom:8px;}}
.acmd{{background:var(--bg);border:1px solid var(--bdr);border-radius:4px;padding:10px;font-family:monospace;font-size:12px;white-space:pre-wrap;word-break:break-all;overflow-x:auto;}}
.an{{font-size:12px;color:var(--t2);margin-top:6px;font-style:italic;}}
.scard{{background:var(--bg2);border:1px solid var(--bdr);border-radius:6px;padding:12px;margin-bottom:10px;}}
.search{{width:100%;padding:10px 16px;background:var(--bg2);border:1px solid var(--bdr);border-radius:6px;color:var(--t1);font-size:14px;margin-bottom:16px;}}
.fb{{display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap;}}
.fbtn{{padding:6px 14px;border-radius:20px;border:1px solid var(--bdr);background:var(--bg2);color:var(--t2);cursor:pointer;font-size:13px;}}
.fbtn:hover,.fbtn.active{{border-color:var(--blu);color:var(--blu);background:rgba(88,166,255,.1);}}
.ssg{{display:grid;grid-template-columns:repeat(auto-fill,minmax(350px,1fr));gap:16px;}}
.ssc{{border:1px solid var(--bdr);border-radius:6px;overflow:hidden;}}
.ssc img{{width:100%;height:auto;display:block;}}
.ssc .cap{{padding:8px 12px;font-size:12px;color:var(--t2);background:var(--bg2);word-break:break-all;}}
</style></head><body>
<header><div class="ctr">
<h1>xLimit Recon - <span>{_html_escape(domain)}</span></h1>
<div class="ts">{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
</div></header>
<div class="ctr">

<div class="sg">
<div class="sc blu"><div class="n">{len(subdomains)}</div><div class="l">Subdomains</div></div>
<div class="sc grn"><div class="n">{len(live_hosts)}</div><div class="l">Live Hosts</div></div>
<div class="sc org"><div class="n">{len(triage_actions)}</div><div class="l">Triage Actions</div></div>
<div class="sc red"><div class="n">{len(p1)}</div><div class="l">P1 Critical</div></div>
<div class="sc pur"><div class="n">{tsec}</div><div class="l">JS Secrets</div></div>
<div class="sc ylw"><div class="n">{len(tech_summary)}</div><div class="l">Technologies</div></div>
</div>

<div class="sec"><div class="sh" onclick="tog(this)">
  Attack Playbook <span class="badge">{len(triage_actions)}</span></div>
<div class="scon">
{"".join(_action_html(a) for a in triage_actions) or '<p style="color:var(--t2)">No actionable items.</p>'}
</div></div>

{"" if not all_secrets else '<div class="sec"><div class="sh" onclick="tog(this)">JS Source Map Secrets <span class="badge">'+str(len(all_secrets))+'</span></div><div class="scon">' + "".join(f'<div class="scard"><strong style="color:var(--red)">[{_html_escape(f.severity.upper())}]</strong> {_html_escape(f.secret_type)}<br><code style="font-size:12px;color:var(--blu)">{_html_escape(f.url)}</code><br>File: <code>{_html_escape(f.source_file)}:{f.line_number}</code> | Entropy: {f.entropy}<br>Value: <code>{_html_escape(f.matched_value)}</code></div>' for f in all_secrets) + '</div></div>'}

<div class="sec"><div class="sh" onclick="tog(this)">
  Live Hosts <span class="badge">{len(httpx_data)}</span></div>
<div class="scon">
<input type="text" class="search" placeholder="Filter..." onkeyup="ft(this,'ht')">
<div class="fb">
<button class="fbtn active" onclick="fs(this,'all')">All</button>
<button class="fbtn" onclick="fs(this,'2')">2xx</button>
<button class="fbtn" onclick="fs(this,'3')">3xx</button>
<button class="fbtn" onclick="fs(this,'4')">4xx</button>
<button class="fbtn" onclick="fs(this,'5')">5xx</button>
</div>
<table id="ht"><thead><tr><th>Status</th><th>URL</th><th>Title</th><th>Server</th><th>Tech</th></tr></thead><tbody>
{"".join(f'<tr data-s="{e.get("status_code","?")}">'
    f'<td><span class="sb s{str(e.get("status_code","?"))[0]}">{e.get("status_code","?")}</span></td>'
    f'<td style="font-family:monospace;font-size:13px;word-break:break-all">'
    f'<a href="{_html_escape(e.get("url","#"))}" target="_blank" style="color:var(--blu);text-decoration:none">{_html_escape(e.get("url","?"))}</a></td>'
    f'<td>{_html_escape(e.get("title",""))}</td>'
    f'<td style="font-size:12px">{_html_escape(e.get("webserver",""))}</td>'
    f'<td>{"".join(f"<span class=tt>{_html_escape(t)}</span>" for t in e.get("tech",[]))}</td>'
    f'</tr>' for e in sorted(httpx_data, key=lambda x: x.get("status_code",999)))}
</tbody></table>
</div></div>

{"" if not screenshots else '<div class="sec"><div class="sh" onclick="tog(this)">Screenshots <span class="badge">'+str(len(screenshots))+'</span></div><div class="scon"><div class="ssg">' + "".join(f'<div class="ssc"><img src="{p}" alt="{n}" loading="lazy"><div class="cap">{n}</div></div>' for n,p in screenshots.items()) + '</div></div></div>'}

<div class="sec"><div class="sh" onclick="tog(this)">
  All Subdomains <span class="badge">{len(subdomains)}</span></div>
<div class="scon hide">
<input type="text" class="search" placeholder="Filter..." onkeyup="fl(this,'sl')">
<div id="sl" style="font-family:monospace;font-size:13px;max-height:400px;overflow-y:auto">
{"".join(f'<div class="se" style="padding:4px 0;border-bottom:1px solid var(--bdr)">{_html_escape(s)}</div>' for s in subdomains)}
</div></div></div>

</div>
<script>
function tog(h){{h.nextElementSibling.classList.toggle('hide')}}
function ft(i,id){{var f=i.value.toLowerCase(),rows=document.getElementById(id).getElementsByTagName('tr');for(var j=1;j<rows.length;j++)rows[j].style.display=rows[j].textContent.toLowerCase().includes(f)?'':'none'}}
function fs(b,s){{document.querySelectorAll('.fbtn').forEach(x=>x.classList.remove('active'));b.classList.add('active');document.querySelectorAll('#ht tbody tr').forEach(r=>r.style.display=s==='all'||r.dataset.s?.startsWith(s)?'':'none')}}
function fl(i,id){{var f=i.value.toLowerCase();document.querySelectorAll('#'+id+' .se').forEach(x=>x.style.display=x.textContent.toLowerCase().includes(f)?'':'none')}}
</script></body></html>'''

    rf.write_text(html)
    log_success(f"HTML dashboard: {rf}")




# ===========================================================================
# XLIMIT SUMMARY LAYER
# ===========================================================================

def _normalize_host(url: str) -> str:
    return (url or "").rstrip("/")


def _safe_hostname(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def _first_nonempty(*values):
    for value in values:
        if value:
            return value
    return ""


def _is_third_party_auth_front(title: str, tech: Set[str], server: str, url: str) -> bool:
    title_l = (title or "").lower()
    server_l = (server or "").lower()
    tech_l = {t.lower() for t in tech}
    url_l = (url or "").lower()
    hostname = _safe_hostname(url)

    title_indicators = [
        "sign in - google accounts",
        "google accounts",
        "authentication required",
        "sign in – google accounts",
    ]
    host_indicators = [
        "accounts.google.com",
        "okta.com",
        "auth0.com",
        "login.microsoftonline.com",
        "microsoftonline.com",
    ]
    tech_indicators = {"okta", "auth0", "vercel"}

    if any(ind in title_l for ind in title_indicators):
        return True
    if any(ind in url_l or ind in hostname for ind in host_indicators):
        return True
    if tech_l & tech_indicators and ("authentication required" in title_l or "sign in" in title_l):
        return True
    if "vercel" in tech_l and ("authentication required" in title_l or "access denied" in title_l):
        return True
    if "google" in title_l and "accounts" in title_l:
        return True
    return False


def infer_target_roles(url: str, title: str, tech: Set[str], server: str, action_categories: Set[str]) -> List[str]:
    url_l = (url or "").lower()
    title_l = (title or "").lower()
    server_l = (server or "").lower()
    roles = set()

    if any(k in url_l or k in title_l for k in ["admin", "dashboard", "panel", "portal", "backoffice", "manage"]):
        roles.add("admin_surface")
    if any(k in url_l or k in title_l for k in ["login", "signin", "auth", "account", "sso"]):
        roles.add("auth_surface")
    if any(ind in url_l or ind in title_l for ind in ["swagger", "graphql", "openapi", "/api/", "/v1/", "/v2/", "/rest/"]):
        roles.add("api_surface")
    if "graphql" in url_l or "graphql" in title_l or ("manual" in action_categories and "api_fuzz" in action_categories):
        roles.add("graphql_surface")
    if any("wordpress" in t or "joomla" in t for t in tech):
        roles.add("cms_surface")
    if any(any(x in t for x in ["tomcat", "spring", "java", "jboss", "weblogic", "wildfly", "jetty"]) for t in tech) or any(x in server_l for x in ["tomcat", "jetty"]):
        roles.add("java_surface")
    if any(any(x in t for x in ["jenkins", "jira", "confluence", "gitlab", "grafana", "kibana"]) for t in tech) or any(x in title_l for x in ["jenkins", "grafana", "kibana", "jira", "confluence"]):
        roles.add("control_plane_surface")
    if any(any(x in t for x in ["elasticsearch", "redis", "mongodb", "couchdb", "rabbitmq", "solr"]) for t in tech):
        roles.add("data_store_surface")
    if not roles and any(k in url_l for k in ["cdn", "static", "assets", "images"]):
        roles.add("asset_host")
    if not roles:
        roles.add("unknown_surface")
    return sorted(roles)



_ENV_TOKENS = {
    "dev", "stage", "staging", "test", "prod", "production", "nonprod", "preview",
    "localdev", "unstable", "stable", "demo", "qa", "uat", "preprod", "sandbox",
    "canary", "internal"
}

def _canonical_host_family(host: str) -> str:
    hostname = _safe_hostname(host)
    if not hostname:
        return host or ""
    labels = [lbl for lbl in hostname.split(".") if lbl]
    collapsed = []
    for lbl in labels:
        norm = re.sub(r"\d+$", "", lbl.lower())
        if norm in _ENV_TOKENS:
            continue
        collapsed.append(lbl.lower())
    return ".".join(collapsed[-5:]) if collapsed else hostname.lower()

def _select_diverse_targets(profiles: List[Dict[str, Any]], limit: int = 5, min_score: int = 0) -> List[Dict[str, Any]]:
    selected = []
    seen_families = set()
    for p in profiles:
        if p.get("score", 0) < min_score:
            continue
        family = _canonical_host_family(p.get("host", ""))
        if family and family in seen_families:
            continue
        seen_families.add(family)
        selected.append(p)
        if len(selected) >= limit:
            break
    return selected

def _score_host(profile: Dict[str, Any]) -> Tuple[int, List[str], List[str], List[str]]:
    score = 0
    why = []
    easy_wins = []
    deprioritize = []

    roles = set(profile["target_roles"])
    status = profile.get("status_code") or 0
    tech = set(profile.get("tech", []))
    action_counts = profile["action_counts"]
    categories = set(profile["categories"])
    secret_counts = profile["secret_severity_counts"]
    title = profile.get("title", "") or ""
    title_l = title.lower()
    server = profile.get("server", "") or ""
    url = profile.get("host", "") or profile.get("url", "") or ""
    url_l = url.lower()

    third_party_auth = _is_third_party_auth_front(title, tech, server, url)
    strong_categories = {"secret_followup", "api_fuzz", "actuator_probe", "jenkins_probe", "bypass_403", "error_probe", "manual"}
    has_meaningful_action = bool(strong_categories & categories)
    has_strong_js_secret = bool(secret_counts.get("critical", 0) or secret_counts.get("high", 0))

    product_title_indicators = [
        "site ctms", "portal", "admin", "strapi admin", "study devices",
        "brand portal", "graphql", "api", "dashboard"
    ]
    custom_403_titles = [
        "access forbidden", "forbidden", "checkpoint", "access denied", "verily - access forbidden"
    ]
    has_product_title = any(ind in title_l for ind in product_title_indicators)
    has_custom_403_title = any(ind in title_l for ind in custom_403_titles)
    interesting_403 = (
        status == 403 and (
            has_product_title
            or has_custom_403_title
            or "admin_surface" in roles
            or "api_surface" in roles
            or "java_surface" in roles
            or "control_plane_surface" in roles
            or any(cat in categories for cat in ["actuator_probe", "api_fuzz", "error_probe"])
            or any(any(x in t for x in ["java", "spring", "tomcat", "jenkins", "grafana", "kibana", "elasticsearch", "nginx"]) for t in tech)
        )
    )

    if "admin_surface" in roles:
        score += 18
        why.append("Admin-like surface detected")

    if "auth_surface" in roles:
        auth_points = 12
        if third_party_auth and not has_meaningful_action and not has_strong_js_secret:
            auth_points = 1
            deprioritize.append("Looks like a hosted or third-party authentication front")
        elif has_product_title:
            auth_points += 4
        score += auth_points
        if auth_points >= 8:
            why.append("Authentication surface detected")

    if "api_surface" in roles:
        score += 18
        why.append("API-like surface detected")
    if "graphql_surface" in roles:
        score += 10
        why.append("GraphQL/schema-enumeration path likely")
    if "control_plane_surface" in roles:
        score += 18
        why.append("High-value control plane / enterprise software surface")
    if "data_store_surface" in roles:
        score += 14
        why.append("Data-store or observability tech exposed")
    if "cms_surface" in roles:
        score += 12
        why.append("CMS surface detected")
    if roles == {"unknown_surface"}:
        score += 2

    if has_product_title and not third_party_auth:
        score += 8
        why.append("Target-owned product or portal title detected")

    if interesting_403:
        score += 8
        why.append("Restricted behavior on a meaningful-looking surface")
    elif status == 403:
        score += 2

    if 500 <= status < 600:
        score += 9
        why.append(f"Server error ({status}) may leak debug or internal behavior")
    if status in {301, 302, 307, 308}:
        score += 2
    if profile.get("nmap_selected"):
        score += 8
        why.append("Selected for port scanning due to interesting indicators")

    content_type = (profile.get("content_type") or "").lower()
    large_sensitive_surface = (
        (profile.get("content_length") or 0) > 900000
        and (
            "api_surface" in roles
            or "admin_surface" in roles
            or "graphql_surface" in roles
            or "java_surface" in roles
            or any(x in content_type for x in ["json", "xml", "text", "csv"])
            or any(cat in categories for cat in ["error_probe", "api_fuzz", "actuator_probe"])
        )
        and not third_party_auth
    )
    if large_sensitive_surface:
        score += 4
        why.append("Large response on a sensitive-looking surface is worth reviewing")

    if any(any(x in t for x in ["jenkins", "elasticsearch", "kibana", "grafana"]) for t in tech):
        score += 12
    if any(any(x in t for x in ["tomcat", "spring", "java", "jboss", "weblogic", "wildfly", "jetty"]) for t in tech):
        score += 10
    if any(any(x in t for x in ["node", "express", "next.js", "nuxt", "koa"]) for t in tech):
        score += 7
    if any(any(x in t for x in ["php", "laravel", "symfony", "codeigniter"]) for t in tech):
        score += 6
    if any(any(x in t for x in ["wordpress", "joomla"]) for t in tech):
        score += 6

    p_action_score = action_counts.get("p1", 0) * 10 + action_counts.get("p2", 0) * 5 + action_counts.get("p3", 0) * 2
    if status == 403 and not interesting_403 and categories.issubset({"bypass_403", "dir_bruteforce"}):
        p_action_score = min(p_action_score, 6)
    score += min(25, p_action_score)

    if secret_counts.get("critical", 0):
        score += 30
        why.append("Critical JS/source-map secret leaked on this host")
        easy_wins.append("Validate leaked critical secret and map impact")
    elif secret_counts.get("high", 0):
        score += 22
        why.append("High-severity JS/source-map secret leaked on this host")
        easy_wins.append("Review leaked secret and associated app behavior")
    elif secret_counts.get("medium", 0):
        score += 12
        why.append("Medium-severity JS/source-map secret leaked on this host")
    elif secret_counts.get("low", 0):
        score += 5

    if ("admin_surface" in roles or "auth_surface" in roles) and interesting_403:
        score += 6
        easy_wins.append("Try 403 bypasses before going broader")
    if "api_surface" in roles and "api_fuzz" in categories:
        score += 10
        why.append("API surface already has concrete route-discovery actions")
        easy_wins.append("Fuzz undocumented routes and compare auth states")
    if "graphql_surface" in roles:
        score += 8
        easy_wins.append("Attempt GraphQL introspection or schema discovery")
    if "java_surface" in roles and "actuator_probe" in categories:
        score += 8
        easy_wins.append("Probe actuator/debug endpoints")
    if "control_plane_surface" in roles and ({"jenkins_probe", "data_exposure", "actuator_probe"} & categories):
        score += 10
        easy_wins.append("Check anonymous access and exposed admin/data endpoints")

    generic = {"vuln_scan", "dir_bruteforce", "data_exposure"}
    if categories and categories.issubset(generic) and action_counts.get("p1", 0) == 0 and action_counts.get("p2", 0) == 0:
        score -= 12
        deprioritize.append("Only generic scan and enumeration signals present")
    if categories == {"dir_bruteforce"} and action_counts.get("p3", 0) <= 1 and roles == {"unknown_surface"}:
        score -= 15
        deprioritize.append("Only baseline brute-force signal with no supporting indicators")
    if roles == {"asset_host"}:
        score -= 12
        deprioritize.append("Looks like a static or asset host")
    if categories == {"open_redirect"}:
        score -= 8
        deprioritize.append("Only redirect-like behavior with no corroborating signal")
    if categories == {"vuln_scan"}:
        score -= 6
        deprioritize.append("Only generic nuclei suggestion with no stronger signal")
    if status == 404 and not categories:
        score -= 6
        deprioritize.append("404-style host with no supporting signals")
    if status == 403 and not interesting_403:
        score -= 8
        deprioritize.append("Plain 403 with no strong supporting indicators")
    if third_party_auth and not has_meaningful_action and not has_strong_js_secret:
        score -= 10

    score = max(0, min(100, score))
    why = list(dict.fromkeys(why))[:5]
    easy_wins = list(dict.fromkeys(easy_wins))[:4]
    deprioritize = list(dict.fromkeys(deprioritize))[:3]
    return score, why, easy_wins, deprioritize


def _priority_tier(score: int) -> str:
    if score >= 80:
        return "focus_now"
    if score >= 60:
        return "investigate_next"
    if score >= 40:
        return "keep_warm"
    return "deprioritize"


def _recommended_first_steps(profile: Dict[str, Any]) -> List[str]:
    categories = set(profile["categories"])
    roles = set(profile["target_roles"])
    steps = []
    if "secret_followup" in categories:
        steps.append("Validate leaked secret context and determine reachable impact")
    if "bypass_403" in categories:
        steps.append("Try 403 bypass variations before wider enumeration")
    if "api_fuzz" in categories:
        steps.append("Fuzz undocumented API routes and compare auth states")
    if "graphql_surface" in roles:
        steps.append("Attempt GraphQL introspection or schema discovery")
    if "auth_test" in categories:
        steps.append("Review login flow behavior and weak/default credential exposure")
    if "actuator_probe" in categories:
        steps.append("Probe Spring actuator and debug endpoints")
    if "jenkins_probe" in categories:
        steps.append("Check Jenkins anonymous-access paths and administrative endpoints")
    if "data_exposure" in categories:
        steps.append("Check for unauthenticated data exposure before brute-forcing more")
    if "error_probe" in categories:
        steps.append("Trigger controlled error cases and capture stack traces or internal paths")
    if "dir_bruteforce" in categories and len(steps) < 3:
        steps.append("Enumerate focused paths that match the detected stack or app role")
    return list(dict.fromkeys(steps))[:4]


def build_xlimit_summary(domain, subdomains, live_hosts, httpx_data, triage_actions, tech_results, js_findings, nmap_results, output_dir):
    log_info("Generating xLimit summary...")
    actions_by_host = defaultdict(list)
    for action in triage_actions or []:
        actions_by_host[_normalize_host(action.host)].append(action)

    js_by_host = defaultdict(list)
    for scan_result in js_findings or []:
        for finding in getattr(scan_result, 'findings', []):
            js_by_host[_normalize_host(finding.url)].append(finding)

    whatweb_by_host = defaultdict(set)
    for ww_url, ww_techs in (tech_results or {}).items():
        hostname = _safe_hostname(ww_url)
        if hostname:
            whatweb_by_host[hostname].update((t or "").lower() for t in ww_techs)

    profiles = []
    for entry in httpx_data or []:
        url = _normalize_host(entry.get("url", ""))
        if not url:
            continue
        hostname = _safe_hostname(url)
        actions = actions_by_host.get(url, [])
        findings = js_by_host.get(url, [])
        tech = set((t or "").lower() for t in entry.get("tech", []))
        tech.update(whatweb_by_host.get(hostname, set()))
        action_counts = {
            "p1": sum(1 for a in actions if a.priority == 1),
            "p2": sum(1 for a in actions if a.priority == 2),
            "p3": sum(1 for a in actions if a.priority == 3),
        }
        secret_counts = Counter((f.severity or "").lower() for f in findings)
        categories = sorted({a.category for a in actions})
        roles = infer_target_roles(url, entry.get("title", ""), tech, entry.get("webserver", ""), set(categories))
        profile = {
            "host": url,
            "hostname": hostname,
            "status_code": entry.get("status_code"),
            "title": entry.get("title", "") or "",
            "server": entry.get("webserver", "") or "",
            "content_type": entry.get("content_type", "") or "",
            "content_length": int(entry.get("content_length", 0) or 0),
            "tech": sorted(tech),
            "target_roles": roles,
            "categories": categories,
            "action_counts": action_counts,
            "js_secrets_count": len(findings),
            "secret_severity_counts": dict(secret_counts),
            "nmap_selected": hostname in (nmap_results or {}),
            "nmap_reasons": (nmap_results or {}).get(hostname, {}).get("reasons", []),
            "example_actions": [
                {
                    "category": a.category,
                    "priority": a.priority,
                    "tool": a.tool,
                    "reason": a.reason,
                    "example_command": next((ln.strip() for ln in a.command.splitlines() if ln.strip() and not ln.strip().startswith('#')), ""),
                }
                for a in actions[:5]
            ],
            "js_secrets_preview": [
                {
                    "secret_type": f.secret_type,
                    "severity": f.severity,
                    "source_file": f.source_file,
                    "matched_value": f.matched_value,
                    "line_number": f.line_number,
                }
                for f in findings[:5]
            ],
        }
        score, why, easy_wins, deprioritize = _score_host(profile)
        profile["score"] = score
        profile["priority_tier"] = _priority_tier(score)
        profile["why_it_matters"] = why
        profile["easy_wins"] = easy_wins
        profile["deprioritize_reasons"] = deprioritize
        profile["recommended_first_steps"] = _recommended_first_steps(profile)
        profile["summary"] = _first_nonempty("; ".join(why[:2]), "Interesting host with recon signals worth reviewing")
        profile["xlimit_prompt_hint"] = (
            f"This host is ranked {profile['priority_tier']} with score {score}. "
            f"Help prioritize the best manual checks and likely high-value paths."
        )
        profiles.append(profile)

    profiles.sort(key=lambda x: (-x["score"], x["host"]))

    ranked_non_deprioritized = _select_diverse_targets(
        [p for p in profiles if p["priority_tier"] != "deprioritize"],
        limit=5,
        min_score=20,
    )
    best_available = []
    if not ranked_non_deprioritized:
        fallback_candidates = _select_diverse_targets(profiles, limit=5, min_score=10)
        for p in fallback_candidates:
            clone = dict(p)
            clone["priority_tier"] = "best_available"
            clone["xlimit_prompt_hint"] = "This host is one of the best available leads from a low-signal scan. Help decide whether it is worth manual time."
            best_available.append(clone)

    top_source = ranked_non_deprioritized if ranked_non_deprioritized else best_available
    top_targets = [
        {
            "rank": idx + 1,
            "host": p["host"],
            "hostname": p["hostname"],
            "score": p["score"],
            "priority_tier": p["priority_tier"],
            "target_role": p["target_roles"],
            "why_it_matters": p["why_it_matters"],
            "signals": {
                "status_code": p["status_code"],
                "title": p["title"],
                "server": p["server"],
                "tech": p["tech"][:10],
                "js_secrets": p["js_secrets_count"],
                "nmap_selected": p["nmap_selected"],
                "action_counts": p["action_counts"],
                "categories": p["categories"],
            },
            "recommended_first_steps": p["recommended_first_steps"],
            "xlimit_prompt_hint": p["xlimit_prompt_hint"],
        }
        for idx, p in enumerate(top_source)
    ]

    focus_now = [p["host"] for p in _select_diverse_targets([p for p in profiles if p["priority_tier"] == "focus_now"], limit=5)]
    investigate_next = [p["host"] for p in _select_diverse_targets([p for p in profiles if p["priority_tier"] == "investigate_next"], limit=5)]
    keep_warm = [p["host"] for p in _select_diverse_targets([p for p in profiles if p["priority_tier"] == "keep_warm"], limit=5)]
    deprioritize_now = [] if best_available else [p["host"] for p in profiles if p["priority_tier"] == "deprioritize"][:5]

    easy_wins = []
    for p in profiles[:8]:
        easy_wins.extend(p.get("easy_wins", []))
    easy_wins = list(dict.fromkeys(easy_wins))[:6]

    action_clusters = []
    cluster_defs = {
        "auth_and_admin": ("auth_surface", "admin_surface"),
        "api_and_graphql": ("api_surface", "graphql_surface"),
        "control_planes": ("control_plane_surface", "java_surface", "data_store_surface"),
        "cms_targets": ("cms_surface",),
        "secret_bearing_hosts": tuple(),
    }
    descriptions = {
        "auth_and_admin": ("Hosts exposing login, admin, panel, portal, or dashboard indicators.", "Often high business impact and frequently underexplored compared to broad bruteforce."),
        "api_and_graphql": ("Hosts with API, Swagger, OpenAPI, or GraphQL signals.", "Can lead to authz issues, undocumented endpoints, and data exposure."),
        "control_planes": ("Enterprise software, Java stack, or datastore/observability surfaces.", "These can expose powerful admin paths, debug endpoints, or unauthenticated data access."),
        "cms_targets": ("CMS-backed targets like WordPress or Joomla.", "Good candidates for plugin/theme exposure, backups, and common weak paths."),
        "secret_bearing_hosts": ("Hosts with leaked source-map secrets after stricter filtering.", "Validate these early because they can create fast, high-signal pivots."),
    }
    for cluster_name, role_set in cluster_defs.items():
        if cluster_name == "secret_bearing_hosts":
            hosts = [p["host"] for p in _select_diverse_targets([p for p in profiles if p["js_secrets_count"] > 0], limit=10)]
        else:
            hosts = [p["host"] for p in _select_diverse_targets([p for p in profiles if set(p["target_roles"]) & set(role_set)], limit=10)]
        if hosts:
            desc, reason = descriptions[cluster_name]
            action_clusters.append({
                "cluster": cluster_name,
                "description": desc,
                "hosts": hosts,
                "reason_to_prioritize": reason,
            })

    summary = {
        "metadata": {
            "tool": "xLimit Recon",
            "summary_type": "xlimit_recon_summary",
            "target": domain,
            "generated_at": datetime.datetime.now().isoformat(),
            "version": "1.3",
            "scan_scope": {
                "subdomains_total": len(subdomains or []),
                "live_hosts_total": len(live_hosts or []),
                "httpx_entries_total": len(httpx_data or []),
                "js_secret_findings_total": sum(len(getattr(r, 'findings', [])) for r in (js_findings or [])),
                "triage_actions_total": len(triage_actions or []),
                "nmap_hosts_total": len(nmap_results or {}),
            },
        },
        "global_assessment": {
            "focus_now": focus_now,
            "investigate_next": investigate_next,
            "keep_warm": keep_warm,
            "best_available": [p["host"] for p in best_available][:5],
            "deprioritize_for_now": deprioritize_now,
            "priority_rationale": [p["summary"] for p in top_source[:3]],
            "easy_wins": easy_wins,
        },
        "top_targets": top_targets,
        "host_summaries": [
            {
                "host": p["host"],
                "score": p["score"],
                "priority_tier": ("best_available" if best_available and any(bp["host"] == p["host"] for bp in best_available) else p["priority_tier"]),
                "target_role": p["target_roles"],
                "summary": p["summary"],
                "signals": {
                    "status_code": p["status_code"],
                    "title": p["title"],
                    "tech": p["tech"][:10],
                    "categories": p["categories"],
                    "js_secrets": p["js_secrets_count"],
                    "action_counts": p["action_counts"],
                },
                "recommended_first_steps": p["recommended_first_steps"],
                "deprioritize_reasons": p["deprioritize_reasons"],
            }
            for p in profiles
        ],
        "action_clusters": action_clusters,
        "xlimit_prompt_stub": "Based on this recon summary, rank the top targets by likely bug bounty value, explain why they matter, identify easy wins vs rabbit holes, and suggest the best next manual checks for the top 3 hosts.",
        "raw_priority_inputs": {
            "playbook_actions": [asdict(a) for a in (triage_actions or [])],
            "js_findings": [asdict(f) for r in (js_findings or []) for f in getattr(r, 'findings', [])],
            "nmap_reasons": {h: v.get("reasons", []) for h, v in (nmap_results or {}).items()},
        },
    }

    json_path = output_dir / "xlimit_summary.json"
    json_path.write_text(json.dumps(summary, indent=2))

    lines = [
        "xLimit Recon Summary",
        f"Target: {domain}",
        f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "Overview",
        f"- Subdomains: {len(subdomains or [])}",
        f"- Live hosts: {len(live_hosts or [])}",
        f"- Triage actions: {len(triage_actions or [])}",
        f"- JS secret findings: {sum(len(getattr(r, 'findings', [])) for r in (js_findings or []))}",
        f"- Nmap-selected hosts: {len(nmap_results or {})}",
        "",
        "Focus first",
    ]
    if not top_source:
        lines.append("- No meaningful targets found.")
    else:
        if best_available and not ranked_non_deprioritized:
            lines.append("- No high-confidence targets found. Best available leads:")
        for idx, p in enumerate(top_source, 1):
            lines.append(f"{idx}. {p['host']}  [score: {p['score']}]")
            if p["why_it_matters"]:
                lines.append("   Why:")
                for reason in p["why_it_matters"][:3]:
                    lines.append(f"   - {reason}")
            if p["recommended_first_steps"]:
                lines.append("   First steps:")
                for step in p["recommended_first_steps"][:3]:
                    lines.append(f"   - {step}")
            lines.append("")
    if not best_available:
        lines.append("Deprioritize for now")
        low = [p for p in profiles if p["priority_tier"] == "deprioritize"][:5]
        if not low:
            lines.append("- None")
        else:
            for p in low:
                reason = "; ".join(p["deprioritize_reasons"][:2]) or "Low-signal host"
                lines.append(f"- {p['host']}")
                lines.append(f"  {reason}")
    lines.extend([
        "",
        "Prompt to paste into xLimit",
        "Based on this recon summary, where should I focus first, why, and what are the best next manual checks for the top targets before going broader?",
        "",
    ])
    txt_path = output_dir / "xlimit_summary.txt"
    txt_path.write_text("\n".join(lines))
    log_success(f"xLimit JSON summary: {json_path}")
    log_success(f"xLimit text summary: {txt_path}")
    return summary
# ===========================================================================
# MONITORING MODE
# ===========================================================================

def monitor_mode(domain, interval_hours=6, deep=False, run_nmap=False):
    log_phase(f"MONITOR MODE - {domain} every {interval_hours}h")
    state_dir = BASE_OUTPUT_DIR / f".monitor_{domain}"
    state_dir.mkdir(parents=True, exist_ok=True)
    state_file = state_dir / "previous_state.json"

    prev = {}
    if state_file.exists():
        try: prev = json.loads(state_file.read_text())
        except: pass

    while True:
        log_info(f"Cycle at {datetime.datetime.now().strftime('%H:%M:%S')}...")
        od = ensure_output_dir(domain)
        subs = subdomain_enumeration(domain, od, deep=deep)
        live, hdata = live_host_detection(subs, od)

        ns = set(subs) - set(prev.get("subdomains", []))
        nh = set(live) - set(prev.get("live_hosts", []))
        if ns:
            print(f"\n{Colors.GREEN}{Colors.BOLD}NEW SUBDOMAINS:{Colors.END}")
            for s in sorted(ns): print(f"  {Colors.GREEN}+ {s}{Colors.END}")
        if nh:
            print(f"\n{Colors.GREEN}{Colors.BOLD}NEW LIVE HOSTS:{Colors.END}")
            for h in sorted(nh): print(f"  {Colors.GREEN}+ {h}{Colors.END}")
        if not (ns or nh): log_info("No changes.")

        state_file.write_text(json.dumps({
            "subdomains": subs, "live_hosts": live,
            "last_scan": datetime.datetime.now().isoformat()}, indent=2))

        tech = technology_fingerprint(live, od)
        jsf = js_map_scan_phase(live, od)
        nmap = selective_port_scan(hdata, od) if run_nmap else {}
        ta = triage_engine(hdata, tech, nmap, jsf, od)
        generate_text_report(domain, subs, live, hdata, ta, tech, jsf, od)
        generate_json_report(domain, subs, live, hdata, ta, tech, jsf, nmap, od)
        generate_html_report(domain, subs, live, hdata, ta, tech, jsf, od)
        build_xlimit_summary(domain, subs, live, hdata, ta, tech, jsf, nmap, od)

        log_info(f"Next scan in {interval_hours}h. Ctrl+C to stop.")
        try: time.sleep(interval_hours * 3600)
        except KeyboardInterrupt: log_info("Monitor stopped."); break


# ===========================================================================
# PRE-FLIGHT & MAIN
# ===========================================================================

def preflight_check():
    log_phase("PRE-FLIGHT CHECK")
    ok = True
    for t in TOOLS_REQUIRED:
        if check_tool(t): log_success(f"{t} ok")
        else: log_error(f"{t} MISSING (required)"); ok = False
    for t in TOOLS_OPTIONAL:
        if check_tool(t): log_success(f"{t} ok")
        else: log_warning(f"{t} missing (optional)")
    print()
    for name, path in WORDLISTS.items():
        if Path(path).exists(): log_success(f"Wordlist {name}: {path}")
        else: log_warning(f"Wordlist {name}: NOT FOUND ({path})")
    print()
    if HAS_REQUESTS: log_success("Python: requests ok")
    else: log_warning("Python: requests missing (JS scan disabled)")
    if HAS_BS4: log_success("Python: beautifulsoup4 ok")
    else: log_warning("Python: beautifulsoup4 missing (regex fallback)")
    if not ok:
        log_error("Missing required tools."); sys.exit(1)
    print()


def main():
    print(BANNER)
    parser = argparse.ArgumentParser(
        description="xLimit Recon by w1j0y - Automated Bug Bounty Recon & Triage Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 xlimit_recon.py -d example.com                     Basic scan
  python3 xlimit_recon.py -d example.com --deep               Deep enumeration
  python3 xlimit_recon.py -d example.com --deep --run-nmap    Deep + port scanning
  python3 xlimit_recon.py --scope scope.csv                   Multi-domain from HackerOne CSV
  python3 xlimit_recon.py --scope scope.csv --bounty-only     Only bounty-eligible targets
  python3 xlimit_recon.py -d example.com --monitor            Continuous monitoring
  python3 xlimit_recon.py -d example.com --custom-header "X-Bug-Bounty: researcher123"
  python3 xlimit_recon.py -d example.com --skip-js-scan       Skip JS source map scanning
        """)
    parser.add_argument("-d", "--domain", help="Target domain")
    parser.add_argument("--scope", help="HackerOne scope CSV")
    parser.add_argument("--bounty-only", action="store_true")
    parser.add_argument("--deep", action="store_true", help="Deep enumeration")
    parser.add_argument("--monitor", action="store_true")
    parser.add_argument("--interval", type=int, default=6, help="Monitor hours (default: 6)")
    parser.add_argument("--custom-header", default="", help="Optional custom header applied to live requests and generated commands, format: 'Header-Name: value'")
    parser.add_argument("--skip-screenshots", action="store_true")
    parser.add_argument("--skip-js-scan", action="store_true")
    parser.add_argument("--run-nmap", action="store_true", help="Enable selective nmap")
    parser.add_argument("--nmap-aggressive", action="store_true")
    parser.add_argument("--js-threads", type=int, default=10)
    parser.add_argument("--output", help="Custom output dir")
    args = parser.parse_args()

    if not args.domain and not args.scope:
        parser.error("Either --domain or --scope required")

    if args.output:
        global BASE_OUTPUT_DIR
        BASE_OUTPUT_DIR = Path(args.output)

    try:
        set_custom_header(args.custom_header)
    except ValueError as e:
        parser.error(str(e))

    preflight_check()

    # Determine targets
    domains = []; oos = []
    if args.scope:
        sd = parse_hackerone_scope(args.scope, bounty_only=args.bounty_only)
        domains = sorted(sd["domains"]); oos = sd["out_of_scope"]
        sdir = BASE_OUTPUT_DIR / "scope_summary"; sdir.mkdir(parents=True, exist_ok=True)
        (sdir / "domains.txt").write_text("\n".join(domains))
        (sdir / "urls.txt").write_text("\n".join(sorted(sd["urls"])))
        (sdir / "wildcards.txt").write_text("\n".join(sd["wildcards"]))
        (sdir / "out_of_scope.txt").write_text("\n".join(oos))
    elif args.domain:
        domains = [args.domain]

    if args.monitor:
        if len(domains) > 1: log_warning("Monitor: using first domain only.")
        monitor_mode(domains[0], args.interval, deep=args.deep,
                     run_nmap=args.run_nmap)
        return

    # Scan each domain
    all_results = {}
    for i, domain in enumerate(domains, 1):
        if len(domains) > 1: log_phase(f"TARGET {i}/{len(domains)}: {domain}")
        od = ensure_output_dir(domain)
        log_info(f"Output: {od}")

        # Phase 1
        subs = subdomain_enumeration(domain, od, deep=args.deep)
        if oos: subs = filter_out_of_scope(subs, oos)

        # Phase 2
        live, hdata = live_host_detection(subs, od)
        if oos: live = filter_out_of_scope(live, oos)

        # Phase 3
        if not args.skip_screenshots: take_screenshots(live, od)

        # Phase 4
        tech = technology_fingerprint(live, od)

        # Phase 5
        jsf = []
        if not args.skip_js_scan:
            jsf = js_map_scan_phase(live, od, threads=args.js_threads)

        # Phase 6
        nmap = {}
        if args.run_nmap:
            nmap = selective_port_scan(hdata, od, aggressive=args.nmap_aggressive)

        # Phase 7 - THE MONEY PHASE
        ta = triage_engine(hdata, tech, nmap, jsf, od)

        # Phase 8
        log_phase("PHASE 8: Report Generation")
        generate_text_report(domain, subs, live, hdata, ta, tech, jsf, od)
        generate_json_report(domain, subs, live, hdata, ta, tech, jsf, nmap, od)
        generate_html_report(domain, subs, live, hdata, ta, tech, jsf, od)
        build_xlimit_summary(domain, subs, live, hdata, ta, tech, jsf, nmap, od)

        all_results[domain] = {
            "subdomains": len(subs), "live_hosts": len(live),
            "triage_actions": len(ta),
            "p1_actions": len([a for a in ta if a.priority == 1]),
            "js_secrets": sum(r.secrets_found for r in jsf),
            "output_dir": str(od),
        }

    # Final summary
    log_phase("RECON COMPLETE")
    if len(all_results) > 1:
        print(f"  Scanned {len(all_results)} domains:\n")
        for dom, st in all_results.items():
            flag = " !!" if st["p1_actions"] > 0 else ""
            print(f"  {dom}{flag}")
            print(f"    Subs: {st['subdomains']} | Live: {st['live_hosts']} | "
                  f"Actions: {st['triage_actions']} (P1: {st['p1_actions']}) | "
                  f"Secrets: {st['js_secrets']}")
            print(f"    Output: {st['output_dir']}")
            if CUSTOM_HEADER:
                print(f"    Header: {CUSTOM_HEADER}\n")
            else:
                print()
    else:
        dom = domains[0]; st = all_results[dom]
        print(f"  Target:         {dom}")
        print(f"  Subdomains:     {st['subdomains']}")
        print(f"  Live hosts:     {st['live_hosts']}")
        print(f"  Triage actions: {st['triage_actions']} (P1: {st['p1_actions']})")
        print(f"  JS secrets:     {st['js_secrets']}")
        print(f"  Output:         {st['output_dir']}")
        print()
        print(f"  Text report:      {st['output_dir']}/report.txt")
        print(f"  JSON data:        {st['output_dir']}/report.json")
        print(f"  HTML dashboard:   {st['output_dir']}/dashboard.html")
        print(f"  Playbook (JSON):  {st['output_dir']}/playbook.json")
        print(f"  Playbook (shell): {st['output_dir']}/playbook_commands.sh")
        print(f"  xLimit JSON:      {st['output_dir']}/xlimit_summary.json")
        print(f"  xLimit text:      {st['output_dir']}/xlimit_summary.txt")
        if CUSTOM_HEADER:
            print(f"  Active header:    {CUSTOM_HEADER}")
    print()



if __name__ == "__main__":
    main()
