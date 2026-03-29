#!/usr/bin/env python3
# ============================================================
# VisionX OS — Target Profiler
# /usr/local/lib/visionx/python/profile.py
# ============================================================

import subprocess
import sys
import socket
import requests
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

R = Fore.RED + Style.BRIGHT
G = Fore.GREEN + Style.BRIGHT
Y = Fore.YELLOW + Style.BRIGHT
C = Fore.CYAN + Style.BRIGHT
W = Fore.WHITE + Style.BRIGHT
DIM = Style.DIM
NC = Style.RESET_ALL

def banner():
    print(f"\n{R}{'='*46}")
    print(f"  VisionX OS - Target Profiler")
    print(f"{'='*46}{NC}")

def section(title):
    print(f"\n{C}-- {title} --{NC}")

def found(msg):   print(f"  {G}[+]{NC} {msg}")
def warn(msg):    print(f"  {Y}[!]{NC} {msg}")
def info(msg):    print(f"  {C}[~]{NC} {msg}")
def suggest(msg): print(f"  {G}[>]{NC} {msg}")
def error(msg):   print(f"  {R}[x]{NC} {msg}")

def run_cmd(cmd):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        return result.stdout.strip()
    except Exception:
        return ""

# ── 1. DNS & IP Info ─────────────────────────────────────────
def get_dns_info(target):
    section("DNS & IP Information")
    results = {}

    info("Resolving target...")
    ip = run_cmd(f"dig +short {target} @8.8.8.8")
    if ip:
        found(f"IP Address: {ip.split()[0]}")
        results['ip'] = ip.split()[0]
    else:
        warn("Could not resolve target")
        results['ip'] = None

    # PTR record
    if results.get('ip'):
        ptr = run_cmd(f"dig +short -x {results['ip']} @8.8.8.8")
        if ptr:
            found(f"PTR Record: {ptr}")
            results['ptr'] = ptr

    # MX records
    mx = run_cmd(f"dig +short MX {target} @8.8.8.8")
    if mx:
        found(f"Mail Server: {mx.split()[1] if len(mx.split()) > 1 else mx}")
        results['mx'] = mx

    # TXT records
    txt = run_cmd(f"dig +short TXT {target} @8.8.8.8")
    if txt:
        for record in txt.split('\n')[:3]:
            if record:
                found(f"TXT: {record[:60]}")

    return results

# ── 2. Web Stack Detection ────────────────────────────────────
def get_web_stack(target):
    section("Web Stack Detection")
    results = {}

    info("Fetching HTTP headers...")
    try:
        r = requests.get(f"http://{target}", timeout=10, allow_redirects=True)
        headers = r.headers

        # Server
        server = headers.get('Server', '')
        if server:
            found(f"Server: {server}")
            results['server'] = server

        # Powered by
        powered = headers.get('X-Powered-By', '')
        if powered:
            found(f"Powered By: {powered}")
            results['powered_by'] = powered

        # Framework detection from headers
        if 'wp-' in r.text.lower() or 'wordpress' in r.text.lower():
            found("CMS: WordPress detected")
            results['cms'] = 'WordPress'
            suggest(f"Run: visionx web scan {target} (wpscan)")
        elif 'joomla' in r.text.lower():
            found("CMS: Joomla detected")
            results['cms'] = 'Joomla'
        elif 'drupal' in r.text.lower():
            found("CMS: Drupal detected")
            results['cms'] = 'Drupal'

        # Security headers check
        print()
        info("Checking security headers...")
        security_headers = [
            'Strict-Transport-Security',
            'X-Frame-Options',
            'X-Content-Type-Options',
            'Content-Security-Policy',
            'X-XSS-Protection'
        ]
        for h in security_headers:
            if h in headers:
                found(f"✔ {h}")
            else:
                warn(f"✘ Missing: {h}")

        results['status_code'] = r.status_code
        found(f"HTTP Status: {r.status_code}")

    except requests.exceptions.ConnectionError:
        warn("Could not connect to HTTP — target may be down or HTTPS only")
        try:
            r = requests.get(f"https://{target}", timeout=10, verify=False)
            found(f"HTTPS Status: {r.status_code}")
        except Exception:
            error("Could not connect to target")
    except Exception as e:
        warn(f"HTTP check failed: {str(e)[:50]}")

    return results

# ── 3. WAF & CDN Detection ────────────────────────────────────
def get_waf_cdn(target):
    section("WAF & CDN Detection")
    results = {}

    info("Running wafw00f...")
    waf = run_cmd(f"wafw00f http://{target} 2>/dev/null")
    if waf:
        for line in waf.split('\n'):
            if 'is behind' in line or 'No WAF' in line:
                found(line.strip())
                results['waf'] = line.strip()

    # CDN detection via IP
    info("Checking for CDN...")
    ip = run_cmd(f"dig +short {target} @8.8.8.8")
    cdn_ranges = {
        'Cloudflare': ['104.16.', '104.17.', '104.18.', '104.19.', '104.20.',
                      '104.21.', '172.64.', '172.65.', '172.66.', '172.67.'],
        'Fastly':     ['151.101.'],
        'Akamai':     ['23.32.', '23.64.', '23.192.'],
        'AWS CloudFront': ['13.32.', '13.35.', '54.182.', '54.192.'],
    }
    detected_cdn = None
    for cdn, ranges in cdn_ranges.items():
        for r in ranges:
            if ip.startswith(r):
                found(f"CDN: {cdn} detected")
                detected_cdn = cdn
                results['cdn'] = cdn
                break

    if not detected_cdn:
        info("No known CDN detected")

    return results

# ── 4. Port Summary ───────────────────────────────────────────
def get_port_summary(target):
    section("Open Ports Summary")
    results = {}

    info("Running quick port scan...")
    nmap_out = run_cmd(f"nmap -T4 --top-ports 100 {target} 2>/dev/null")

    open_ports = []
    for line in nmap_out.split('\n'):
        if '/tcp' in line and 'open' in line:
            parts = line.split()
            port = parts[0]
            service = parts[2] if len(parts) > 2 else 'unknown'
            open_ports.append((port, service))
            found(f"Port {port} ({service})")

    if not open_ports:
        warn("No open ports found")

    results['ports'] = open_ports
    return results

# ── 5. Tool Suggestions ───────────────────────────────────────
def get_tool_suggestions(target, dns_results, web_results, waf_results, port_results):
    section("Suggested Next Steps")

    ports = [p[0].split('/')[0] for p in port_results.get('ports', [])]
    cms = web_results.get('cms', '')
    cdn = waf_results.get('cdn', '')

    if '80' in ports or '443' in ports:
        suggest(f"visionx web recon {target}   — web reconnaissance")
        suggest(f"visionx web scan {target}    — web vulnerability scan")

    if cms == 'WordPress':
        suggest(f"wpscan --url http://{target} --enumerate vp  — scan WordPress plugins")

    if '22' in ports:
        suggest(f"hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://{target}")

    if '21' in ports:
        suggest(f"hydra -l anonymous -p anonymous ftp://{target}")

    if '445' in ports:
        suggest(f"visionx exploit run ms17-010 {target}")

    if cdn:
        warn(f"Target is behind {cdn} — some scans may be blocked or return CDN IP")

    suggest(f"visionx autopwn {target}    — run full automated pipeline")
    suggest(f"visionx report {target}     — generate full report")

# ── Main ──────────────────────────────────────────────────────
def profile(target):
    banner()
    print(f"\n  {W}Target: {C}{target}{NC}")
    print(f"  {W}Time:   {DIM}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{NC}")
    print(f"\n  {R}[!] Only profile targets you own or have permission to test.{NC}\n")

    dns_results  = get_dns_info(target)
    web_results  = get_web_stack(target)
    waf_results  = get_waf_cdn(target)
    port_results = get_port_summary(target)
    get_tool_suggestions(target, dns_results, web_results, waf_results, port_results)

    print(f"\n{G}{'='*46}{NC}\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        error("Usage: profile.py <target>")
        sys.exit(1)
    profile(sys.argv[1])
