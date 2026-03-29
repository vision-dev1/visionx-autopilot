#!/usr/bin/env python3
# ============================================================
# VisionX OS — Report Generator
# /usr/local/lib/visionx/python/report.py
# ============================================================

import subprocess
import sys
import os
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

R = Fore.RED + Style.BRIGHT
G = Fore.GREEN + Style.BRIGHT
Y = Fore.YELLOW + Style.BRIGHT
C = Fore.CYAN + Style.BRIGHT
W = Fore.WHITE + Style.BRIGHT
NC = Style.RESET_ALL

def info(msg):  print(f"  {C}[~]{NC} {msg}")
def ok(msg):    print(f"  {G}[+]{NC} {msg}")
def warn(msg):  print(f"  {Y}[!]{NC} {msg}")
def error(msg): print(f"  {R}[x]{NC} {msg}")

def run_cmd(cmd):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
        return result.stdout.strip()
    except Exception:
        return ""

def generate_report(target):
    print(f"\n{R}{'='*46}")
    print(f"  VisionX OS - Report Generator")
    print(f"{'='*46}{NC}")
    print(f"\n  {W}Target: {C}{target}{NC}")
    print(f"  {W}Time:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{NC}\n")

    # Collect data
    info("Collecting DNS info...")
    dns = run_cmd(f"dig +short {target} @8.8.8.8")

    info("Collecting WHOIS info...")
    whois = run_cmd(f"whois {target} 2>/dev/null | grep -E 'Registrar|Creation|Expiry'")

    info("Scanning ports...")
    nmap = run_cmd(f"nmap -T4 --top-ports 100 {target} 2>/dev/null")

    info("Checking HTTP headers...")
    headers = run_cmd(f"curl -sI http://{target} 2>/dev/null | head -20")

    info("Running nikto...")
    nikto = run_cmd(f"nikto -h http://{target} -maxtime 30 2>/dev/null")

    # Parse open ports
    open_ports = []
    for line in nmap.split('\n'):
        if '/tcp' in line and 'open' in line:
            open_ports.append(line.strip())

    # Generate HTML
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    report_dir = f"/root/visionx_reports"
    os.makedirs(report_dir, exist_ok=True)
    report_file = f"{report_dir}/{target}_{timestamp}.html"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VisionX Report — {target}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ background: #0a0a0a; color: #e0e0e0; font-family: 'Courier New', monospace; padding: 20px; }}
        .header {{ background: #1a1a1a; border-left: 4px solid #ff0000; padding: 20px; margin-bottom: 20px; }}
        .header h1 {{ color: #ff0000; font-size: 24px; }}
        .header p {{ color: #888; margin-top: 5px; }}
        .section {{ background: #1a1a1a; border: 1px solid #333; border-radius: 4px; padding: 15px; margin-bottom: 15px; }}
        .section h2 {{ color: #00ccff; border-bottom: 1px solid #333; padding-bottom: 8px; margin-bottom: 12px; font-size: 16px; }}
        .found {{ color: #00ff88; }}
        .warn  {{ color: #ffcc00; }}
        .info  {{ color: #00ccff; }}
        pre {{ background: #0d0d0d; padding: 12px; border-radius: 4px; overflow-x: auto; font-size: 13px; line-height: 1.5; white-space: pre-wrap; }}
        .port-open {{ color: #00ff88; }}
        .badge {{ display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 12px; margin: 2px; }}
        .badge-red   {{ background: #3a0000; color: #ff4444; border: 1px solid #ff0000; }}
        .badge-green {{ background: #003a00; color: #44ff44; border: 1px solid #00ff00; }}
        .badge-blue  {{ background: #00003a; color: #4444ff; border: 1px solid #0000ff; }}
        .footer {{ text-align: center; color: #444; margin-top: 20px; font-size: 12px; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin-bottom: 20px; }}
        .summary-card {{ background: #1a1a1a; border: 1px solid #333; padding: 15px; text-align: center; border-radius: 4px; }}
        .summary-card .number {{ font-size: 28px; color: #ff0000; font-weight: bold; }}
        .summary-card .label {{ font-size: 12px; color: #888; margin-top: 5px; }}
    </style>
</head>
<body>

<div class="header">
    <h1>⚡ VisionX OS — Security Report</h1>
    <p>Target: <strong style="color:#fff">{target}</strong></p>
    <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    <p>DNS: {dns.replace(chr(10), ', ') if dns else 'Not resolved'}</p>
</div>

<div class="summary-grid">
    <div class="summary-card">
        <div class="number">{len(open_ports)}</div>
        <div class="label">Open Ports</div>
    </div>
    <div class="summary-card">
        <div class="number">{len(dns.split()) if dns else 0}</div>
        <div class="label">IP Addresses</div>
    </div>
    <div class="summary-card">
        <div class="number">{len([l for l in nikto.split(chr(10)) if '+ ' in l])}</div>
        <div class="label">Nikto Findings</div>
    </div>
    <div class="summary-card">
        <div class="number">{len(whois.split(chr(10))) if whois else 0}</div>
        <div class="label">WHOIS Records</div>
    </div>
</div>

<div class="section">
    <h2>🔍 DNS Information</h2>
    <pre>{dns if dns else 'No DNS records found'}</pre>
</div>

<div class="section">
    <h2>📋 WHOIS Information</h2>
    <pre>{whois if whois else 'No WHOIS data found'}</pre>
</div>

<div class="section">
    <h2>🔓 Open Ports</h2>
    <pre>{chr(10).join(open_ports) if open_ports else "No open ports found"}</pre>
</div>

<div class="section">
    <h2>🌐 HTTP Headers</h2>
    <pre>{headers if headers else 'No headers found'}</pre>
</div>

<div class="section">
    <h2>⚠️ Nikto Findings</h2>
    <pre>{nikto if nikto else 'No findings'}</pre>
</div>

<div class="section">
    <h2>🎯 Recommended Next Steps</h2>
    <pre>
1. visionx web scan {target}        — deep web vulnerability scan
2. visionx exploit suggest {target} — find exploits for open services
3. visionx osint recon {target}     — gather more intelligence
4. visionx autopwn {target}         — run full automated pipeline
    </pre>
</div>

<div class="footer">
    <p>Generated by VisionX OS — Lightweight. Lethal. Learning Focused.</p>
</div>

</body>
</html>"""

    with open(report_file, 'w') as f:
        f.write(html)

    ok(f"Report saved: {report_file}")
    print(f"\n  {G}Open in browser:{NC}")
    print(f"  {C}xdg-open {report_file}{NC}\n")
    return report_file

if __name__ == "__main__":
    if len(sys.argv) < 2:
        error("Usage: report.py <target>")
        sys.exit(1)
    generate_report(sys.argv[1])
