# VisionX Autopilot

**VisionX Autopilot** is the core automation engine of **VisionX OS**, designed to streamline penetration testing and security workflows. It integrates **four powerful features**—autopwn, target profiling, lazy installer, and report generation—into a single, intelligent, modular system.

This project transforms VisionX OS into a **guided, smart, and lightweight** penetration testing platform, making security assessments faster and more actionable.

---

## 🔹 Features

### 1. Autopwn
- One-command automation pipeline: recon → scan → vulnerability analysis → exploit suggestions.
- Automatically selects appropriate tools based on target type (network, web, wireless).
- Outputs structured results with **actionable next steps**:


[+] Subdomains found: ...
[+] Open ports: ...
[!] Possible vulnerability: ...
[>] Suggested exploit: ...
[>] Next step: visionx exploit run <tool> <target>


### 2. Lazy Installer
- Automatically detects and installs missing tools required for tasks.
- Keeps VisionX OS lightweight (<500MB) without sacrificing functionality.
- Works seamlessly across all modules (network, websecurity, osint, wireless, exploitation, password-cracking, reverse-engineering).

### 3. Target Profiling
- Collects essential information about the target before scanning:
  - Web stack, OS, technologies, CDN/WAF
  - Open ports and services
  - Potential vulnerabilities
- Helps autopwn choose the optimal workflow automatically.

### 4. Report Generator
- Generates clean, professional **HTML or PDF reports** summarizing findings.
- Includes:
  - Severity levels
  - Tools used
  - Suggested next steps
- Captures both **autopwn automated scans** and manual commands.

---

## 🔹 Installation

Clone the repository:

```bash
git clone https://github.com/vision-dev1/visionx-autopilot.git
cd visionx-autopilot
```

---

### Install dependencies and setup:
python3 setup.py install
⚠️ Requires Python 3.x and a Linux environment (Debian/Ubuntu recommended).
Dependencies for autopwn tools will be installed automatically by the Lazy Installer.

---

### 🔹 Usage

- Run the full automated scan:

visionx autopwn <target>

- Check the target profile separately:

visionx profile <target>

- Generate a report (HTML/PDF):

visionx report <target>

Autopwn will automatically install any missing tools as needed.

## 🔹 Requirements
Python 3.x
Linux OS (Debian/Ubuntu recommended)
Network tools (installed automatically if missing via Lazy Installer)


## 🔹 Contributing

Contributions are welcome!
Please ensure:

Code is modular and well-documented
CLI commands remain clear and intuitive
New tools are integrated with autopwn and lazy installer

Submit pull requests or open issues for suggestions and improvements.

## 🔹 License

This project is licensed under the MIT License.
See LICENSE
 for details.

## 🔹 Example Output
$ visionx autopwn example.com

[+] Target: example.com
[+] Subdomains found: www.example.com, blog.example.com
[+] Open ports: 80, 443, 22
[!] Possible vulnerability: SQL Injection
[>] Suggested exploit: sqlmap
[>] Next step: visionx exploit run sqlmap example.com

Full report available: visionx report example.com

