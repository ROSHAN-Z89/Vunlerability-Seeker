# Vulnerability Seeker v2.0

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/Platform-Linux-green?style=for-the-badge&logo=linux&logoColor=white"/>
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Version-2.0-red?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Made%20by-R05HAN-purple?style=for-the-badge"/>
</p>

<p align="center">
  A professional <b>Vulnerability Assessment and Penetration Testing (VAPT)</b> tool that performs port scanning, banner grabbing, CVE lookup via the NVD API, and generates AI-powered security reports.
</p>

---

## Table of Contents

- [Features](#features)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [How It Works](#how-it-works)
- [Sample Output](#sample-output)
- [Tech Stack](#tech-stack)
- [Disclaimer](#disclaimer)
- [Author](#author)

---

## Features

- **Full Port Scanner** — Scans all 65,535 TCP/UDP ports using multithreading (50 threads)
- **Banner Grabbing** — Extracts service banners from open ports (SSH, FTP, HTTP, MySQL, Redis, and more)
- **CVE Lookup** — Queries the NVD (National Vulnerability Database) API in real-time for known CVEs with CVSS scores
- **AI-Powered Report** — Generates a professional VAPT report using Groq's LLaMA 3.3 70B model
- **Markdown Report** — Report saved as a `.md` file with structured sections, tables, findings, countermeasures, and recommendations
- **Dynamic ASCII Banner** — Random hacker-style font and color combination on every run
- **Detailed Logging** — Full scan activity logged to `vuln_scanner.log`

---

## Project Structure

```
Vulnerability-Seeker/
│
├── main.py              # Main entry point — orchestrates scan and report generation
├── proto.py             # Banner grabbing, CVE lookup, port and protocol definitions
├── report.py            # AI-powered report generation using Groq API
├── .env                 # API keys — not committed to version control
├── vuln_scanner.log     # Scan activity log (auto-generated at runtime)
└── README.md            # Project documentation
```

---

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/Roshan-z89/Vulnerability-Seeker.git
cd Vulnerability-Seeker
```

### 2. Install Python Dependencies

```bash
pip install pyfiglet colorama python-dotenv requests --break-system-packages
```

### 3. Install Extended Figlet Fonts (Optional but Recommended)

```bash
wget https://github.com/xero/figlet-fonts/archive/master.zip
unzip master.zip
sudo cp figlet-fonts-main/*.flf /usr/lib/python3/dist-packages/pyfiglet/fonts/
```

---

## Configuration

Create a `.env` file in the project root directory:

```env
GROQ_API_KEY=your_groq_api_key_here
NVD_API_KEY=your_nvd_api_key_here
```

| Key | Source | Cost |
|-----|--------|------|
| `GROQ_API_KEY` | [console.groq.com](https://console.groq.com) | Free |
| `NVD_API_KEY` | [nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key) | Free |

---

## Usage

```bash
python3 main.py
```

You will be prompted for:

1. **Project Name** — Used as the output report filename
2. **Target IP** — IPv4 address of the target machine

```
[*] Enter project name (used for report filename): HTB_Machine
[*] Enter the IP you want to scan: 10.10.10.1
[*] Scanning 65535 ports with 50 threads...
```

> **Warning:** Only scan systems you own or have explicit written permission to test.

---

## How It Works

```
+----------------+     +-------------------+     +----------------+     +--------------+
|   main.py      |---->|    proto.py       |---->|   NVD API      |---->|  report.py   |
|                |     |                   |     |                |     |              |
|  User Input    |     |  Port Scanning    |     |  CVE Lookup    |     |  Groq AI     |
|  IP + Name     |     |  Banner Grabbing  |     |  CVSS Scores   |     |  VAPT Report |
+----------------+     +-------------------+     +----------------+     +--------------+
                                 |                                              |
                                 v                                              v
                       vuln_scanner.log                             {project}_report.md
```

### Scan Flow

1. User provides target IP address and project name
2. 50 threads scan all ports simultaneously for maximum speed
3. Open ports have their service banners grabbed via raw sockets
4. Banner keywords are queried against the NVD API for matching CVEs
5. All findings are collected into a structured results list
6. Groq LLaMA 3.3 70B generates a complete professional VAPT report
7. Report is saved as `{project_name}_report.md`

---

## Sample Output

```
[+] 10.10.10.1:22/tcp  - ssh-2.0-openssh_7.4
  [CVE] CVE-2023-38408 | Score: 9.8 | Remote code execution vulnerability in ssh-agent
  [CVE] CVE-2023-51385 | Score: 9.8 | OS command injection via invalid username

[+] 10.10.10.1:80/tcp  - http/1.1 200 ok server: apache/2.4.18
  [CVE] CVE-2017-7679  | Score: 9.8 | Buffer overflow in mod_mime with malformed Content-Type

[*] Scan complete in 109.5s
[*] 2 open port(s) found

[*] Generating AI report... please wait

[+] Report saved: HTB_Machine_report.md
```

---

## Tech Stack

| Component | Technology |
|-----------|------------|
| Language | Python 3.8+ |
| Port Scanning | `socket`, `concurrent.futures.ThreadPoolExecutor` |
| CVE Lookup | NVD REST API v2.0 |
| AI Report Generation | Groq API — LLaMA 3.3 70B Versatile |
| Banner Grabbing | Raw TCP/UDP sockets with protocol-specific probes |
| ASCII Art | `pyfiglet` with 400+ fonts |
| Logging | Python `logging` module |
| Environment Config | `python-dotenv` |
| HTTP Client | `requests` |

---

## Disclaimer

This tool is developed strictly for **educational purposes** and **authorized penetration testing** only.

- Use only on systems you own or have explicit written permission to assess
- Do not use this tool against systems without prior authorization
- The author is not responsible for any misuse, damage, or legal consequences arising from use of this tool
- Always comply with applicable local laws and regulations before conducting any security assessment

---

## Author

**R05HAN**

<p>
  <a href="https://github.com/Roshan-z89">
    <img src="https://img.shields.io/badge/GitHub-Roshan--z89-black?style=for-the-badge&logo=github"/>
  </a>
  <a href="https://linkedin.com/in/roshan-z89">
    <img src="https://img.shields.io/badge/LinkedIn-roshan--z89-blue?style=for-the-badge&logo=linkedin"/>
  </a>
  <a href="https://roshan-z89.github.io/Portfolio">
    <img src="https://img.shields.io/badge/Portfolio-roshan--z89-green?style=for-the-badge&logo=firefox"/>
  </a>
</p>

---

<p align="center">
  Developed by R05HAN &nbsp;|&nbsp; For educational and authorized use only
</p>
