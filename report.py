import json
import os
import time
import logging
import requests
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger('vuln_scanner')


def generate_ai_report(project_name, target_ip, scan_results):

    if not scan_results:
        print("[!] No scan results to report on.")
        return

    # Build findings text
    findings_text = ""
    for r in scan_results:
        cve_block = ""
        if r["cves"]:
            for cve in r["cves"]:
                cve_block += f"    - {cve['id']} | Score: {cve['score']} | Severity: {cve['severity']}\n"
                cve_block += f"      {cve['description']}\n"
        else:
            cve_block = "    - No CVEs found\n"

        findings_text += (
            f"Port {r['port']}/{r['proto']}:\n"
            f"  Banner: {r['banner']}\n"
            f"  CVEs:\n{cve_block}\n"
        )

    prompt = f"""
        You are a senior penetration tester writing a professional VAPT report in Markdown format.
        Target IP: {target_ip}
        Scan Date: {datetime.now().strftime("%Y-%m-%d %H:%M")}
        Project: {project_name}
        Scan Findings:
        {findings_text}
        Write a complete professional VAPT report using proper Markdown formatting. Use the exact structure below:
        ---
        ## 1. Executive Summary
        Provide a brief overview of the assessment scope, methodology, and overall findings.
        | Field | Details |
        |-------|---------|
        | Target IP | {target_ip} |
        | Scan Date | {datetime.now().strftime("%Y-%m-%d %H:%M")} |
        | Project | {project_name} |
        | Overall Risk Rating | [Critical/High/Medium/Low] |
        Brief paragraph summarizing the overall security posture.
        ---
        ## 2. Findings
        For each open port, use this format:
        ### 🔴 Finding [N] — [Service Name] (Port [X]/[proto])
        | Field | Details |
        |-------|---------|
        | Port | |
        | Service | |
        | Version | |
        | Risk Rating | Critical / High / Medium / Low |
        **Vulnerability Details:**
        Describe the CVEs found and what they mean.
        **Proof of Concept:**
        Describe exactly what an attacker could do to exploit this.
        ---
        ## 3. Countermeasures
        For each finding, use this format:
        ### Finding [N] — [Service Name]
        - Step 1
        - Step 2
        - Step 3
        ---
        ## 4. Overall Recommendations
        ### Priority Actions
        | Priority | Action | Finding |
        |----------|--------|---------|
        | 1 | | |
        | 2 | | |
        ### General Hardening Advice
        - Advice 1
        - Advice 2
        ---
        Use proper Markdown: ## for sections, ### for subsections, tables, bold, bullet points.
        Use emojis for risk levels: 🔴 Critical, 🟠 High, 🟡 Medium, 🟢 Low.
        Be specific, technical, and formal throughout.
    """

    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        logger.error("GROQ_API_KEY not found in .env")
        print("[-] Error: GROQ_API_KEY missing from .env file")
        return

    url = "https://api.groq.com/openai/v1/chat/completions"

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}"
    }

    payload = {
        "model": "llama-3.3-70b-versatile",
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 4096,
        "temperature": 0.3
    }

    # Retry logic for rate limiting
    print("\n[*] Generating AI report... please wait\n")
    report_text = None

    for attempt in range(3):
        try:
            response = requests.post(url, headers=headers, json=payload, timeout=60)

            if response.status_code == 200:
                data = response.json()
                report_text = data["choices"][0]["message"]["content"]
                break
            elif response.status_code == 429:
                print(f"[!] Rate limited — retrying in 60s (attempt {attempt+1}/3)")
                time.sleep(60)
            else:
                logger.error(f"Groq API error: {response.status_code} - {response.text}")
                print(f"[-] API Error {response.status_code}: {response.text}")
                return

        except Exception as e:
            logger.error(f"Report generation failed: {e}")
            print(f"[-] Report generation failed: {e}")
            return

    if not report_text:
        print("[-] Failed to generate report after 3 attempts")
        logger.error("Report generation failed after 3 retry attempts")
        return

    # Save report
    filename = f"{project_name.replace(' ', '_')}_report.md"
    header = f"""# VAPT Report — {project_name}
**Target:** {target_ip}
**Date:** {datetime.now().strftime("%Y-%m-%d %H:%M")}
**Tool:** Vulnerability Seeker v2.0 by R05HAN

---

"""
    full_report = header + report_text

    with open(filename, "w", encoding="utf-8") as f:
        f.write(full_report)

    print(f"[+] Report saved: {filename}")
    logger.info(f"Report saved: {filename}")
    return filename