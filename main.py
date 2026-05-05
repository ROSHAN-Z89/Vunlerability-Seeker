#!/usr/bin/python3

import os 
import sys
import pyfiglet
from colorama import Fore, Style
import ipaddress
import logging
from pathlib import Path
from proto import retBanner, portlist, lookup_cve, UDP_ports
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from report import generate_ai_report
import random 


project_name = ''
scan_results = []
# Loging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename = 'vuln_scanner.log',
    filemode = 'a'
)
logger = logging.getLogger('vuln_scanner')

# Type the colored Text
def Type(text, delay=0.1):
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    sys.stdout.write("\n")
    sys.stdout.flush()

# TEXT COLOR
wanted_fonts = [
    "Doom", "Graffiti", "Speed", "Gothic", "Bloody",
    "Poison", "Ghost", "Ghoulish", "Electronic", "Cyberlarge",
    "Cybermedium", "Bulbhead", "Isometric1", "Letters", "Mirror",
    "Thin", "Weird", "Star Wars", "Univers", "shadow",
    "block", "banner", "big", "digital", "slant", "larry3d"
]
 
chosen_font  = random.choice(wanted_fonts)
chosen_color = random.choice([
    Fore.GREEN, Fore.CYAN, Fore.MAGENTA,
    Fore.RED, Fore.YELLOW, Fore.LIGHTGREEN_EX,
    Fore.LIGHTCYAN_EX, Fore.LIGHTMAGENTA_EX
])
 
name = "Vuln Seeker"
ascii_art = pyfiglet.figlet_format(name, font=chosen_font)
 
print(chosen_color + ascii_art + Style.RESET_ALL)
print(Fore.CYAN    + ' ' * 30 + "----by R05HAN")
print(Fore.MAGENTA + ' ' * 35 + "--[v2.0]")
print()
print(Fore.YELLOW + ' ' * 20 + "GitHub    : https://github.com/Roshan-z89")
print(Fore.CYAN   + ' ' * 20 + "LinkedIn  : https://linkedin.com/in/roshan-z89")
print(Fore.BLUE   + ' ' * 20 + "Portfolio : https://roshan-z89.github.io/Portfolio")
print(Style.RESET_ALL)
 
 
# Type the colored Text
def Type(text, delay=0.05):
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    sys.stdout.write("\n")
    sys.stdout.flush()
 
 
# Validates IP
def validate_ip(ip_str):
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        logger.warning(f"Invalid IP Address provided: {ip_str}")
        return False

# Threaded scan
def scanport(ip, port):
    banner = retBanner(ip, port)
    if banner:
        print(f"{Fore.GREEN}[+] {ip}:{port}/tcp - {banner[:100]}")
        keyword = banner.split()[0]
        cves = lookup_cve(keyword)

        scan_results.append({
        "port": port,
        "proto": "udp" if port in UDP_ports else "tcp"  ,
        "banner": banner[:200],
        "cves": cves
    })

        for cve in cves:
            print(f"  {Fore.RED}[CVE] {cve['id']} | Score: {cve['score']} | {cve['description'][:100]}")
    else:
        return None

def run_threaded_scan(ip, portlist, max_workers=50):

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(scanport, ip, port): port
            for port in portlist
        }
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                port = futures[future]
                logger.error(f"Thread error on port {port}: {e}")
    future.result(timeout=4)
    
    generate_ai_report(project_name, ip, scan_results)

def main():
    start_time = time.time()
    logger.info("=== Vulnerability Scanner Started ===")

    project_name = input(f"{Fore.CYAN}[*] Enter project name (used for report filename): {Style.RESET_ALL}").strip()
    if not project_name:
        project_name = "scan_report"

    while True:
        target_ip = input(f"{Fore.YELLOW}[*] Enter the IP you want to grab: ")
        if validate_ip(target_ip):
            # ips = target_ip
            logger.info(f"Target IP validated: {target_ip}")
            break
        else:
            print(f"{Fore.RED}[-] Invalid IP. Please enter a valid IPv4 address.")

    print(f"{Fore.YELLOW}[*] Scanning {len(portlist)} ports with 50 threads...\n")
    run_threaded_scan(target_ip, portlist, max_workers=50)

    elapsed = time.time() - start_time
    logger.info("=== Scan Completed ===")
    print(f"\n{Fore.CYAN}[*] Scan complete in {elapsed:.1f}s")
    print(f"{Fore.CYAN}[*] {len(scan_results)} open port(s) found\n")

    # Generate AI Report
    if scan_results:
        generate_ai_report(project_name, target_ip, scan_results)
    else:
        print(f"{Fore.YELLOW}[!] No open ports found — no report generated.")

    print(f"{Fore.CYAN}[*] Check 'vuln_scanner.log' for full scan details")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user")
        logger.info("Scan Interrupted by user")
        sys.exit(0)
    
    except Exception as e:
        print(f"{Fore.RED}[-] Fatal Error: {str(e)}")
        logger.critical(f"fatal error: {str(e)}", exc_info=True)
        sys.exit(1)
