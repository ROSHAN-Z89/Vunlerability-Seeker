import logging
import socket
import urllib.request
import urllib.parse
import json
import random
from dotenv import load_dotenv
import os

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename = 'vuln_scanner.log',
    filemode = 'a'
)
logger = logging.getLogger('vuln_scanner')

def lookup_cve(keyword, max_results=3): 
    """Query NVD API for CVEs matching a keyword (e.g. 'openssh 10.2')"""
    try:
        keyword_encoded = urllib.parse.quote(keyword)
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword_encoded}&resultsPerPage={max_results}"
        
        user_agents = [
             # Chrome on Windows
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",

            # Firefox on Windows
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) "
            "Gecko/20100101 Firefox/125.0",

            # Chrome on macOS
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",

            # Safari on macOS
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/605.1.15 "
            "(KHTML, like Gecko) Version/17.0 Safari/605.1.15",

            # Chrome on Android
            "Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",

            # Safari on iPhone
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) "
            "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 "
            "Mobile/15E148 Safari/604.1"

            # Edge on Windows
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.2478.67",

            # Opera on Windows
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 OPR/109.0.0.0",

            # Brave (Chromium-based, looks like Chrome)
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",

            # Firefox on Linux
            "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",

            # Chrome on Linux
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",

            # Safari on older macOS
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_6) AppleWebKit/605.1.15 "
            "(KHTML, like Gecko) Version/16.6 Safari/605.1.15",
        ]
        for user_agent in user_agents:
            user_agent = random.choice(user_agents)

        req = urllib.request.Request(url, headers={
            "User-Agent": f"{user_agent}",
            "apiKey": os.getenv("nvd_API-KEY")
        })
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode())
        
        cves = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "N/A")
            descriptions = cve.get("descriptions", [])
            desc = next((d["value"] for d in descriptions if d["lang"] == "en"), "No description")
            metrics = cve.get("metrics", {})
            
            # Try CVSS v3.1 first, then v3.0, then v2
            score = "N/A"
            severity = "N/A"
            for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if version in metrics:
                    m = metrics[version][0]
                    score = m.get("cvssData", {}).get("baseScore", "N/A")
                    severity = m.get("cvssData", {}).get("baseSeverity", m.get("baseSeverity", "N/A"))
                    break

            cves.append({
                "id": cve_id,
                "score": score,
                "severity": severity,
                "description": desc[:200]
            })
        
        return cves

    except Exception as e:
        logger.error(f"CVE lookup error for '{keyword}': {e}")
        return []



def retBanner(ip, port):
    if port in UDP_ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(2)
            if port == 53:  # DNS
                dns_query = b'\xAA\xAA\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' \
                            b'\x07example\x03com\x00' \
                            b'\x00\x01' \
                            b'\x00\x01'
                s.sendto(dns_query, (ip, port))
                data, _ = s.recvfrom(1024)
                banner = data.decode(errors="ignore").strip()
            
            elif port == 67 or port == 68:  # DHCP
                # DHCP Discover packet
                dhcp_discover = b'\x01\x01\x06\x00' + b'\x00' * 236
                s.sendto(dhcp_discover, (ip, port))
                data, _ = s.recvfrom(1024)
                banner = data.decode(errors="ignore").strip()
            
            elif port == 69:  # TFTP
                # TFTP Read Request
                tftp_req = b'\x00\x01test.txt\x00octet\x00'
                s.sendto(tftp_req, (ip, port))
                data, _ = s.recvfrom(1024)
                banner = data.decode(errors="ignore").strip()
            
            elif port == 123:  # NTP
                ntp_query = b'\x1b' + 47 * b'\0'
                s.sendto(ntp_query, (ip, port))
                data, _ = s.recvfrom(1024)
                banner = data.hex()

            elif port == 137:  # NetBIOS Name Service
                # NetBIOS Name Query
                netbios_query = b'\xAB\xCD\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00' \
                            b'\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01'
                s.sendto(netbios_query, (ip, port))
                data, _ = s.recvfrom(1024)
                banner = data.decode(errors="ignore").strip()
            
            elif port == 138:  # NetBIOS Datagram Service
                s.sendto(b'', (ip, port))
                data, _ = s.recvfrom(1024)
                banner = data.decode(errors="ignore").strip()

            elif port == 161 or port == 162:  # SNMP
                snmp_query = b'\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x71\xb4\x1c\x16' \
                            b'\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00'
                s.sendto(snmp_query, (ip, port))
                data, _ = s.recvfrom(1024)
                banner = data.decode(errors="ignore").strip()

            elif port == 389:  # LDAP (can be UDP)
                ldap_query = b'\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00'
                s.sendto(ldap_query, (ip, port))
                data, _ = s.recvfrom(1024)
                banner = data.decode(errors="ignore").strip()
            
            elif port == 445:  # SMB over UDP (NetBIOS-less)
                s.sendto(b'', (ip, port))
                data, _ = s.recvfrom(1024)
                banner = data.decode(errors="ignore").strip()
            
            elif port == 500:  # IKE (IPSec)
                # IKE Main Mode packet
                ike_packet = b'\x00' * 28 + b'\x01\x10\x02\x00' + b'\x00' * 16
                s.sendto(ike_packet, (ip, port))
                data, _ = s.recvfrom(1024)
                banner = data.hex()
            
            elif port == 514:  # Syslog
                syslog_msg = b'<14>Test syslog message'
                s.sendto(syslog_msg, (ip, port))
                data, _ = s.recvfrom(1024)
                banner = data.decode(errors="ignore").strip()
            
            elif port == 520:  # RIP (Routing Information Protocol)
                rip_request = b'\x01\x01\x00\x00' + b'\x00' * 20
                s.sendto(rip_request, (ip, port))
                data, _ = s.recvfrom(1024)
                banner = data.decode(errors="ignore").strip()
            
            elif port == 1434:  # MS-SQL Monitor
                mssql_probe = b'\x02'
                s.sendto(mssql_probe, (ip, port))
                data, _ = s.recvfrom(1024)
                banner = data.decode(errors="ignore").strip()
            
            elif port == 1812 or port == 1813:  # RADIUS
                s.sendto(b'', (ip, port))
                data, _ = s.recvfrom(1024)
                banner = data.decode(errors="ignore").strip()
            
            elif port == 1900:  # SSDP (UPnP)
                ssdp_discover = b'M-SEARCH * HTTP/1.1\r\n' \
                            b'HOST: 239.255.255.250:1900\r\n' \
                            b'MAN: "ssdp:discover"\r\n' \
                            b'MX: 1\r\n' \
                            b'ST: ssdp:all\r\n\r\n'
                s.sendto(ssdp_discover, (ip, port))
                data, _ = s.recvfrom(1024)
                banner = data.decode(errors="ignore").strip()
            
            elif port == 4500:  # IPSec NAT-T
                s.sendto(b'\x00' * 16, (ip, port))
                data, _ = s.recvfrom(1024)
                banner = data.hex()
            
            elif port == 5353:  # mDNS (Multicast DNS)
                mdns_query = b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00' \
                            b'\x09_services\x07_dns-sd\x04_udp\x05local\x00\x00\x0c\x00\x01'
                s.sendto(mdns_query, (ip, port))
                data, _ = s.recvfrom(1024)
                banner = data.decode(errors="ignore").strip()

            elif port == 11211:  # Memcached
                memcached_stats = b'stats\r\n'
                s.sendto(memcached_stats, (ip, port))
                data, _ = s.recvfrom(1024)
                banner = data.decode(errors="ignore").strip()

            else:
                # Generic empty UDP probe
                s.sendto(b'', (ip, port))
                data, _ = s.recvfrom(1024)
                banner = data.decode(errors="ignore").strip()

        except socket.timeout:
            logger.debug(f"UDP timeout - {ip}:{port}")
            return None
        except Exception as e:
            logger.error(f"UDP error - {ip}:{port} - {e}")
            return None
        finally:
            s.close()
       
        logger.info(f"UDP Banner retrieved - {ip}:{port}")
        return banner.lower()

    else:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((ip, port))

            if port == 21:  # FTP
                banner = s.recv(1024).decode(errors="ignore").strip()
            
            elif port == 22:  # SSH
                banner = s.recv(1024).decode(errors="ignore").strip()

            elif port == 23:  # Telnet
                banner = s.recv(1024).decode(errors="ignore").strip()

            elif port == 25:  # SMTP
                banner = s.recv(1024).decode(errors="ignore").strip()

            elif port == 80 or port == 8080 or port == 443:  # HTTP/HTTPS
                s.sendall(b"GET / HTTP/1.0\r\n\r\n")
                banner = s.recv(1024).decode(errors="ignore").strip()

            elif port == 110:  # POP3
                banner = s.recv(1024).decode(errors="ignore").strip()

            elif port == 143:  # IMAP
                banner = s.recv(1024).decode(errors="ignore").strip()

            elif port == 1433:  # MSSQL
                # MSSQL handshake might need more complex packet, here just reading banner
                banner = s.recv(1024).decode(errors="ignore").strip()

            elif port == 3306:  # MySQL
                banner = s.recv(1024).decode(errors="ignore").strip()

            elif port == 3389:  # RDP
                s.sendall(b"\x03\x00\x00\x0b\x06\xd0\x00\x00\x12\x34\x00")
                banner = s.recv(1024).decode(errors="ignore").strip()

            elif port == 5432:  # PostgreSQL
                banner = s.recv(1024).decode(errors="ignore").strip()

            elif port == 5900: # VNC
                banner = s.recv(1024).decode(errors="ignore").strip()

            elif port == 6379:  # Redis
                s.sendall(b"*1\r\n$4\r\nINFO\r\n")
                banner = s.recv(1024).decode(errors="ignore").strip()

            elif port == 8000:  # Web Server
                s.sendall(b"*1\r\n$4\r\nINFO\r\n")
                banner = s.recv(1024).decode(errors="ignore").strip()

            elif port == 9200:  # Elasticsearch (HTTP)
                s.sendall(b"GET / HTTP/1.0\r\n\r\n")
                banner = s.recv(1024).decode(errors="ignore").strip()

            elif port == 9050:  # SOCKS5 (Tor)
                s.sendall(b"\x05\x01\x00")
                banner = s.recv(1024).decode(errors="ignore").strip()

            else:  
                banner = s.recv(1024).decode(errors="ignore").strip()
            
        except socket.timeout:
            logger.debug(f"TCP timeout - {ip}:{port}")
            return None
        except Exception as e:
            logger.error(f"TCP error - {ip}:{port} ")
            return None
        finally:
            s.close()


        logger.info(f"TCP Banner retrieved - {ip}:{port}")
        return banner.lower()
    


portlist = list(range(1,65536))
UDP_ports = {53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 520, 1434, 1900, 4500, 5353, 11211}
