"""
KernelByte Scanner - Advanced Reconnaissance Tool (v2)
Author: KernelByte
License: MIT

IMPORTANT LEGAL WARNING
This tool is provided for EDUCATIONAL, DEFENSIVE, AND AUTHORIZED TESTING ONLY.
Do NOT run against systems you do not own or do not have explicit, written permission to test.
The author and distributor are not responsible for misuse.

DESCRIPTION (v2 Improvements):
 - Securely loads all API keys from a .env file to prevent leaks.
 - Added SSL/TLS certificate analysis for any given TCP port (--ssl-info).
 - Added basic, concurrent UDP port scanning for common ports (--udp).
 - Full integration for new APIs: CriminalIP, IPQualityScore, IPHub, and others.
 - Enhanced HTML reporting with sections for each data type and improved styling.
 - Refactored code for better organization and maintainability.
 - Added more CLI flags for new features and improved console output.

Requirements (Debian/Ubuntu):
 - Python 3.8+
 - pip install -r requirements.txt

requirements.txt (recommended):
 aiohttp
 aiodns
 python-dotenv
 python-nmap
 tqdm
 pyopenssl

Install example:
 sudo apt update && sudo apt install -y python3 python3-pip nmap
 pip3 install aiohttp aiodns python-dotenv python-nmap tqdm pyopenssl

USAGE (examples):
 python3 kernelbyte_scanner_advanced.py --target example.com
 python3 kernelbyte_scanner_advanced.py --target 198.51.100.25 --full --udp --ssl-info
 python3 kernelbyte_scanner_advanced.py --target example.com --subdomains --subfile wordlist.txt --nmap

"""
import argparse
import asyncio
import csv
import html
import ipaddress
import json
import os
import socket
import subprocess
import sys
import time
from datetime import datetime
from threading import Thread
from typing import Any, Dict, List, Optional

# Optional imports for core functionality
try:
    import aiohttp
    import aiodns
    from dotenv import load_dotenv
except ImportError:
    print("[!] Missing core dependencies. Please run: pip3 install aiohttp aiodns python-dotenv")
    sys.exit(1)

# Optional imports for extra features
try:
    from OpenSSL import SSL
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    HAS_PYOPENSSL = True
except ImportError:
    HAS_PYOPENSSL = False

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False

# Load environment variables from .env file
load_dotenv()

# --- Configuration / Defaults ---
BANNER = r"""
 _  __           _               ____              _
| |/ /___ _   _| |__   ___ _ __ | __ )  ___  _ __ | |_
| ' // _ \ | | | '_ \ / _ \ '_ \|  _ \ / _ \| '_ \| __|
| . \  __/ |_| | |_) |  __/ | | | |_) | (_) | | | | |_
|_|\_\___|\__, |_.__/ \___|_| |_|____/ \___/|_| |_|\__|
          |___/
KernelByte Scanner v2 - Advanced Reconnaissance Tool
"""
DEFAULT_CONCURRENCY = 200
CONNECT_TIMEOUT = 3.0
BANNER_GRAB_BYTES = 1024
DEFAULT_TCP_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443]
DEFAULT_UDP_PORTS = [53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 1900, 4500, 5353]
EXPORT_DIR = os.getcwd()

# --- Utility Functions ---

def is_ip(addr: str) -> bool:
    try:
        ipaddress.ip_address(addr)
        return True
    except ValueError:
        return False

def now_iso() -> str:
    return datetime.utcnow().isoformat() + 'Z'

def safe_filename(s: str) -> str:
    return "".join(c if c.isalnum() or c in "._-" else "_" for c in s)

# --- Legal Confirmation ---

def legal_confirmation_sync(timeout: int = 20) -> bool:
    if os.getenv('KB_AUTO_CONFIRM') == '1':
        return True
    print('\n' + BANNER)
    print("LEGAL NOTICE: You must only scan systems you own or have written permission to test.")
    print(f"You have {timeout} seconds to respond. Type 'yes' to proceed.")
    answer = {'value': None}
    def read_input():
        try:
            answer['value'] = sys.stdin.readline().strip().lower()
        except Exception:
            answer['value'] = None
    t = Thread(target=read_input, daemon=True)
    t.start()
    t.join(timeout)
    if answer.get('value') == 'yes':
        return True
    print('\n[!] Confirmation not received. Scan aborted.')
    return False

# --- Core Scanning Modules ---

async def tcp_connect(host: str, port: int, timeout: float = CONNECT_TIMEOUT) -> Optional[str]:
    try:
        fut = asyncio.open_connection(host=host, port=port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        writer.write(b"\r\n\r\n")
        await writer.drain()
        try:
            data = await asyncio.wait_for(reader.read(BANNER_GRAB_BYTES), timeout=1.0)
            banner = data.decode('utf-8', errors='ignore').strip()
            return banner if banner else "OPEN (No Banner)"
        except (asyncio.TimeoutError, ConnectionResetError):
            return "OPEN (No Banner)"
        finally:
            writer.close()
            await writer.wait_closed()
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return None

async def scan_ports_tcp(host: str, ports: List[int], concurrency: int) -> Dict[int, str]:
    semaphore = asyncio.Semaphore(concurrency)
    results = {}
    async def task_wrapper(port):
        async with semaphore:
            banner = await tcp_connect(host, port)
            if banner is not None:
                results[port] = banner
    tasks = [task_wrapper(p) for p in ports]
    if HAS_TQDM:
        [await f for f in tqdm(asyncio.as_completed(tasks), total=len(tasks), desc='Scanning TCP Ports')]
    else:
        await asyncio.gather(*tasks)
    return results

async def scan_ports_udp(host: str, ports: List[int], concurrency: int) -> List[int]:
    semaphore = asyncio.Semaphore(concurrency)
    open_ports = []
    class UDPEchoProtocol(asyncio.DatagramProtocol):
        def __init__(self, port):
            self.port = port
            self.transport = None
            self.closed = asyncio.Future()
        def connection_made(self, transport):
            self.transport = transport
            self.transport.sendto(b'data')
        def error_received(self, exc):
            if isinstance(exc, ConnectionRefusedError):
                self.closed.set_result(False) # Port is closed
            else:
                self.closed.set_result(True) # Can't determine, assume open/filtered
            if self.transport:
                self.transport.close()
        def connection_lost(self, exc):
            if not self.closed.done():
                self.closed.set_result(True) # No error, assume open/filtered

    async def check_port(port):
        async with semaphore:
            try:
                loop = asyncio.get_running_loop()
                connect = loop.create_datagram_endpoint(lambda: UDPEchoProtocol(port), remote_addr=(host, port))
                transport, protocol = await asyncio.wait_for(connect, timeout=2.0)
                is_open = await asyncio.wait_for(protocol.closed, timeout=2.0)
                if is_open:
                    open_ports.append(port)
                transport.close()
            except (asyncio.TimeoutError, OSError):
                open_ports.append(port) # Timeout implies open or filtered
    tasks = [check_port(p) for p in ports]
    if HAS_TQDM:
        [await f for f in tqdm(asyncio.as_completed(tasks), total=len(tasks), desc='Scanning UDP Ports')]
    else:
        await asyncio.gather(*tasks)
    return open_ports

async def get_ssl_cert_info(host: str, port: int) -> Optional[Dict[str, Any]]:
    if not HAS_PYOPENSSL:
        return {"error": "PyOpenSSL not installed, skipping certificate check."}
    try:
        cert_pem = ssl.get_server_certificate((host, port))
        cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
        
        subject = {attr.rfc4514_string(): attr.value for attr in cert.subject}
        issuer = {attr.rfc4514_string(): attr.value for attr in cert.issuer}
        
        sans = []
        try:
            ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            sans = ext.value.get_values_for_type(x509.GeneralName)
        except x509.ExtensionNotFound:
            pass
            
        return {
            "subject": subject,
            "issuer": issuer,
            "serial_number": cert.serial_number,
            "valid_from": cert.not_valid_before.isoformat(),
            "valid_until": cert.not_valid_after.isoformat(),
            "subject_alternative_names": sans,
            "signature_hash_algorithm": cert.signature_hash_algorithm.name,
        }
    except Exception as e:
        return {"error": str(e)}

# --- API Enrichment Modules ---

async def generic_api_get(session: aiohttp.ClientSession, name: str, url: str, **kwargs) -> Dict[str, Any]:
    try:
        async with session.get(url, timeout=10, **kwargs) as resp:
            if resp.status == 200:
                return {name: await resp.json()}
            return {name: {"error": f"HTTP Status {resp.status}"}}
    except Exception as e:
        return {name: {"error": str(e)}}

# Add dedicated functions for each API
async def vt_lookup(session, target, key):
    t_type = "ip_addresses" if is_ip(target) else "domains"
    return await generic_api_get(session, "virustotal", f"https://www.virustotal.com/api/v3/{t_type}/{target}", headers={'x-apikey': key})
async def shodan_lookup(session, target, key):
    url = f"https://api.shodan.io/shodan/host/{target}?key={key}" if is_ip(target) else f"https://api.shodan.io/dns/resolve?hostnames={target}&key={key}"
    return await generic_api_get(session, "shodan", url)
async def abuseipdb_lookup(session, ip, key):
    return await generic_api_get(session, "abuseipdb", "https://api.abuseipdb.com/api/v2/check", headers={'Key': key, 'Accept': 'application/json'}, params={'ipAddress': ip})
async def ipinfo_lookup(session, ip, key):
    return await generic_api_get(session, "ipinfo", f"https://ipinfo.io/{ip}/json", params={'token': key})
async def criminalip_lookup(session, ip, key):
    return await generic_api_get(session, "criminalip", f"https://api.criminalip.io/v1/ip/data/{ip}", headers={'x-api-key': key})
async def greynoise_lookup(session, ip, key):
    return await generic_api_get(session, "greynoise", f"https://api.greynoise.io/v3/community/{ip}", headers={'key': key})
async def whoisxml_lookup(session, domain, key):
    return await generic_api_get(session, "whoisxml", "https://www.whoisxmlapi.com/whoisserver/WhoisService", params={'domainName': domain, 'apiKey': key, 'outputFormat': 'JSON'})
async def securitytrails_lookup(session, domain, key):
    return await generic_api_get(session, "securitytrails", f"https://api.securitytrails.com/v1/domain/{domain}", headers={'APIKEY': key})
async def ipqualityscore_lookup(session, ip, key):
    return await generic_api_get(session, "ipqualityscore", f"https://www.ipqualityscore.com/api/json/ip/{key}/{ip}")
async def iphub_lookup(session, ip, key):
    return await generic_api_get(session, "iphub", f"http://v2.api.iphub.info/ip/{ip}", headers={'X-Key': key})
async def authabuse_lookup(session, ip, key):
    return await generic_api_get(session, "authabuse", "https://www.authabuse.com/api/ip/check", params={"ip": ip, "key": key})
# ... Add more API functions here as needed ...

# --- Main Scan Flow ---

async def enrich_and_report(target: str, primary_ip: str, args) -> Dict[str, Any]:
    print("[+] Gathering enrichment data from APIs...")
    enrichment_data = {}
    api_keys = {
        "virustotal": os.getenv("VIRUSTOTAL_API_KEY"),
        "shodan": os.getenv("SHODAN_API_KEY"),
        "abuseipdb": os.getenv("ABUSEIPDB_API_KEY"),
        "ipinfo": os.getenv("IPINFO_API_TOKEN"),
        "criminalip": os.getenv("CRIMINALIP_API_KEY"),
        "greynoise": os.getenv("GREYNOISE_API_KEY"),
        "whoisxml": os.getenv("WHOISXML_API_KEY"),
        "securitytrails": os.getenv("SECURITYTRAILS_API_KEY"),
        "ipqualityscore": os.getenv("IPQUALITYSCORE_API_KEY"),
        "iphub": os.getenv("IPHUB_API_KEY"),
        "authabuse": os.getenv("AUTHABUSE_API_KEY"),
    }
    
    async with aiohttp.ClientSession() as session:
        tasks = []
        if api_keys["virustotal"]:
            tasks.append(vt_lookup(session, primary_ip, api_keys["virustotal"]))
        if api_keys["shodan"]:
            tasks.append(shodan_lookup(session, primary_ip, api_keys["shodan"]))
        if api_keys["abuseipdb"] and is_ip(primary_ip):
            tasks.append(abuseipdb_lookup(session, primary_ip, api_keys["abuseipdb"]))
        if api_keys["ipinfo"] and is_ip(primary_ip):
            tasks.append(ipinfo_lookup(session, primary_ip, api_keys["ipinfo"]))
        if api_keys["criminalip"] and is_ip(primary_ip):
            tasks.append(criminalip_lookup(session, primary_ip, api_keys["criminalip"]))
        if api_keys["greynoise"] and is_ip(primary_ip):
            tasks.append(greynoise_lookup(session, primary_ip, api_keys["greynoise"]))
        if api_keys["ipqualityscore"] and is_ip(primary_ip):
            tasks.append(ipqualityscore_lookup(session, primary_ip, api_keys["ipqualityscore"]))
        if api_keys["iphub"] and is_ip(primary_ip):
            tasks.append(iphub_lookup(session, primary_ip, api_keys["iphub"]))
        if api_keys["authabuse"] and is_ip(primary_ip):
            tasks.append(authabuse_lookup(session, primary_ip, api_keys["authabuse"]))
        if api_keys["whoisxml"] and not is_ip(target):
            tasks.append(whoisxml_lookup(session, target, api_keys["whoisxml"]))
        if api_keys["securitytrails"] and not is_ip(target):
            tasks.append(securitytrails_lookup(session, target, api_keys["securitytrails"]))

        results = await asyncio.gather(*tasks)
        for res in results:
            enrichment_data.update(res)
            
    return enrichment_data

async def run_scan_flow(args):
    target = args.target
    if not is_ip(target):
        print(f"[+] Resolving domain: {target}")
        try:
            ips = [r.host for r in await aiodns.DNSResolver().query(target, 'A')]
            if not ips:
                print(f"[!] Could not resolve {target}. Exiting.")
                sys.exit(1)
            primary_ip = ips[0]
            print(f"[+] Domain resolved to {primary_ip}")
        except aiodns.error.DNSError:
            print(f"[!] Could not resolve {target}. Exiting.")
            sys.exit(1)
    else:
        primary_ip = target
    
    report = {
        "target": target,
        "primary_ip": primary_ip,
        "scan_start_time": now_iso(),
        "tcp_open_ports": {},
        "udp_open_ports": [],
        "ssl_certificates": {},
        "enrichment_data": {},
    }

    # TCP Scan
    tcp_ports_to_scan = list(range(1, 65536)) if args.full else DEFAULT_TCP_PORTS
    print(f"[+] Starting TCP scan on {len(tcp_ports_to_scan)} ports...")
    report["tcp_open_ports"] = await scan_ports_tcp(primary_ip, tcp_ports_to_scan, args.concurrency)

    # UDP Scan
    if args.udp:
        print(f"[+] Starting UDP scan on {len(DEFAULT_UDP_PORTS)} common ports...")
        report["udp_open_ports"] = await scan_ports_udp(primary_ip, DEFAULT_UDP_PORTS, args.concurrency)

    # SSL/TLS Certificate Info
    if args.ssl_info:
        print("[+] Gathering SSL/TLS certificate information...")
        ssl_tasks = [get_ssl_cert_info(primary_ip, p) for p in report["tcp_open_ports"]]
        ssl_results = await asyncio.gather(*ssl_tasks)
        for port, cert_info in zip(report["tcp_open_ports"], ssl_results):
            if cert_info and "error" not in cert_info:
                report["ssl_certificates"][port] = cert_info

    # API Enrichment
    report["enrichment_data"] = await enrich_and_report(target, primary_ip, args)
    
    report["scan_finish_time"] = now_iso()
    return report

# --- Reporting ---

def generate_html_report(report, filename):
    def dict_to_html(d, level=0):
        html_str = "<ul>"
        for k, v in d.items():
            k_esc = html.escape(str(k))
            if isinstance(v, dict):
                html_str += f"<li><strong>{k_esc}:</strong>{dict_to_html(v, level+1)}</li>"
            elif isinstance(v, list):
                 html_str += f"<li><strong>{k_esc}:</strong><ul>{''.join(f'<li>{html.escape(str(i))}</li>' for i in v)}</ul></li>"
            else:
                html_str += f"<li><strong>{k_esc}:</strong> {html.escape(str(v))}</li>"
        return html_str + "</ul>"

    with open(filename, "w", encoding="utf-8") as f:
        f.write("<!DOCTYPE html><html><head><title>Scan Report</title><style>body{font-family:sans-serif;margin:2em;} h1,h2{color:#333;} .card{border:1px solid #ddd; border-radius:5px; padding:1em; margin-bottom:1em; box-shadow: 2px 2px 5px #eee;} ul{list-style-type:none;}</style></head><body>")
        f.write(f"<h1>Scan Report for: {html.escape(report['target'])} ({html.escape(report['primary_ip'])})</h1>")
        f.write(f"<p>Scan Time: {report['scan_start_time']} to {report['scan_finish_time']}</p>")

        # TCP Ports
        f.write("<div class='card'><h2>Open TCP Ports</h2><table><tr><th>Port</th><th>Banner / Service</th></tr>")
        for port, banner in sorted(report['tcp_open_ports'].items()):
            f.write(f"<tr><td>{port}</td><td><pre>{html.escape(banner)}</pre></td></tr>")
        f.write("</table></div>")
        
        # UDP Ports
        if report['udp_open_ports']:
            f.write("<div class='card'><h2>Open/Filtered UDP Ports</h2><p>" + ", ".join(map(str, sorted(report['udp_open_ports']))) + "</p></div>")

        # SSL Certs
        if report['ssl_certificates']:
            f.write("<div class='card'><h2>SSL/TLS Certificate Details</h2>")
            for port, cert in report['ssl_certificates'].items():
                f.write(f"<h3>Certificate on Port {port}</h3>{dict_to_html(cert)}")
            f.write("</div>")
            
        # API Enrichment
        f.write("<div class='card'><h2>API Enrichment Data</h2>")
        for api, data in report['enrichment_data'].items():
            f.write(f"<h3>{api.title()}</h3>{dict_to_html(data)}")
        f.write("</div>")

        f.write("</body></html>")

# --- Main Execution ---

def main():
    parser = argparse.ArgumentParser(description='KernelByte Scanner v2 - Advanced Reconnaissance')
    parser.add_argument('--target', '-t', required=True, help='Target IP or domain')
    parser.add_argument('--full', action='store_true', help='Scan all 65535 TCP ports instead of common ones')
    parser.add_argument('--udp', action='store_true', help='Run a scan for common UDP ports')
    parser.add_argument('--ssl-info', action='store_true', help='Retrieve SSL/TLS certificate info from open ports')
    parser.add_argument('--concurrency', type=int, default=DEFAULT_CONCURRENCY, help=f'Async concurrency limit (default: {DEFAULT_CONCURRENCY})')
    parser.add_argument('--confirm', action='store_true', help='Auto-confirm legal ownership (use with caution)')
    
    args = parser.parse_args()

    if not args.confirm and not legal_confirmation_sync():
        sys.exit(1)
        
    try:
        report = asyncio.run(run_scan_flow(args))
        
        # Console Summary
        print("\n" + "="*20 + " Scan Summary " + "="*20)
        print(f"Target: {report['target']} ({report['primary_ip']})")
        print(f"Open TCP Ports ({len(report['tcp_open_ports'])}): {sorted(report['tcp_open_ports'].keys())}")
        if report['udp_open_ports']:
            print(f"Open/Filtered UDP Ports ({len(report['udp_open_ports'])}): {sorted(report['udp_open_ports'])}")
        
        # Export Reports
        base_name = safe_filename(f"{report['target']}_{int(time.time())}")
        json_path = f"{base_name}_report.json"
        html_path = f"{base_name}_report.html"
        
        with open(json_path, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\n[+] Full JSON report saved to: {json_path}")
        
        generate_html_report(report, html_path)
        print(f"[+] Visual HTML report saved to: {html_path}")

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
    except Exception as e:
        print(f"\n[!] An unexpected error occurred: {e}")

if __name__ == '__main__':
    main()
