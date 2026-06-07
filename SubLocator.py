#!/usr/bin/env python3
"""
Subdomain Locater (Interactive Menu)
- Passive: crt.sh + DNS (A, CNAME)
- Active: TCP/HTTP brute‑force
- Takeover verification & risk scoring
- Threat intel checks (AlienVault OTX, URLhaus)
- History comparison between scans
- Output to JSON or CSV
- Interactive menu for all settings
"""

import json
import csv
import os
import socket
import sys
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from colorama import Fore, Style, init

# Optional DNS resolution
try:
    import dns.resolver
    HAVE_DNSPYTHON = True
except ImportError:
    HAVE_DNSPYTHON = False

init(autoreset=True)

# ----------------------------------------------------------------------
# Constants
# ----------------------------------------------------------------------
DEFAULT_SUBDOMAINS = [
    "www", "mail", "ftp", "dev", "test", "staging",
    "api", "beta", "blog", "shop", "admin", "cdn",
    "portal", "vpn", "m", "app"
]

SOCKET_TIMEOUT = 2
REQUEST_TIMEOUT = 5
USER_AGENT = "Mozilla/5.0 (compatible; SubLocater/2.0)"

TAKEOVER_FINGERPRINTS = {
    "There isn't a GitHub Pages site here.": "GitHub Pages",
    "NoSuchBucket": "AWS S3",
    "The specified bucket does not exist": "AWS S3",
    "herokucdn.com/error-pages/no-such-app.html": "Heroku",
    "No such app": "Heroku",
    "You're Almost There": "Pantheon",
    "Repository not found": "GitHub",
    "Fastly error: unknown domain": "Fastly",
    "The thing you were looking for is no longer here": "Tumblr",
    "No settings were found for this company": "Desk",
    "Sorry, this shop is currently unavailable": "Shopify"
}

SERVICE_RISK = {
    "AWS S3": "High",
    "GitHub Pages": "High",
    "Heroku": "High",
    "Pantheon": "Medium",
    "GitHub": "Medium",
    "Fastly": "Medium",
    "Tumblr": "Low",
    "Desk": "Low",
    "Shopify": "Low"
}

HISTORY_DIR = "scan_history"

# ----------------------------------------------------------------------
# Helper functions (unchanged core logic)
# ----------------------------------------------------------------------
def resolve_dns(hostname):
    ips = []
    cnames = []
    if HAVE_DNSPYTHON:
        try:
            for rdata in dns.resolver.resolve(hostname, 'A'):
                ips.append(rdata.to_text())
        except Exception:
            pass
        try:
            for rdata in dns.resolver.resolve(hostname, 'CNAME'):
                cnames.append(rdata.to_text())
        except Exception:
            pass
    else:
        try:
            ips.append(socket.gethostbyname(hostname))
        except Exception:
            pass
    return ips, cnames

def fetch_crtsh_subdomains(domain):
    subdomains = set()
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        resp = requests.get(url, timeout=10, headers={"User-Agent": USER_AGENT})
        if resp.status_code == 200:
            data = resp.json()
            for entry in data:
                name = entry.get("name_value", "")
                for n in name.split("\n"):
                    n = n.strip().lower()
                    if n.endswith(f".{domain}") and n != domain:
                        sub = n[:-len(domain)-1]
                        subdomains.add(sub)
        else:
            print(Fore.YELLOW + f"crt.sh returned status {resp.status_code}")
    except Exception as e:
        print(Fore.YELLOW + f"crt.sh query failed: {e}")
    return list(subdomains)

def check_ip_urlhaus(ip):
    try:
        resp = requests.post(
            "https://urlhaus-api.abuse.ch/v1/host/",
            data={"host": ip},
            timeout=5,
            headers={"User-Agent": USER_AGENT}
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("query_status") == "ok":
                return bool(data.get("urls", []))
    except Exception:
        pass
    return False

def check_ip_otx(ip, api_key):
    try:
        headers = {"X-OTX-API-KEY": api_key}
        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
        resp = requests.get(url, headers=headers, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            pulse_count = data.get("pulse_info", {}).get("count", 0)
            return pulse_count > 0, pulse_count
    except Exception:
        pass
    return False, 0

def tcp_check(hostname, port):
    try:
        sock = socket.create_connection((hostname, port), timeout=SOCKET_TIMEOUT)
        sock.close()
        return True
    except Exception:
        return False

def detect_takeover(response_text):
    for fingerprint, service in TAKEOVER_FINGERPRINTS.items():
        if fingerprint.lower() in response_text.lower():
            return service
    return None

def check_subdomain(subdomain, domain, config):
    hostname = f"{subdomain}.{domain}"
    result = {
        "subdomain": subdomain,
        "host": hostname,
        "active": True,
        "reachable": False,
        "status_code": None,
        "final_url": None,
        "takeover_service": None,
        "takeover_verified": False,
        "risk_score": None,
        "cnames": [],
        "ips": [],
        "threat_intel": None
    }

    tcp80 = tcp_check(hostname, 80)
    tcp443 = tcp_check(hostname, 443)
    if not tcp80 and not tcp443:
        result["status"] = "No TCP connection"
        return result

    result["reachable"] = True
    protocols = []
    if tcp443:
        protocols.append("https")
    if tcp80:
        protocols.append("http")

    for proto in protocols:
        try:
            url = f"{proto}://{hostname}"
            response = requests.get(
                url,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True,
                headers={"User-Agent": USER_AGENT}
            )
            result["status_code"] = response.status_code
            result["final_url"] = response.url
            result["protocol"] = proto

            service = detect_takeover(response.text)
            if service:
                result["takeover_service"] = service
                result["risk_score"] = SERVICE_RISK.get(service, "Medium")

            ips, cnames = resolve_dns(hostname)
            result["ips"] = ips
            result["cnames"] = cnames

            # Threat intel on IPs
            otx_key = config.get("otx_key")
            if ips:
                malicious = False
                for ip in ips:
                    if check_ip_urlhaus(ip):
                        malicious = True
                        break
                    if otx_key:
                        mal, _ = check_ip_otx(ip, otx_key)
                        if mal:
                            malicious = True
                            break
                if malicious:
                    result["threat_intel"] = "Known malicious IP (URLhaus/OTX)"

            # Takeover verification
            if result["takeover_service"] and cnames:
                for cname in cnames:
                    try:
                        ver_url = f"http://{cname}"
                        vresp = requests.get(ver_url, timeout=REQUEST_TIMEOUT, headers={"User-Agent": USER_AGENT})
                        if detect_takeover(vresp.text) == service:
                            result["takeover_verified"] = True
                            result["risk_score"] = "High"
                            break
                    except Exception:
                        pass

            return result

        except requests.RequestException:
            continue

    result["status"] = "HTTP request failed"
    return result

def load_history(domain):
    filepath = os.path.join(HISTORY_DIR, f"{domain}.json")
    if not os.path.exists(filepath):
        return None
    with open(filepath, "r") as f:
        return json.load(f)

def save_history(domain, data):
    os.makedirs(HISTORY_DIR, exist_ok=True)
    filepath = os.path.join(HISTORY_DIR, f"{domain}.json")
    with open(filepath, "w") as f:
        json.dump(data, f, indent=2, default=str)

def compare_scans(old, new):
    if not old:
        return {"message": "No previous scan to compare."}
    old_subs = {e["subdomain"] for e in old["results"]}
    new_subs = {e["subdomain"] for e in new["results"]}
    added = new_subs - old_subs
    removed = old_subs - new_subs
    changed = []
    old_map = {e["subdomain"]: e for e in old["results"]}
    new_map = {e["subdomain"]: e for e in new["results"]}
    for sub in new_subs & old_subs:
        o = old_map[sub]
        n = new_map[sub]
        if o.get("status_code") != n.get("status_code") or \
           o.get("takeover_service") != n.get("takeover_service") or \
           o.get("threat_intel") != n.get("threat_intel"):
            changed.append(sub)
    return {
        "added": sorted(added),
        "removed": sorted(removed),
        "changed": sorted(changed)
    }

def output_results(results, output_file, output_format):
    if not output_file:
        return
    if output_format == "json":
        with open(output_file, "w") as f:
            json.dump(results, f, indent=2, default=str)
        print(Fore.GREEN + f"Results saved to {output_file} (JSON)")
    elif output_format == "csv":
        with open(output_file, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["subdomain", "host", "reachable", "status_code",
                             "final_url", "takeover_service", "risk_score",
                             "ips", "cnames", "threat_intel"])
            for r in results["results"]:
                writer.writerow([
                    r.get("subdomain"),
                    r.get("host"),
                    r.get("reachable"),
                    r.get("status_code"),
                    r.get("final_url"),
                    r.get("takeover_service"),
                    r.get("risk_score"),
                    ",".join(r.get("ips", [])),
                    ",".join(r.get("cnames", [])),
                    r.get("threat_intel")
                ])
        print(Fore.GREEN + f"Results saved to {output_file} (CSV)")

# ----------------------------------------------------------------------
# Scan execution (called after menu)
# ----------------------------------------------------------------------
def run_scan(domain, config):
    """Execute the full scan based on the config dictionary."""
    subdomains_set = set()

    # Passive
    if config.get("passive", True) and not config.get("active_only"):
        print(Fore.CYAN + f"[*] Passive: querying crt.sh for {domain}")
        crt_subs = fetch_crtsh_subdomains(domain)
        subdomains_set.update(crt_subs)
        print(f"    crt.sh returned {len(crt_subs)} subdomains")

    # Active wordlist
    if config.get("active", True) and not config.get("passive_only"):
        if config.get("wordlist"):
            with open(config["wordlist"], "r") as f:
                wordlist = [line.strip() for line in f if line.strip()]
        else:
            wordlist = DEFAULT_SUBDOMAINS
        subdomains_set.update(wordlist)

    if not subdomains_set:
        print(Fore.RED + "No subdomains to scan. Exiting.")
        return

    subdomains = sorted(subdomains_set)

    # History
    previous = None
    if config.get("compare_history"):
        previous = load_history(domain)
        if previous:
            print(Fore.CYAN + "[*] Previous scan loaded for comparison")

    # Active scanning
    results = []
    print(Fore.CYAN + f"\n--- Scanning {len(subdomains)} subdomains ---\n")
    threads = config.get("threads", 20)
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check_subdomain, sub, domain, config): sub for sub in subdomains}
        for future in as_completed(futures):
            res = future.result()
            results.append(res)

            # Live output
            host = res["host"]
            if not res.get("reachable"):
                print(Fore.RED + f"[X] {host} -> {res.get('status')}")
            else:
                code = res.get("status_code", "???")
                color = Fore.GREEN if code not in [404, 500] else Fore.YELLOW
                output = f"[{code}] {host}"
                if res.get("takeover_service"):
                    output += f" | TAKEOVER: {res['takeover_service']} (Risk: {res['risk_score']})"
                    color = Fore.MAGENTA
                if res.get("threat_intel"):
                    output += f" | ⚠️ {res['threat_intel']}"
                    color = Fore.RED
                print(color + output)

    # Summary
    summary = {
        "domain": domain,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_scanned": len(results),
        "reachable": sum(1 for r in results if r.get("reachable")),
        "takeovers": [r for r in results if r.get("takeover_service")],
        "threats": [r for r in results if r.get("threat_intel")]
    }

    print(Fore.CYAN + "\n--- Summary ---")
    print(f"Scanned: {summary['total_scanned']} | Reachable: {summary['reachable']}")
    if summary["takeovers"]:
        print(Fore.MAGENTA + f"Possible takeovers: {len(summary['takeovers'])}")
        for t in summary["takeovers"]:
            print(f"  {t['host']} -> {t['takeover_service']} (Risk: {t['risk_score']})")
    if summary["threats"]:
        print(Fore.RED + f"Malicious IPs found: {len(summary['threats'])}")
        for t in summary["threats"]:
            print(f"  {t['host']} -> {t['threat_intel']}")

    # History diff
    if config.get("compare_history") and previous:
        diff = compare_scans(previous, {"results": results})
        print(Fore.CYAN + "\n--- Changes since last scan ---")
        if diff.get("added"):
            print(Fore.GREEN + f"New subdomains ({len(diff['added'])}):")
            for s in diff["added"]:
                print(f"  + {s}")
        if diff.get("removed"):
            print(Fore.RED + f"Removed subdomains ({len(diff['removed'])}):")
            for s in diff["removed"]:
                print(f"  - {s}")
        if diff.get("changed"):
            print(Fore.YELLOW + f"Changed subdomains ({len(diff['changed'])}):")
            for s in diff["changed"]:
                print(f"  ~ {s}")
        if not any(diff.values()):
            print("No changes detected.")

    # Save current results to history
    save_history(domain, {"results": results, "summary": summary})

    # Output file
    output_file = config.get("output_file")
    output_format = config.get("output_format", "json")
    if output_file:
        output_results({"results": results, "summary": summary}, output_file, output_format)

# ----------------------------------------------------------------------
# Interactive Menu
# ----------------------------------------------------------------------
def interactive_menu():
    print(Fore.CYAN + r"""
  >=>>=>            >=>            >=>                                        >=>                      
>=>    >=>          >=>            >=>                                        >=>                      
 >=>       >=>  >=> >=>            >=>          >=>        >==>    >=> >=>  >=>>==>    >=>     >> >==> 
   >=>     >=>  >=> >=>>==>        >=>        >=>  >=>   >=>     >=>   >=>    >=>    >=>  >=>   >=>    
      >=>  >=>  >=> >=>  >=>       >=>       >=>    >=> >=>     >=>    >=>    >=>   >=>    >=>  >=>    
>=>    >=> >=>  >=> >=>  >=>       >=>        >=>  >=>   >=>     >=>   >=>    >=>    >=>  >=>   >=>    
  >=>>=>     >==>=> >=>>==>        >=======>    >=>        >==>   >==>>>==>    >=>     >=>     >==>    
""" + Style.RESET_ALL)

    # Default config
    config = {
        "active": True,
        "passive": True,
        "passive_only": False,
        "active_only": False,
        "wordlist": None,
        "threads": 20,
        "otx_key": os.environ.get("OTX_API_KEY", ""),
        "output_file": None,
        "output_format": "json",
        "compare_history": False
    }

    domain = ""

    while True:
        print(Fore.YELLOW + Style.BRIGHT + "\n=== SUBDOMAIN LOCATER MENU ===")
        print(Fore.WHITE + f"Domain: {domain if domain else 'Not set'}")
        print(f"1. Set domain")
        print(f"2. Scan type: ", end="")
        if config["passive_only"]:
            print("Passive only")
        elif config["active_only"]:
            print("Active only")
        else:
            print("Active + Passive")
        print(f"3. Wordlist: {config['wordlist'] if config['wordlist'] else 'Default'}")
        print(f"4. Threads: {config['threads']}")
        print(f"5. OTX API Key: {'Set' if config['otx_key'] else 'Not set'}")
        print(f"6. Output file: {config['output_file'] if config['output_file'] else 'None'} (Format: {config['output_format'].upper()})")
        print(f"7. Compare with previous scan: {'Yes' if config['compare_history'] else 'No'}")
        print(Fore.GREEN + f"8. RUN SCAN")
        print(Fore.RED + f"9. Quit")

        choice = input(Fore.WHITE + "Choose an option: ").strip()

        if choice == '1':
            domain = input("Enter domain (e.g., example.com): ").strip()
        elif choice == '2':
            print("1. Active + Passive (default)")
            print("2. Passive only")
            print("3. Active only")
            st = input("Select: ").strip()
            if st == '2':
                config["passive_only"] = True
                config["active_only"] = False
            elif st == '3':
                config["active_only"] = True
                config["passive_only"] = False
            else:
                config["passive_only"] = False
                config["active_only"] = False
        elif choice == '3':
            path = input("Wordlist file path (blank for default): ").strip()
            config["wordlist"] = path if path else None
        elif choice == '4':
            try:
                t = int(input("Number of threads (default 20): ") or 20)
                config["threads"] = t
            except ValueError:
                print(Fore.RED + "Invalid number; keeping 20.")
        elif choice == '5':
            key = input("OTX API key (blank to clear, or 'env' to use environment variable): ").strip()
            if key.lower() == 'env':
                config["otx_key"] = os.environ.get("OTX_API_KEY", "")
            else:
                config["otx_key"] = key if key else ""
        elif choice == '6':
            out_file = input("Output filename (blank for no file): ").strip()
            if out_file:
                fmt = input("Format (json/csv, default json): ").strip().lower()
                if fmt not in ("json", "csv"):
                    fmt = "json"
                config["output_file"] = out_file
                config["output_format"] = fmt
            else:
                config["output_file"] = None
        elif choice == '7':
            hist = input("Compare with previous scan? (y/n): ").strip().lower()
            config["compare_history"] = hist == 'y'
        elif choice == '8':
            if not domain:
                print(Fore.RED + "Domain is required!")
                continue
            run_scan(domain, config)
            input(Fore.WHITE + "\nPress Enter to return to menu...")
        elif choice == '9':
            print(Fore.GREEN + "Goodbye!")
            break
        else:
            print(Fore.RED + "Invalid option.")

if __name__ == "__main__":
    interactive_menu()