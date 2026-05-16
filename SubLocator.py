import socket
import requests
import os
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style, init

init(autoreset=True)

print(Fore.CYAN + """
  >=>>=>            >=>            >=>                                        >=>                      
>=>    >=>          >=>            >=>                                        >=>                      
 >=>       >=>  >=> >=>            >=>          >=>        >==>    >=> >=>  >=>>==>    >=>     >> >==> 
   >=>     >=>  >=> >=>>==>        >=>        >=>  >=>   >=>     >=>   >=>    >=>    >=>  >=>   >=>    
      >=>  >=>  >=> >=>  >=>       >=>       >=>    >=> >=>     >=>    >=>    >=>   >=>    >=>  >=>    
>=>    >=> >=>  >=> >=>  >=>       >=>        >=>  >=>   >=>     >=>   >=>    >=>    >=>  >=>   >=>    
  >=>>=>     >==>=> >=>>==>        >=======>    >=>        >==>   >==>>>==>    >=>     >=>     >==>    
                                                                                                       
                                                                                                       """ + Style.RESET_ALL)
  
# Default subdomains
DEFAULT_SUBDOMAINS = [
    "www", "mail", "ftp", "dev", "test", "staging",
    "api", "beta", "blog", "shop", "admin", "cdn",
    "portal", "vpn", "m", "app"
]

SOCKET_TIMEOUT = 2
REQUEST_TIMEOUT = 5

# Common takeover fingerprints
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


def tcp_check(hostname, port):
    try:
        sock = socket.create_connection(
            (hostname, port),
            timeout=SOCKET_TIMEOUT
        )
        sock.close()
        return True
    except Exception:
        return False


def load_subdomains():
    choice = input(
        "Use custom subdomain list? (y/n): "
    ).strip().lower()

    if choice == "y":
        path = input("Enter wordlist path: ").strip()

        if not os.path.exists(path):
            print(Fore.RED + "File not found.")
            return DEFAULT_SUBDOMAINS

        with open(path, "r") as f:
            subs = [line.strip() for line in f if line.strip()]

        return subs

    return DEFAULT_SUBDOMAINS


def detect_takeover(response_text):
    for fingerprint, service in TAKEOVER_FINGERPRINTS.items():
        if fingerprint.lower() in response_text.lower():
            return service

    return None


def check_subdomain(subdomain, domain):
    hostname = f"{subdomain}.{domain}"

    result = {
        "host": hostname,
        "reachable": False
    }

    # TCP checks
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
                headers={
                    "User-Agent": "Mozilla/5.0"
                }
            )

            result["status_code"] = response.status_code
            result["final_url"] = response.url
            result["protocol"] = proto

            # Check takeover fingerprints
            service = detect_takeover(response.text)

            if service:
                result["takeover"] = service

            return result

        except requests.RequestException:
            continue

    result["status"] = "HTTP request failed"
    return result


def main():
    domain = input(
        "Enter target domain (example.com): "
    ).strip()

    subdomains = load_subdomains()

    print(
        Fore.CYAN +
        f"\nScanning {len(subdomains)} subdomains...\n"
    )

    found_404s = []
    found_takeovers = []

    with ThreadPoolExecutor(max_workers=20) as executor:
        results = executor.map(
            lambda sub: check_subdomain(sub, domain),
            subdomains
        )

        for result in results:
            host = result["host"]

            # Failed
            if not result.get("reachable"):
                print(
                    Fore.RED +
                    f"[X] {host} -> {result.get('status')}"
                )
                continue

            code = result.get("status_code", "???")

            # 404s
            if code == 404:
                found_404s.append(host)
                color = Fore.YELLOW
            else:
                color = Fore.GREEN

            output = (
                f"[{code}] {host}"
            )

            if "takeover" in result:
                service = result["takeover"]

                found_takeovers.append((host, service))

                output += (
                    f" | POSSIBLE TAKEOVER ({service})"
                )

                color = Fore.MAGENTA

            print(color + output)

    print(
        Fore.CYAN +
        "\n--- 404 Subdomains ---"
    )

    if found_404s:
        for sub in found_404s:
            print(Fore.YELLOW + sub)
    else:
        print("None found.")

    print(
        Fore.CYAN +
        "\n--- Possible Takeovers ---"
    )

    if found_takeovers:
        for host, service in found_takeovers:
            print(
                Fore.MAGENTA +
                f"{host} -> {service}"
            )
    else:
        print("None detected.")


if __name__ == "__main__":
    main()