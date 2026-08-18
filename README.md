# SubDomain-Locater

SuDomain-Locater is an interactive subdomain enumeration and takeover detection tool that combines passive (crt.sh) and active (wordlist brute‑force) scanning, checks for subdomain takeover vulnerabilities, performs threat intelligence lookups (AlienVault OTX, URLhaus), and compares results against previous scans. Output can be saved as JSON or CSV.

## Features

- **Passive scanning** – Query crt.sh for subdomains discovered in SSL certificates
- **Active scanning** – Brute‑force subdomains using a built‑in list or custom wordlist
- **Takeover detection** – Identify vulnerable services (AWS S3, GitHub Pages, Heroku, etc.)
- **Threat intelligence** – Check IPs against URLhaus and AlienVault OTX
- **History comparison** – Track changes between scans
- **Interactive menu** – Configure all options easily
- **Output** – Save results as JSON or CSV

## Installation

```bash
pip install requests colorama dnspython
