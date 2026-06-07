# SubDomain Locator
# 🔎 SubLocater – Subdomain Recon & Monitoring Tool

A versatile **subdomain discovery and monitoring tool** built for security analysts, 
blue teams, and anyone who wants to understand the external footprint of a domain.  
It combines passive intelligence (certificate transparency, DNS) with active 
brute‑forcing, automatically flags potential subdomain takeovers, checks 
resolving IPs against threat intelligence, and remembers every scan so you can 
spot changes over time.


## 🧠 Why this tool exists

I wanted a single, fast, interactive assistant that could:

- Discover subdomains **without sending a single packet to the target** (passive)
- Enumerate subdomains **actively** when a full picture is needed
- Identify **subdomain takeover risks** and verify them automatically
- Flag subdomains that resolve to **known malicious IPs**
- Let me **compare** the current scan with a previous one to see what’s new, 
  removed, or changed
- Export everything to **JSON or CSV** for reports and further analysis

No more juggling five different command‑line tools. No more forgetting 
which flags do what. **SubLocater** gives you a clean, coloured menu that 
holds your hand through the entire workflow.

---

## ✨ Features

### Discovery
- **Passive** – Certificate Transparency logs via [crt.sh](https://crt.sh)
- **Active** – TCP/HTTP brute‑force with built‑in or custom wordlists
- **DNS enrichment** – Resolve A and CNAME records for every discovered subdomain

### Vulnerability Detection
- **Subdomain takeover** fingerprinting (GitHub Pages, AWS S3, Heroku, 
  Azure, Pantheon, Shopify, and more)
- **Automatic verification** – If a CNAME points to an unclaimed service, 
  the tool re‑checks it and assigns a **risk score** (`High`, `Medium`, `Low`)

### Threat Intelligence
- Checks each resolved IP against:
  - **URLhaus** (malware hosting)
  - **AlienVault OTX** (community threat pulses)
- Flagged subdomains are clearly marked with a red warning

### Continuous Monitoring
- Every scan is saved automatically in the `scan_history/` folder
- Use the built‑in **history comparison** to see:
  - New subdomains (🟢)
  - Removed subdomains (🔴)
  - Changed status / risk (🟡)

### Usability
- **Fully interactive menu** – no command‑line flags to remember
- Coloured terminal output (`colorama`) – errors in red, takeovers in magenta, 
  threats in red, success in green
- Export results to **JSON** or **CSV** with a single menu selection

---

## 🧪 Tech Stack

| Component           | Technology                            |
|---------------------|---------------------------------------|
| Language            | Python 3.8+                           |
| HTTP / Networking   | `requests`, `socket`                  |
| DNS                 | `dnspython` (optional but recommended)|
| Terminal styling    | `colorama`                            |
| Threat intelligence | URLhaus API, AlienVault OTX API       |
| Data persistence    | JSON (history & output), CSV (export) |


🚀 Usage

Run the script from your terminal:
bash

python3 sublocater.py

You’ll be greeted with the ASCII banner and an interactive menu.
No arguments, no confusion.
Menu Walkthrough
Option	What it does
1. Set domain	The target domain (e.g., example.com)
2. Scan type	Choose Active + Passive, Passive only, or Active only
3. Wordlist	Default (16 common subdomains) or a custom file
4. Threads	Speed of active scanning (default 20)
5. OTX API Key	Enter key, use env, or leave blank
6. Output file	Save results as JSON or CSV
7. Compare with previous scan	Enable diff view after scanning
8. RUN SCAN	Start the actual discovery
9. Quit	Exit the program
Example Session

    Set domain to example.com

    Leave everything else at default

    Choose 8. RUN SCAN

    Watch the live output – subdomains appear, takeovers and threats are flagged

    After the summary, if you enabled history comparison, changes are shown

    Press Enter to return to the menu and scan another domain or export

📊 Understanding the Output

While scanning you’ll see lines like:
text

[200] www.example.com                                  (green)
[404] dev.example.com                                  (yellow)
[404] test.example.com | TAKEOVER: GitHub Pages (Risk: High)  (magenta)
[200] api.example.com | ⚠️ Known malicious IP (URLhaus/OTX)    (red)

After the scan a summary is printed, and if you opted for history comparison
you’ll get a clean diff:
text

--- Changes since last scan ---
New subdomains (2):
  + blog.example.com
  + staging.example.com
Removed subdomains (1):
  - old.example.com
Changed subdomains (1):
  ~ dev.example.com

🧾 Exporting Results

When you set an output file in the menu, the tool will write all results
plus the summary to that file.

    JSON – full structured data, perfect for further scripting

    CSV – ready for Excel, Google Sheets, or feeding into a SIEM

The JSON export contains every field: subdomain, host, reachable, status code,
final URL, takeover service, risk score, IPs, CNAMEs, and threat intel notes.
⚠️ Important Notes & Ethics

    Use this tool only on domains you own or have explicit permission to test.
    Unauthorised scanning can be considered intrusive and may violate
    terms of service or local laws.

    The passive mode (crt.sh) is completely harmless – no traffic is sent to
    the target. Active brute‑forcing does send HTTP requests, so use responsibly.

    This is an educational and professional assistant, not a weapon.
    Always follow responsible disclosure guidelines if you find vulnerabilities.

    Rate limiting – The tool does not implement delays. If you scan a
    domain you don’t own, you risk being blocked or flagged.

 
🙌 Acknowledgements

    crt.sh – phenomenal free certificate transparency log

    URLhaus & AlienVault OTX – free threat intelligence for the community

    dnspython – the backbone of DNS resolution in Python

    colorama – for making terminal tools feel like real applications

🛠️ Author

Made by sudo-scorpion
Feel free to star and pull requests
THank you for your time...
