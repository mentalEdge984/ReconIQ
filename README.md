# ReconIQ

**AI-Powered Network Vulnerability Analyzer with Real-World Risk Scoring**

ReconIQ is a Python-based network analysis tool that combines fast multi-threaded port scanning, AI-driven CVE extraction, and probabilistic exploit scoring via the FIRST.org EPSS API. It produces actionable threat reports with real-world exploit-likelihood data — not just static severity ratings.

> Built by a Security+ certified practitioner running a custom SOC home lab (`ironforge.corp`).

---

## Features

- **Multi-Threaded Scanning:** Fast TCP banner grabbing across single hosts or full subnets (CIDR supported)
- **AI CVE Extraction:** Uses OpenAI or Google Gemini to identify the most critical CVEs from scan output
- **EPSS Risk Scoring:** Pulls real-time exploit probability scores from the [FIRST.org EPSS API](https://www.first.org/epss/) — predicts the chance of exploitation within the next 30 days
- **Senior-Analyst-Style Reports:** AI synthesizes findings into structured reports with attack vectors, CVSS scores, and step-by-step remediation
- **Premium Terminal UI:** Live spinner, Unicode box drawing, markdown-to-ANSI rendering — looks good in any modern terminal
- **Persistent Configuration:** API keys stored once at `~/.reconiq.json` (chmod 600)
- **Report Export:** Save full audit results to file with `-o`

---

## Installation

```bash
git clone https://github.com/mentalEdge984/ReconIQ.git
cd ReconIQ
pip install -r requirements.txt
chmod +x reconiq.py
```

For global access:
```bash
sudo cp reconiq.py /usr/local/bin/reconiq
```

### Requirements
- Python 3.7+
- `requests` library
- `keyring` library (for OS keyring storage; falls back to `~/.reconiq.json` if unavailable)
- An API key from **OpenAI**, **Google Gemini**, or **Anthropic Claude**

---

## Usage

### First Run — Interactive Setup
```bash
reconiq -t 192.168.1.1
```
You will be prompted once for your provider and API key. Stored at `~/.reconiq.json`.

### Common Commands

```bash
# Quick scan of common ports
reconiq -t example.com

# Full port scan with custom thread count
reconiq -t 192.168.1.10 -p all -w 200

# Subnet sweep with brief output
reconiq -t 192.168.1.0/24 --brief

# Custom port range with file output
reconiq -t target.com -p 1-1000 -o report.txt

# Quiet mode for piping
reconiq -t 10.0.0.5 -q -o scan.txt
```

### CLI Reference

| Flag | Description | Default |
|------|-------------|---------|
| `-t, --target` | Target IP, domain, or CIDR subnet | **required** |
| `-p, --ports` | Ports: `common`, `all`, `80`, `1-1000`, or `22,80,443` | `common` |
| `-w, --workers` | Concurrent scanner threads | `100` |
| `-o, --output` | Save report to file | — |
| `-q, --quiet` | Suppress UI output | — |
| `--brief` | Skip detailed remediation tutorials | — |
| `--timeout` | Socket timeout per port in seconds | `1.5` |
| `--i-have-permission` | Skip authorization prompt for scans > 16 hosts | — |
| `--api-delay` | Seconds between AI calls on multi-host scans | `0.5` |
| `--ai-timeout` | AI provider response timeout in seconds | `60.0` |
| `--version` | Print version | — |

---

## How It Works

**Why two AI calls?** The first call is a tightly-constrained extraction (CVE IDs only), which keeps the EPSS lookup clean. The second call synthesizes the full report with real exploit-probability data injected back in. This produces dramatically better-grounded analysis than a single pass.

---

## Network Configuration

ReconIQ uses the [`requests`](https://requests.readthedocs.io) library for all outbound HTTP calls (AI providers, EPSS API). `requests` automatically honors the standard proxy environment variables — no extra flags needed:

| Variable | Purpose |
|----------|---------|
| `HTTP_PROXY` | Proxy for plain HTTP requests |
| `HTTPS_PROXY` | Proxy for HTTPS requests (AI API calls go here) |
| `NO_PROXY` | Comma-separated list of hostnames to bypass |

**Example — route all AI/EPSS calls through Burp Suite:**
```bash
export HTTPS_PROXY=http://127.0.0.1:8080
reconiq -t 192.168.1.1
```

**Example — corporate proxy with no-proxy exclusions:**
```bash
export HTTPS_PROXY=http://proxy.corp.local:3128
export NO_PROXY=localhost,127.0.0.1,10.0.0.0/8
reconiq -t 10.10.5.20
```

TLS certificate verification uses the system CA bundle by default. To trust a custom CA (e.g., Burp's certificate), set `REQUESTS_CA_BUNDLE=/path/to/ca.pem`.

---

## Security Notes

See [SECURITY.md](SECURITY.md) for the full audit. Current notes:

- **API key storage:** Saved to OS keyring (Keychain / Secret Service / Credential Manager) via the `keyring` library. Falls back to `~/.reconiq.json` (chmod 600) if no keyring backend is available. Set `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, or `GOOGLE_API_KEY` to bypass both.
- **Banner grabbing:** v2.5+ listens first; HTTP HEAD probe is only sent as a fallback for non-speaking services.
- **Prompt injection:** Banner data is wrapped in `<<<SCAN_DATA_BEGIN>>>` / `<<<SCAN_DATA_END>>>` delimiters and the model is instructed to treat the block as data only.

---

## Legal & Ethical Use

**ReconIQ is for authorized security assessment only.** You may use it against:

- Systems and networks you personally own
- Targets for which you have **explicit, written authorization** (penetration testing engagements, bug bounty programs, etc.)
- Lab environments and intentionally vulnerable systems (HTB, VulnHub, etc.)

Unauthorized scanning is illegal in most jurisdictions (Computer Fraud and Abuse Act in the US, Computer Misuse Act in the UK, etc.). The author assumes **no liability** for misuse.

---

## Roadmap

- **v2.5 ✓:** Anthropic Claude support, additional AI providers, environment-variable API key support, smart protocol-aware banner grabbing, narrowed exception handling, `--timeout` flag, prompt-injection delimiter wrapping
- **v2.6 ✓:** OS keyring integration, authorization confirmation prompt, report chmod 600, AI call rate limiting (`--api-delay`), proxy/TLS documentation
- **v2.6.1 ✓:** `--ai-timeout` flag, HTTP error surfacing, timeout auto-retry in brief mode, partial results on synthesis failure, rotating spinner messages
- **v2.6.2 ✓:** Banner truncation fix — increased recv buffer, capture first 6 header lines (H-3)
- **v2.6.3 ✓:** Binary protocol detection — `_is_binary()` helper prevents false-positive CVEs on TLS/RDP/proprietary services (H-4)
- **v2.7:** SQLite scan history, diff mode, JSON output format
- **v3.0:** FastAPI + WebSocket dashboard for real-time scan visualization
- **v4.0+:** Possible Go/Rust rewrite for performance

---

## Acknowledgements

- **FIRST.org** for the open EPSS API and the broader EPSS framework
- **Eric Taylor** for the [EPSS lookup tool](https://epsslookuptool.com) referenced in deep-dive output
- The cybersecurity community building open-source tooling in public

---

## License

[MIT License](LICENSE) — free for personal, commercial, educational, and contracted security testing use.

---

## Author

**Nicholas Del Nero**
CompTIA Security+ certified | SOC home lab operator | aspiring incident responder

- GitHub: [@mentalEdge984](https://github.com/mentalEdge984)
- Other tools: [DBF3000](https://github.com/mentalEdge984/DBF3000) (web directory brute-forcer) | [Gridwalk](https://github.com/mentalEdge984/Gridwalk) (network port scanner) | [grumpynum](https://github.com/mentalEdge984/grumpynum) (subdomain enumerator)
