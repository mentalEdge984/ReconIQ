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
| `--version` | Print version | — |

---

## How It Works

**Why two AI calls?** The first call is a tightly-constrained extraction (CVE IDs only), which keeps the EPSS lookup clean. The second call synthesizes the full report with real exploit-probability data injected back in. This produces dramatically better-grounded analysis than a single pass.

---

## Security Notes

This tool is in active development. See [SECURITY.md](SECURITY.md) for the full audit. Quick summary of v2.4 limitations:

- **API key storage:** Plaintext at `~/.reconiq.json` (chmod 600). Set `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, or `GOOGLE_API_KEY` to bypass file storage entirely. OS keyring integration arrives in v2.6.
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
- **v2.6:** OS keyring integration, configurable scan timeouts, prompt-injection hardening
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
