# ReconIQ

**AI-Powered Network Vulnerability Analyzer with Real-World Risk Scoring**

ReconIQ is a Python-based network analysis tool that combines fast multi-threaded port scanning, AI-driven CVE extraction, and probabilistic exploit scoring via the FIRST.org EPSS API. It produces actionable threat reports with real-world exploit-likelihood data — not just static severity ratings.

> Built by a Security+ certified practitioner running a custom SOC home lab (`ironforge.corp`).

---

## Features

- **Multi-Threaded Scanning:** Fast TCP banner grabbing across single hosts or full subnets (CIDR supported)
- **AI CVE Extraction:** Uses OpenAI, Google Gemini, or Anthropic Claude to identify the most critical CVEs from scan output — with automatic exponential backoff and provider fallback on sustained failure
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

Run tests with: `pytest test_reconiq.py -v`

> **Free-tier API users:** If you hit rate limits, use `--api-delay 10` to add a 10-second pause between AI calls on multi-host scans.

---

## How It Works

**Why two AI calls?** The first call is a tightly-constrained extraction (CVE IDs only), which keeps the EPSS lookup clean. The second call synthesizes the full report with real exploit-probability data injected back in. This produces dramatically better-grounded analysis than a single pass.

### Internal Utilities

| Helper | Purpose |
|--------|---------|
| `_recv_until(sock, timeout, max_bytes=16384)` | Loops `recv()` until HTTP header terminator (`\r\n\r\n` or `\n\n`), timeout, or byte cap. Never raises — returns whatever arrived. Used by both banner-grab paths in `scan_and_grab()`. |
| `severity_color(cvss=None, epss_pct=None)` | Returns `(ansi_color, badge_string)` for the worst severity derived from either or both inputs. Used by `render_markdown_to_terminal()` to prepend colored badges to CVSS and EPSS lines in AI reports. |
| `_parse_summary(report_text)` | Extracts the `RECONIQ_SUMMARY_START/END` block from AI output. Returns `(dict, stripped_body)` or `(None, report_text)` if absent or malformed. |
| `_render_summary(summary_dict, target_ip)` | Renders the 68-char executive summary box with risk badge, service counts, CVSS/EPSS highs, evidence basis, headline, and action item. Returns `""` when `summary_dict` is `None`. |
| `_render_cve_priority_list(cve_list, epss_data, report_body)` | Renders a `╭─╮` CVE panel sorted by EPSS descending. Each row shows a severity badge, CVE ID, EPSS %, CVSS score, and inline description extracted from the report body. Returns `""` when `cve_list` is empty. |
| `_render_confidence_warning(evidence_basis)` | Returns a yellow five-line warning block when `evidence_basis` is `Port-signature-only` or `Mixed`, flagging that CVE associations are speculative. |

---

## Sample Output

Every scan produces a structured terminal report. The executive summary box appears first, followed by the CVE priority panel and the full AI analysis.

```
╔══════════════════════════════════════════════════════════════════╗
║  RECONIQ // EXECUTIVE SUMMARY — 192.168.1.10                     ║
╠══════════════════════════════════════════════════════════════════╣
║  Overall Risk:      🔴 CRITICAL                                   ║
║  Services Found:    4                                             ║
║  Critical CVEs:     3                                             ║
║  Highest CVSS:      10.0                                         ║
║  Highest EPSS:      94.41% (30-day exploit probability)          ║
║  Evidence Basis:    Banner-identified                             ║
╠══════════════════════════════════════════════════════════════════╣
║  Three unpatched RCE vulnerabilities on a Windows SMB host.      ║
║                                                                   ║
║  →  Apply MS17-010 patches and disable SMBv1 immediately.        ║
╚══════════════════════════════════════════════════════════════════╝

╭─ CVE PRIORITY LIST — sorted by exploit probability ────────────╮
│                                                                  │
│  🔴 CRITICAL    CVE-2017-0144  EPSS: 94.41%  CVSS: 10.0        │
│             EternalBlue SMB remote code execution               │
│                                                                  │
│  🟠 HIGH        CVE-2020-0796  EPSS: 41.20%  CVSS: 10.0        │
│             SMBGhost pre-auth RCE in SMBv3 compression          │
│                                                                  │
╰──────────────────────────────────────────────────────────────────╯
```

When no software banner is identified, a confidence note is printed before the full report:

```
  ⚠ CONFIDENCE NOTE
  No software banner was identified on this host. CVE associations
  are based on port signatures only and may not reflect the actual
  software stack. Verify the software running on each port before
  acting on these findings.
```

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
- **v2.6.4 ✓:** H-5 fix — sendall() OSError now returns an explicit probe-failed banner, distinguishing it from a genuine quiet service; pytest suite wired to CI
- **v2.7.0 ✓:** H-6 recv loop fix (`_recv_until()`), exponential backoff on AI 429/503, provider fallback on sustained failure, colored CVSS/EPSS severity badges (`severity_color()`), executive summary box with risk metrics, CVE priority panel sorted by EPSS, confidence context warning for port-signature-only evidence, visual h1/h2/h3 header hierarchy in terminal reports
- **v2.8:** SQLite scan history, diff mode, JSON output format
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
