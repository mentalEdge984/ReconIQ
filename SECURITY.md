# ReconIQ Security Audit — v2.4 (Initial Public Release)

This document tracks known security and code-quality issues identified at v2.4. Each item links to the version where it will be addressed.

## High Severity

### H-1 — API key plaintext storage
**Status:** Documented (will fix in v2.5/v2.6)
**Location:** `save_config()` writes `~/.reconiq.json` with raw key in JSON
**Impact:** Anyone with read access to the user's home directory could read stored API keys. The file is `chmod 600`, limiting damage to the user themselves and root, but this is below industry standard for credential storage.
**v2.5 fix:** Read from environment variables (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GOOGLE_API_KEY`) before falling back to the config file.
**v2.6 fix:** OS keyring integration via the `keyring` library (Keychain on macOS, Secret Service on Linux, Credential Manager on Windows).

### H-2 — Bare `except: pass` swallows all errors
**Status:** Will fix in v2.5
**Location:** 7 occurrences across `load_config`, `scan_and_grab`, `get_cves_from_ai`, `fetch_epss_data`
**Impact:** Hides bugs and security-relevant errors (TLS failures, auth errors, malformed responses).
**v2.5 fix:** Narrow each handler to expected exceptions: `socket.timeout`, `ConnectionRefusedError`, `requests.RequestException`, `json.JSONDecodeError`, `KeyError`.

## Medium Severity

### M-1 — HTTP probe blasted at every port
**Status:** Will fix in v2.5
**Location:** `scan_and_grab()` always sends `HEAD / HTTP/1.0\r\n\r\n`
**Impact:** Corrupts banners on protocols where the server speaks first (SSH, SMTP, FTP, etc.) and increases IDS/IPS detection likelihood.
**v2.5 fix:** Receive first with a short timeout. If nothing arrives, send the HTTP HEAD as a fallback.

### M-2 — Prompt injection via banner content
**Status:** Will fix in v2.5
**Location:** `get_cves_from_ai()` and `analyze_with_ai()` interpolate raw banners directly
**Impact:** A hostile banner could attempt to redirect AI output. Risk is low because the AI cannot take actions, but it could shape reports misleadingly.
**v2.5 fix:** Wrap untrusted banner data in clear delimiters and instruct the model that the contents are data, not instructions.

### M-3 — No proxy / TLS configurability
**Status:** Will document in v2.5, configurable in v2.6
**Note:** `requests` already honors `HTTP_PROXY` / `HTTPS_PROXY` environment variables, but this is undocumented.

### M-4 — Hardcoded 1.5s socket timeout
**Status:** Will fix in v2.5
**Impact:** Slow on filtered networks. /24 sweep × 1000 ports could approach 25 minutes worst-case.
**v2.5 fix:** Add `--timeout` flag.

## Low Severity

### L-1 — No rate limiting on AI/EPSS calls
Subnet sweeps can burn through API quota quickly. Add token bucket in v2.7.

### L-2 — No authorization confirmation prompt
Other tools in this author's portfolio (DBF3000) prompt for authorization confirmation; ReconIQ should match. v2.5 will add a `--i-have-permission` flag for any scan against more than a /28.

### L-3 — Output report files written without permission restrictions
v2.5 will `chmod 600` saved reports.

## Informational

- Spinner uses a global flag (works but not textbook thread-safe; in practice fine for this use)
- `parse_ports` does not validate range bounds (could pass port 99999 without error)
- No structured logging — everything goes to stdout

---

**Last reviewed:** v2.4.0 (initial public release)
