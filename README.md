# DNSleuth

DNSleuth is a read-only DNS security posture auditor. From a single command it checks a domain for three common DNS-layer weaknesses: open zone transfers (AXFR), subdomain takeover (passive enumeration or a local wordlist + CNAME fingerprinting), and weak email anti-spoofing records (SPF / DMARC / DKIM).

### What it checks

| Module | What it does | Technique |
|--------|--------------|-----------|
| **AXFR** | Discovers every authoritative NS and attempts a single zone transfer against each. A successful transfer is reported as **CRÍTICO** (critical). | Iterates all NS servers — a forgotten secondary is the usual culprit. |
| **Takeover** | Enumerates subdomains (passively, or from a local wordlist), keeps only those with a **CNAME**, then fingerprints the HTTP response against a database of known-vulnerable services (S3, GitHub Pages, Heroku, UptimeRobot, …). Matches are **ALTO**/**MÉDIO**. | Active probing is limited to CNAME-bearing hosts, minimising traffic to the target. |
| **Email** | Looks up SPF, DMARC and common DKIM selectors and grades the policy. Missing/weak records are **ALTO**; missing DKIM is **MÉDIO**. | DNS lookups only — no test emails are sent. |

Severities: `CRÍTICO` · `ALTO` · `MÉDIO` · `INFORMATIVO`.

### Installation

Requires **Python 3.10+**.

```bash
# clone / copy the files, then:
python3 -m venv .venv
source .venv/bin/activate       
pip install -r requirements.txt
```

### Usage

```bash
python DNSleuth.py <domain> [options]
```

#### Examples

```bash
# Full audit with passive enumeration, saving JSON
python DNSleuth.py exemplo.com.br --check all -o report.json

# Zone-transfer check only
python DNSleuth.py exemplo.com.br --check axfr

# Takeover check using a local wordlist (skips passive enumeration)
python DNSleuth.py exemplo.com.br --check takeover --subdomains-file subs.txt

# Email spoofing posture only
python DNSleuth.py exemplo.com.br --check email
```

### Flags

| Flag | Description | Default |
|------|-------------|---------|
| `domain` | Target domain (positional, required) | — |
| `--check {all,axfr,takeover,email}` | Which module(s) to run | `all` |
| `--subdomains-file FILE` | Local subdomain wordlist (one per line; `#` comments and blanks ignored). **Skips passive enumeration.** | — |
| `--fingerprints FILE` | Takeover fingerprint JSON | `fingerprints.json` next to the script |
| `--dkim-selectors s1,s2,...` | DKIM selectors to probe (CSV) | built-in common list |
| `-o, --output report.json` | Write JSON report | — |
| `--rate-limit N` | HTTP requests per second | `50` |
| `--concurrency N` | Max simultaneous DNS/HTTP operations | `50` |
| `--timeout N` | DNS timeout in seconds | `5` |
| `--nameservers ip1,ip2` | Custom resolvers (CSV of IPs) | system |
| `--no-color` | Disable ANSI colour | off |

**Exit code:** `1` if any `ALTO`/`CRÍTICO` finding is present, else `0` (handy for CI gates). `2` for a bad domain, `130` on Ctrl-C.

### Wordlist format

```
# comment lines are ignored
www
api
staging
blank lines ignored, lines with spaces skipped
```
Labels are expanded under the target domain; fully-qualified entries are accepted as-is. On start you'll see `X subdomínios carregados da wordlist local`.

### Updating takeover fingerprints

`fingerprints.json` is a plain list of `{service, cname[], fingerprint[], status, vulnerable}` entries, modelled on the community [`can-i-take-over-xyz`](https://github.com/EdOverflow/can-i-take-over-xyz) project. Add or edit entries freely; `"vulnerable": true` yields **ALTO**, `"edge"` yields **MÉDIO** (confirm manually).

### JSON output shape

```jsonc
{
  "tool": "DNSleuth",
  "target": "exemplo.com.br",
  "generated_at": "2026-11-07T...Z",
  "summary": { "CRÍTICO": 0, "ALTO": 2, "MÉDIO": 1, "INFORMATIVO": 3 },
  "modules": {
    "axfr":     { "info": {...}, "errors": [...], "findings": [ { "severity": "...", "title": "...", "detail": "...", "evidence": {...} } ] },
    "takeover": { ... },
    "email":    { ... }
  }
}
```

### Notes
- TLS verification is disabled for the active takeover probes on purpose — a dangling subdomain often has a mismatched/absent certificate, and only the error body is inspected.
- Failures (timeouts, unreachable OSINT sources) are recorded per module and never abort the other checks.

---DNSleuth is a read-only DNS security posture auditor. From a single command it checks a domain for three common DNS-layer weaknesses: open zone transfers (AXFR), subdomain takeover (passive enumeration or a local wordlist + CNAME fingerprinting), and weak email anti-spoofing records (SPF / DMARC / DKIM).
