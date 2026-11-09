# DNSleuth
DNSleuth is a read-only DNS security posture auditor. From a single command it checks a domain for three common DNS-layer weaknesses: open zone transfers (AXFR), subdomain takeover (passive enumeration or a local wordlist + CNAME fingerprinting), and weak email anti-spoofing records (SPF / DMARC / DKIM).
