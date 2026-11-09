#!/usr/bin/env python3


from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Iterable

try:
    import dns.asyncresolver
    import dns.resolver
    import dns.zone
    import dns.query
    import dns.exception
except ImportError:
    sys.exit("[!] Missing dependency 'dnspython'. Install with: pip install -r requirements.txt")

try:
    import httpx
except ImportError:
    sys.exit("[!] Missing dependency 'httpx'. Install with: pip install -r requirements.txt")


SEV_CRITICAL = "CRÍTICO"
SEV_HIGH = "ALTO"
SEV_MEDIUM = "MÉDIO"
SEV_INFO = "INFORMATIVO"

SEV_ORDER = {SEV_CRITICAL: 0, SEV_HIGH: 1, SEV_MEDIUM: 2, SEV_INFO: 3}

SEV_COLOR = {
    SEV_CRITICAL: "\033[1;91m",   
    SEV_HIGH: "\033[91m",         
    SEV_MEDIUM: "\033[93m",       
    SEV_INFO: "\033[96m",         
}
RESET = "\033[0m"
DIM = "\033[2m"
BOLD = "\033[1m"

DEFAULT_DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2", "s1", "s2",
    "k1", "k2", "mail", "dkim", "mandrill", "mailjet", "mxvault",
    "sig1", "smtp", "zoho", "fm1", "fm2", "fm3", "pm", "pic",
]

CRTSH_URL = "https://crt.sh/?q=%25.{domain}&output=json"
HACKERTARGET_URL = "https://api.hackertarget.com/hostsearch/?q={domain}"
RAPIDDNS_URL = "https://rapiddns.io/subdomain/{domain}?full=1"

_LABEL = r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
HOSTNAME_RE = re.compile(rf"^(?:{_LABEL}\.)+{_LABEL}$")

@dataclass
class Finding:
    module: str
    severity: str
    title: str
    detail: str
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class ModuleResult:
    name: str
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    info: dict[str, Any] = field(default_factory=dict)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def err(self, msg: str) -> None:
        self.errors.append(msg)



class RateLimiter:
    """Simple async rate limiter: at most `rate` acquisitions per second."""

    def __init__(self, rate: float):
        self.rate = max(rate, 0.1)
        self.min_interval = 1.0 / self.rate
        self._lock = asyncio.Lock()
        self._next = 0.0

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            wait = self._next - now
            if wait > 0:
                await asyncio.sleep(wait)
                now = time.monotonic()
            self._next = max(now, self._next) + self.min_interval



def build_resolver(timeout: float, nameservers: list[str] | None) -> dns.asyncresolver.Resolver:
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    if nameservers:
        resolver.nameservers = nameservers
    return resolver


async def resolve(resolver, name: str, rdtype: str) -> list[str]:
    """Resolve a record type, returning string values. Empty list on NXDOMAIN/no-answer."""
    try:
        answer = await resolver.resolve(name, rdtype, raise_on_no_answer=False)
        if answer.rrset is None:
            return []
        return [r.to_text() for r in answer]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return []
    except (dns.exception.Timeout, dns.exception.DNSException):
        raise



async def module_axfr(domain: str, resolver, timeout: float) -> ModuleResult:
    res = ModuleResult(name="axfr")

    try:
        ns_records = await resolve(resolver, domain, "NS")
    except dns.exception.DNSException as e:
        res.err(f"Falha ao obter registros NS: {e}")
        return res

    ns_hosts = sorted({r.rstrip(".") for r in ns_records})
    res.info["nameservers"] = ns_hosts
    if not ns_hosts:
        res.err("Nenhum servidor NS autoritativo encontrado.")
        return res

    # Resolve each NS to IP(s).
    async def ns_ips(ns: str) -> list[str]:
        ips: list[str] = []
        for rdtype in ("A", "AAAA"):
            try:
                ips += await resolve(resolver, ns, rdtype)
            except dns.exception.DNSException:
                pass
        return ips

    ns_ip_map = dict(zip(ns_hosts, await asyncio.gather(*(ns_ips(ns) for ns in ns_hosts))))


    def attempt_axfr(ns: str, ip: str) -> tuple[bool, Any]:
        try:
            zone = dns.zone.from_xfr(dns.query.xfr(ip, domain, timeout=timeout, lifetime=timeout))
            return True, zone
        except Exception as e:  
            return False, str(e)

    for ns in ns_hosts:
        ips = ns_ip_map.get(ns) or []
        if not ips:
            res.err(f"NS {ns}: não foi possível resolver IP.")
            continue
        for ip in ips:
            ok, result = await asyncio.to_thread(attempt_axfr, ns, ip)
            if ok:
                zone = result
                names = sorted(zone.nodes.keys(), key=str)
                records: list[str] = []
                for name in names:
                    node = zone[name]
                    for rdataset in node.rdatasets:
                        for rdata in rdataset:
                            fqdn = f"{name}.{domain}".replace("@.", "").rstrip(".")
                            records.append(f"{fqdn} {dns.rdatatype.to_text(rdataset.rdtype)} {rdata.to_text()}")
                res.add(Finding(
                    module="axfr",
                    severity=SEV_CRITICAL,
                    title=f"Transferência de zona (AXFR) permitida em {ns} ({ip})",
                    detail=(
                        f"O servidor {ns} respondeu a uma solicitação AXFR e expôs "
                        f"{len(records)} registros da zona {domain}. Qualquer pessoa na "
                        f"Internet pode enumerar toda a zona DNS."
                    ),
                    evidence={"nameserver": ns, "ip": ip, "record_count": len(records),
                              "records": records[:500]},
                ))
            else:
                res.info.setdefault("refused", []).append(f"{ns} ({ip}): {result}")

    if not res.findings:
        res.add(Finding(
            module="axfr",
            severity=SEV_INFO,
            title="Transferência de zona (AXFR) negada em todos os NS",
            detail=f"Nenhum dos {len(ns_hosts)} servidores autoritativos permitiu AXFR.",
            evidence={"nameservers": ns_hosts},
        ))
    return res


def load_wordlist(path: str) -> tuple[list[str], int]:
    """Read a subdomain wordlist. Returns (valid_fqdns_or_labels, skipped_count)."""
    valid: list[str] = []
    skipped = 0
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if " " in line or "\t" in line:
                skipped += 1
                continue
            candidate = line.lower().rstrip(".")
            if HOSTNAME_RE.match(candidate) or HOSTNAME_RE.match(candidate + ".x"):
                valid.append(candidate)
            else:
                skipped += 1
    # de-dup, preserve order
    seen: set[str] = set()
    deduped = [x for x in valid if not (x in seen or seen.add(x))]
    return deduped, skipped


def normalize_subdomains(raw: Iterable[str], domain: str) -> list[str]:
    """Turn labels or FQDNs into full subdomains under `domain`."""
    out: set[str] = set()
    dsuffix = "." + domain
    for item in raw:
        host = item.strip().lower().rstrip(".")
        if not host:
            continue
        if host == domain or host.endswith(dsuffix):
            out.add(host)
        else:
            out.add(f"{host}.{domain}")
    return sorted(out)


async def passive_enum(domain: str, http: httpx.AsyncClient, res: ModuleResult) -> list[str]:
    """Enumerate subdomains via public OSINT sources. No traffic to the target."""
    found: set[str] = set()

    async def crtsh() -> None:
        try:
            r = await http.get(CRTSH_URL.format(domain=domain), timeout=25)
            if r.status_code == 200 and r.text.strip():
                for entry in r.json():
                    for nm in str(entry.get("name_value", "")).splitlines():
                        nm = nm.strip().lower().lstrip("*.")
                        if nm.endswith("." + domain) or nm == domain:
                            found.add(nm)
        except Exception as e:
            res.err(f"crt.sh indisponível: {e}")

    async def hackertarget() -> None:
        try:
            r = await http.get(HACKERTARGET_URL.format(domain=domain), timeout=25)
            if r.status_code == 200 and "API count exceeded" not in r.text:
                for line in r.text.splitlines():
                    host = line.split(",")[0].strip().lower()
                    if host.endswith("." + domain) or host == domain:
                        found.add(host)
        except Exception as e:
            res.err(f"HackerTarget indisponível: {e}")

    async def rapiddns() -> None:
        try:
            r = await http.get(RAPIDDNS_URL.format(domain=domain), timeout=25)
            if r.status_code == 200:
                for m in re.findall(r"<td>([A-Za-z0-9._-]+)</td>", r.text):
                    host = m.strip().lower()
                    if host.endswith("." + domain) or host == domain:
                        found.add(host)
        except Exception as e:
            res.err(f"RapidDNS indisponível: {e}")

    await asyncio.gather(crtsh(), hackertarget(), rapiddns())
    found.discard(domain)
    return sorted(found)


def match_fingerprint(cname: str, status: int, body: str, fingerprints: list[dict]) -> dict | None:
    cl = cname.lower().rstrip(".")
    body_l = body.lower()
    for fp in fingerprints:
        if not any(pat.lower() in cl for pat in fp.get("cname", [])):
            continue
        sigs = fp.get("fingerprint", [])
        if any(sig.lower() in body_l for sig in sigs):
            return fp
    return None


async def module_takeover(
    domain: str,
    resolver,
    http: httpx.AsyncClient,
    fingerprints: list[dict],
    subdomains_file: str | None,
    limiter: RateLimiter,
    dns_sem: asyncio.Semaphore,
    http_sem: asyncio.Semaphore,
) -> ModuleResult:
    res = ModuleResult(name="takeover")

    if subdomains_file:
        try:
            labels, skipped = load_wordlist(subdomains_file)
        except OSError as e:
            res.err(f"Não foi possível ler a wordlist: {e}")
            return res
        subdomains = normalize_subdomains(labels, domain)
        res.info["source"] = "wordlist"
        res.info["loaded"] = len(subdomains)
        res.info["skipped"] = skipped
        print(f"  {DIM}[*] {len(subdomains)} subdomínios carregados da wordlist local "
              f"({skipped} linhas ignoradas){RESET}")
    else:
        print(f"  {DIM}[*] Enumeração passiva (crt.sh, HackerTarget, RapidDNS)...{RESET}")
        passive = await passive_enum(domain, http, res)
        subdomains = normalize_subdomains(passive, domain)
        res.info["source"] = "passive"
        res.info["loaded"] = len(subdomains)
        print(f"  {DIM}[*] {len(subdomains)} subdomínios descobertos passivamente{RESET}")

    if not subdomains:
        res.add(Finding("takeover", SEV_INFO, "Nenhum subdomínio para avaliar",
                        "A fase de coleta não retornou candidatos.", {}))
        return res

    # Phase 2: CNAME resolution (only CNAME-bearing hosts are candidates).
    async def get_cname(host: str) -> tuple[str, str | None]:
        async with dns_sem:
            try:
                vals = await resolve(resolver, host, "CNAME")
                return host, (vals[0].rstrip(".") if vals else None)
            except dns.exception.DNSException:
                return host, None

    cname_pairs = await asyncio.gather(*(get_cname(h) for h in subdomains))
    candidates = [(h, c) for h, c in cname_pairs if c]
    res.info["cname_candidates"] = len(candidates)
    print(f"  {DIM}[*] {len(candidates)} subdomínios com CNAME para análise ativa{RESET}")

    async def probe(host: str, cname: str) -> None:
        async with http_sem:
            await limiter.acquire()
            body, status = "", 0
            for scheme in ("https", "http"):
                try:
                    r = await http.get(f"{scheme}://{host}", timeout=12,
                                       follow_redirects=True)
                    body, status = r.text, r.status_code
                    break
                except Exception:
                    continue
            fp = match_fingerprint(cname, status, body, fingerprints)
            if fp:
                is_vuln = fp.get("vulnerable") is True
                sev = SEV_HIGH if is_vuln else SEV_MEDIUM
                qualifier = "" if is_vuln else " (depende de configuração — confirmar manualmente)"
                res.add(Finding(
                    module="takeover",
                    severity=sev,
                    title=f"Possível subdomain takeover: {host} -> {fp['service']}{qualifier}",
                    detail=(
                        f"{host} possui CNAME para '{cname}' ({fp['service']}) e a resposta "
                        f"HTTP corresponde à assinatura de recurso não reivindicado."
                    ),
                    evidence={"host": host, "cname": cname, "service": fp["service"],
                              "http_status": status, "confirmed_vulnerable": is_vuln},
                ))

    await asyncio.gather(*(probe(h, c) for h, c in candidates))

    if not res.findings:
        res.add(Finding("takeover", SEV_INFO, "Nenhum subdomain takeover detectado",
                        f"{len(candidates)} candidatos com CNAME analisados, nenhuma assinatura vulnerável.",
                        {"candidates": len(candidates)}))
    return res


async def module_email(domain: str, resolver, selectors: list[str]) -> ModuleResult:
    res = ModuleResult(name="email")

    # --- SPF ---
    try:
        txt = await resolve(resolver, domain, "TXT")
    except dns.exception.DNSException as e:
        res.err(f"Falha ao consultar TXT: {e}")
        txt = []

    spf = next((t for t in (x.strip('"') for x in txt) if t.lower().startswith("v=spf1")), None)
    if spf is None:
        res.add(Finding("email", SEV_HIGH, "Registro SPF ausente",
                        f"{domain} não possui registro SPF. Qualquer servidor pode enviar "
                        f"e-mails em nome do domínio.", {}))
    else:
        policy = "neutro/ausente"
        sev = SEV_HIGH
        if "-all" in spf:
            policy, sev = "-all (hardfail)", SEV_INFO
        elif "~all" in spf:
            policy, sev = "~all (softfail)", SEV_MEDIUM
        elif "?all" in spf:
            policy, sev = "?all (neutro)", SEV_MEDIUM
        elif "+all" in spf:
            policy, sev = "+all (permite qualquer remetente)", SEV_HIGH
        detail = f"Política SPF: {policy}."
        if sev in (SEV_HIGH, SEV_MEDIUM):
            detail += " Política fraca ou permissiva permite spoofing."
        res.add(Finding("email", sev, f"SPF presente ({policy})", detail,
                        {"record": spf}))

    try:
        dtxt = await resolve(resolver, f"_dmarc.{domain}", "TXT")
    except dns.exception.DNSException as e:
        res.err(f"Falha ao consultar DMARC: {e}")
        dtxt = []

    dmarc = next((t for t in (x.strip('"') for x in dtxt) if t.lower().startswith("v=dmarc1")), None)
    if dmarc is None:
        res.add(Finding("email", SEV_HIGH, "Registro DMARC ausente",
                        f"_dmarc.{domain} não existe. Sem DMARC não há enforcement nem "
                        f"relatórios de abuso.", {}))
    else:
        m = re.search(r"\bp\s*=\s*(none|quarantine|reject)\b", dmarc, re.I)
        pol = m.group(1).lower() if m else "none"
        if pol == "none":
            res.add(Finding("email", SEV_HIGH, "Política DMARC = none",
                            "DMARC está em modo monitor (p=none); não bloqueia spoofing.",
                            {"record": dmarc}))
        else:
            res.add(Finding("email", SEV_INFO, f"DMARC aplicado (p={pol})",
                            f"Política DMARC '{pol}' protege contra spoofing.",
                            {"record": dmarc}))

    async def check_selector(sel: str) -> str | None:
        name = f"{sel}._domainkey.{domain}"
        try:
            vals = await resolve(resolver, name, "TXT")
        except dns.exception.DNSException:
            return None
        for v in vals:
            if "v=dkim1" in v.lower() or "p=" in v.lower():
                return sel
        return None

    sel_results = await asyncio.gather(*(check_selector(s) for s in selectors))
    found_selectors = [s for s in sel_results if s]
    if found_selectors:
        res.add(Finding("email", SEV_INFO, "Seletor(es) DKIM encontrado(s)",
                        f"Seletores DKIM ativos: {', '.join(found_selectors)}.",
                        {"selectors": found_selectors}))
    else:
        res.add(Finding("email", SEV_MEDIUM, "Nenhum seletor DKIM comum encontrado",
                        f"Nenhum dos {len(selectors)} seletores testados retornou chave DKIM. "
                        f"DKIM pode estar ausente ou usar um seletor não padrão.",
                        {"selectors_tested": selectors}))
    return res


def print_report(domain: str, modules: list[ModuleResult], use_color: bool) -> None:
    def c(code: str) -> str:
        return code if use_color else ""

    print()
    print(c(BOLD) + "=" * 70 + c(RESET))
    print(c(BOLD) + f" DNSleuth — relatório de postura DNS: {domain}" + c(RESET))
    print(c(BOLD) + "=" * 70 + c(RESET))

    all_findings: list[Finding] = []
    for mod in modules:
        all_findings.extend(mod.findings)

    counts = {s: 0 for s in SEV_ORDER}
    for f in all_findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    summary = "  ".join(
        f"{c(SEV_COLOR[s])}{s}: {counts[s]}{c(RESET)}" for s in SEV_ORDER
    )
    print(f"\n Resumo: {summary}\n")

    for mod in modules:
        print(c(BOLD) + f"[ Módulo: {mod.name} ]" + c(RESET))
        if mod.info:
            for k, v in mod.info.items():
                if isinstance(v, list) and len(v) > 8:
                    v = f"{len(v)} itens"
                print(f"   {c(DIM)}• {k}: {v}{c(RESET)}")
        for f in sorted(mod.findings, key=lambda x: SEV_ORDER.get(x.severity, 9)):
            tag = f"{c(SEV_COLOR.get(f.severity, ''))}[{f.severity}]{c(RESET)}"
            print(f"   {tag} {f.title}")
            print(f"       {c(DIM)}{f.detail}{c(RESET)}")
            if f.module == "axfr" and f.evidence.get("records"):
                recs = f.evidence["records"]
                for r in recs[:10]:
                    print(f"         {c(DIM)}{r}{c(RESET)}")
                if len(recs) > 10:
                    print(f"         {c(DIM)}... (+{len(recs) - 10} registros, ver JSON){c(RESET)}")
        for e in mod.errors:
            print(f"   {c(SEV_COLOR[SEV_INFO])}[erro]{c(RESET)} {c(DIM)}{e}{c(RESET)}")
        print()


def build_json(domain: str, modules: list[ModuleResult], started: float) -> dict:
    return {
        "tool": "DNSleuth",
        "target": domain,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "duration_seconds": round(time.monotonic() - started, 2),
        "summary": _severity_summary(modules),
        "modules": {
            m.name: {
                "info": m.info,
                "errors": m.errors,
                "findings": [asdict(f) for f in m.findings],
            }
            for m in modules
        },
    }


def _severity_summary(modules: list[ModuleResult]) -> dict[str, int]:
    counts = {s: 0 for s in SEV_ORDER}
    for m in modules:
        for f in m.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def load_fingerprints(path: str | None) -> list[dict]:
    import os
    if path is None:
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fingerprints.json")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data.get("fingerprints", data if isinstance(data, list) else [])
    except (OSError, json.JSONDecodeError) as e:
        print(f"[!] Aviso: não foi possível carregar fingerprints ({e}). "
              f"Módulo de takeover ficará limitado.", file=sys.stderr)
        return []


async def run(args: argparse.Namespace) -> int:
    started = time.monotonic()
    domain = args.domain.strip().lower().rstrip(".")
    if not HOSTNAME_RE.match(domain):
        print(f"[!] Domínio inválido: {args.domain}", file=sys.stderr)
        return 2

    checks = {"axfr", "takeover", "email"} if args.check == "all" else {args.check}
    resolver = build_resolver(args.timeout, args.nameservers.split(",") if args.nameservers else None)

    limiter = RateLimiter(args.rate_limit)
    dns_sem = asyncio.Semaphore(args.concurrency)
    http_sem = asyncio.Semaphore(args.concurrency)

    headers = {"User-Agent": "DNSleuth/1.0 (+defensive-audit)"}
    modules: list[ModuleResult] = []

    async with httpx.AsyncClient(headers=headers, verify=False, http2=False) as http:
        if "axfr" in checks:
            print(f"{BOLD}[AXFR]{RESET} Testando transferência de zona...")
            modules.append(await module_axfr(domain, resolver, args.timeout))

        if "takeover" in checks:
            print(f"{BOLD}[TAKEOVER]{RESET} Avaliando subdomain takeover...")
            fingerprints = load_fingerprints(args.fingerprints)
            modules.append(await module_takeover(
                domain, resolver, http, fingerprints, args.subdomains_file,
                limiter, dns_sem, http_sem,
            ))

        if "email" in checks:
            print(f"{BOLD}[EMAIL]{RESET} Verificando SPF / DMARC / DKIM...")
            selectors = (args.dkim_selectors.split(",") if args.dkim_selectors
                         else DEFAULT_DKIM_SELECTORS)
            modules.append(await module_email(domain, resolver, selectors))

    use_color = sys.stdout.isatty() and not args.no_color
    print_report(domain, modules, use_color)

    if args.output:
        report = build_json(domain, modules, started)
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                json.dump(report, fh, ensure_ascii=False, indent=2)
            print(f"[+] Relatório JSON salvo em: {args.output}")
        except OSError as e:
            print(f"[!] Falha ao salvar JSON: {e}", file=sys.stderr)

    # exit code reflects worst severity found
    worst = min((SEV_ORDER.get(f.severity, 9) for m in modules for f in m.findings),
                default=9)
    return 1 if worst <= SEV_ORDER[SEV_HIGH] else 0


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="DNSleuth.py",
        description="DNSleuth — auditor de postura de segurança DNS (uso autorizado apenas).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Exemplos:\n"
            "  python DNSleuth.py exemplo.com.br --check all -o report.json\n"
            "  python DNSleuth.py exemplo.com.br --check axfr\n"
            "  python DNSleuth.py exemplo.com.br --check takeover "
            "--subdomains-file subs.txt\n"
            "  python DNSleuth.py exemplo.com.br --check email\n"
        ),
    )
    p.add_argument("domain", help="Domínio alvo (ex: exemplo.com.br)")
    p.add_argument("--check", choices=["all", "axfr", "takeover", "email"],
                   default="all", help="Qual verificação executar (padrão: all)")
    p.add_argument("--subdomains-file", metavar="ARQUIVO",
                   help="Wordlist local de subdomínios (pula a enumeração passiva)")
    p.add_argument("--fingerprints", metavar="ARQUIVO",
                   help="JSON de fingerprints de takeover (padrão: fingerprints.json ao lado do script)")
    p.add_argument("--dkim-selectors", metavar="s1,s2,...",
                   help="Lista de seletores DKIM a testar (CSV). Padrão: lista comum embutida.")
    p.add_argument("-o", "--output", metavar="report.json",
                   help="Salvar relatório em JSON")
    p.add_argument("--rate-limit", type=float, default=50.0,
                   help="Requisições HTTP por segundo (padrão: 50)")
    p.add_argument("--concurrency", type=int, default=50,
                   help="Máximo de consultas DNS/HTTP simultâneas (padrão: 50)")
    p.add_argument("--timeout", type=float, default=5.0,
                   help="Timeout de DNS em segundos (padrão: 5)")
    p.add_argument("--nameservers", metavar="ip1,ip2",
                   help="Resolvers DNS a usar (CSV de IPs). Padrão: do sistema.")
    p.add_argument("--no-color", action="store_true", help="Desabilitar cores no terminal")
    return p.parse_args(argv)


def main() -> None:
    args = parse_args()
    # Silence noisy TLS warnings from verify=False (we only read error pages).
    import warnings
    warnings.filterwarnings("ignore", message="Unverified HTTPS request")
    try:
        import urllib3
        urllib3.disable_warnings()
    except Exception:
        pass
    try:
        rc = asyncio.run(run(args))
    except KeyboardInterrupt:
        print("\n[!] Interrompido pelo usuário.", file=sys.stderr)
        rc = 130
    sys.exit(rc)


if __name__ == "__main__":
    main()
