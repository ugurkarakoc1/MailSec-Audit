from typing import List, Dict
import dns.resolver
import dns.reversename
from core.context import Finding
from core.console import C, banner

def _records(name: str, rtype: str) -> List[str]:
    try:
        ans = dns.resolver.resolve(name, rtype)
        return [str(r).strip() for r in ans]
    except Exception:
        return []

def _txt(domain: str) -> List[str]:
    try:
        ans = dns.resolver.resolve(domain, "TXT")
        out = []
        for r in ans:
            s = "".join([b.decode("utf-8", "ignore") if isinstance(b, (bytes, bytearray)) else str(b) for b in getattr(r, "strings", [])]) if getattr(r, "strings", None) else str(r)
            out.append(s.strip('"'))
        return out
    except Exception:
        return []

def run(ctx):
    if not ctx.domain:
        return
    banner("auxiliary/scanner/dns/policy (SAFE)")

    # [1/6] Mail routing discovery (MX + host IPs)
    print(f"{C.CY}[1/6]{C.W} Mail routing discovery (MX/A/AAAA/PTR)")
    mx = _records(ctx.domain, "MX")
    a = _records(ctx.domain, "A")
    aaaa = _records(ctx.domain, "AAAA")
    ctx.results.setdefault("dns", {})["discovery"] = {"mx": mx, "a": a, "aaaa": aaaa}

    # PTR best-effort for A records
    ptr_map = {}
    for ip in a[:5]:
        try:
            rev = dns.reversename.from_address(ip)
            ptr = _records(str(rev), "PTR")
            if ptr:
                ptr_map[ip] = ptr
        except Exception:
            pass
    if ptr_map:
        ctx.results["dns"]["discovery"]["ptr"] = ptr_map

    # [2/6] SPF
    print(f"{C.CY}[2/6]{C.W} SPF")
    spf = [t for t in _txt(ctx.domain) if "v=spf1" in t.lower()]
    ctx.results["dns"]["spf"] = spf
    if not spf:
        ctx.add_finding(Finding(
            id="DNS-SPF-001",
            category="dns",
            title="SPF kaydı bulunamadı",
            severity="Medium",
            description="Domain üzerinde SPF (v=spf1) TXT kaydı tespit edilemedi.",
            recommendation="Yetkili mail göndericileri içeren bir SPF kaydı yayınlayın ve olgunlaşma sonrası '-all' ile sonlandırın.",
            evidence={"domain": ctx.domain},
        ))
    else:
        if not any(" -all" in (" "+s.lower()) for s in spf):
            ctx.add_finding(Finding(
                id="DNS-SPF-002",
                category="dns",
                title="SPF politikası sıkı değil (-all yok)",
                severity="Low",
                description="SPF kaydı mevcut ancak '-all' mekanizması görülmedi (heuristic).",
                recommendation="Geçiş tamamlandıktan sonra SPF'i '-all' ile sıkılaştırmayı değerlendirin.",
                evidence={"spf": spf[:3]},
            ))

    # [3/6] DMARC
    print(f"{C.CY}[3/6]{C.W} DMARC")
    dmarc_domain = f"_dmarc.{ctx.domain}"
    dmarc = [t for t in _txt(dmarc_domain) if "v=dmarc1" in t.lower()]
    ctx.results["dns"]["dmarc"] = dmarc
    if not dmarc:
        ctx.add_finding(Finding(
            id="DNS-DMARC-001",
            category="dns",
            title="DMARC kaydı bulunamadı",
            severity="Medium",
            description="_dmarc.<domain> altında DMARC TXT kaydı tespit edilemedi.",
            recommendation="DMARC kaydı yayınlayın (raporlama adresi ile). 'p=none' ile başlayıp 'quarantine/reject' seviyesine ilerleyin.",
            evidence={"name": dmarc_domain},
        ))
    else:
        d = dmarc[0].lower()
        if "p=reject" not in d and "p=quarantine" not in d:
            ctx.add_finding(Finding(
                id="DNS-DMARC-002",
                category="dns",
                title="DMARC politikası enforcing değil (p=none)",
                severity="Low",
                description="DMARC kaydı mevcut ancak enforcing politika görülmedi (p=none).",
                recommendation="Monitoring sonrası p=quarantine ve p=reject seviyesine ilerleyin.",
                evidence={"dmarc": dmarc[0]},
            ))

    # [4/6] DKIM (selectors)
    print(f"{C.CY}[4/6]{C.W} DKIM (selector denemeleri)")
    selectors = ctx.dkim_selectors or ["default", "selector1", "selector2", "dkim"]
    found = {}
    for sel in selectors:
        name = f"{sel}._domainkey.{ctx.domain}"
        txts = _txt(name)
        if txts:
            found[sel] = txts[:2]
    ctx.results["dns"]["dkim"] = {"tested_selectors": selectors, "found": found}
    if not found:
        ctx.add_finding(Finding(
            id="DNS-DKIM-001",
            category="dns",
            title="DKIM kaydı bulunamadı (heuristic)",
            severity="Low",
            description="Test edilen yaygın selector'larda DKIM TXT kaydı bulunamadı. Selector farklı olabilir (false negative).",
            recommendation="DKIM etkinliğini doğrulayın ve gerçek selector'lar ile kontrol edin; _domainkey TXT kayıtlarını yayınlayın.",
            evidence={"tested": selectors},
        ))

    # [5/6] MTA-STS
    print(f"{C.CY}[5/6]{C.W} MTA-STS")
    mta_sts = [t for t in _txt(f"_mta-sts.{ctx.domain}") if "v=sts" in t.lower()]
    ctx.results["dns"]["mta_sts_txt"] = mta_sts
    if not mta_sts:
        ctx.add_finding(Finding(
            id="DNS-MTA-STS-001",
            category="dns",
            title="MTA-STS TXT kaydı bulunamadı",
            severity="Info",
            description="_mta-sts.<domain> altında MTA-STS TXT kaydı bulunamadı (her kurum için zorunlu değildir, önerilir).",
            recommendation="MTA-STS uygulamasını ve https://mta-sts.<domain>/.well-known/mta-sts.txt politikasını değerlendirin.",
            evidence={"name": f"_mta-sts.{ctx.domain}"},
        ))

    # [6/6] TLS-RPT
    print(f"{C.CY}[6/6]{C.W} TLS-RPT")
    tls_rpt = [t for t in _txt(f"_smtp._tls.{ctx.domain}") if "v=tlsrptv1" in t.lower()]
    ctx.results["dns"]["tls_rpt"] = tls_rpt
    if not tls_rpt:
        ctx.add_finding(Finding(
            id="DNS-TLS-RPT-001",
            category="dns",
            title="TLS-RPT kaydı bulunamadı",
            severity="Info",
            description="_smtp._tls.<domain> altında TLS-RPT TXT kaydı bulunamadı.",
            recommendation="SMTP TLS hatalarını raporlamak için TLS-RPT yapılandırmasını değerlendirin.",
            evidence={"name": f"_smtp._tls.{ctx.domain}"},
        ))
