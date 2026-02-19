import ssl
import smtplib
from core.context import Finding
from core.console import C, banner

def _check_port(host: str, port: int, timeout: float):
    res = {"port": port}
    try:
        s = smtplib.SMTP(host=host, port=port, timeout=timeout) if port != 465 else smtplib.SMTP_SSL(host=host, port=port, timeout=timeout, context=ssl.create_default_context())
        if port != 465:
            s.connect(host, port)
        s.ehlo_or_helo_if_needed()
        res["esmtp_features"] = {k: (v.decode("utf-8","ignore") if isinstance(v,(bytes,bytearray)) else str(v)) for k,v in (s.esmtp_features or {}).items()}
        res["starttls_advertised"] = ("starttls" in res["esmtp_features"])
        res["auth_advertised"] = ("auth" in res["esmtp_features"])
        # best-effort TLS for STARTTLS ports
        if port in (25,587) and res["starttls_advertised"]:
            try:
                s.starttls(context=ssl.create_default_context())
                s.ehlo()
                sock = s.sock
                res["tls"] = {
                    "version": sock.version() if sock and hasattr(sock,"version") else None,
                    "cipher": sock.cipher() if sock and hasattr(sock,"cipher") else None,
                }
            except Exception as e:
                res["tls_error"] = str(e)
        try:
            s.quit()
        except Exception:
            pass
        res["ok"] = True
    except Exception as e:
        res["ok"] = False
        res["error"] = str(e)
    return res

def run(ctx):
    if not ctx.smtp:
        return
    banner("auxiliary/scanner/smtp/transport (SAFE)")

    host = ctx.smtp
    ports = [25, 587, 465]
    ctx.results.setdefault("smtp", {})["target"] = {"host": host, "ports_tested": ports}

    print(f"{C.CY}[1/3]{C.W} SMTP discovery (25/587/465)")
    port_results = {}
    for p in ports:
        port_results[str(p)] = _check_port(host, p, ctx.timeout)
    ctx.results["smtp"]["ports"] = port_results

    # Findings
    print(f"{C.CY}[2/3]{C.W} STARTTLS/TLS değerlendirmesi")
    p25 = port_results.get("25", {})
    if p25.get("ok") and not p25.get("starttls_advertised"):
        ctx.add_finding(Finding(
            id="SMTP-TLS-001",
            category="smtp",
            title="Port 25 üzerinde STARTTLS advertise edilmiyor",
            severity="Medium",
            description="SMTP (25) EHLO yanıtında STARTTLS görülmedi.",
            recommendation="SMTP üzerinde STARTTLS'i etkinleştirin (kurum politikaları ve gateway mimarisi ile uyumlu şekilde).",
            evidence={"esmtp_features": list((p25.get("esmtp_features") or {}).keys())},
        ))
    if p25.get("ok") and p25.get("starttls_advertised") and p25.get("tls_error"):
        ctx.add_finding(Finding(
            id="SMTP-TLS-002",
            category="smtp",
            title="SMTP STARTTLS handshake/validation hatası",
            severity="Medium",
            description="STARTTLS advertise edildi ancak TLS handshake/validation başarısız oldu (client perspective).",
            recommendation="SMTP TLS sertifika zinciri/SAN ve TLS ayarlarını düzeltin.",
            evidence={"error": p25.get("tls_error")},
        ))

    print(f"{C.CY}[3/3]{C.W} AUTH advertise kontrolü (login denemesi yok)")
    # If AUTH on port 25, recommend review
    if p25.get("ok") and p25.get("auth_advertised"):
        ctx.add_finding(Finding(
            id="SMTP-AUTH-001",
            category="smtp",
            title="Port 25 üzerinde SMTP AUTH advertise ediliyor (inceleme önerilir)",
            severity="Low",
            description="SMTP sunucusu port 25 üzerinde AUTH advertise ediyor. Her zaman yanlış değildir ancak genelde AUTH submission portlarında (587/465) sınırlandırılır.",
            recommendation="Mümkünse AUTH'u submission portlarına taşıyın ve modern auth/rate limit politikaları uygulayın.",
            evidence={"auth_feature": (p25.get("esmtp_features") or {}).get("auth")},
        ))
