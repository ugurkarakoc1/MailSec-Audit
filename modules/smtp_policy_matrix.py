from core.context import Finding
from core.console import C, banner

def run(ctx):
    if not ctx.smtp:
        return
    banner("auxiliary/scanner/smtp/policy_matrix (SAFE)")

    ports = (ctx.results.get("smtp", {}) or {}).get("ports", {}) or {}
    matrix = {}
    for pstr, pres in ports.items():
        if not isinstance(pres, dict):
            continue
        matrix[pstr] = {
            "ok": bool(pres.get("ok")),
            "starttls_advertised": bool(pres.get("starttls_advertised")),
            "auth_advertised": bool(pres.get("auth_advertised")),
            "tls_version": ((pres.get("tls") or {}).get("version") if isinstance(pres.get("tls"), dict) else None),
            "tls_error": pres.get("tls_error"),
        }
    ctx.results.setdefault("smtp_policy", {})["matrix"] = matrix

    p25 = matrix.get("25", {})
    if p25.get("ok") and p25.get("auth_advertised") and not p25.get("starttls_advertised"):
        ctx.add_finding(Finding(
            id="SMTP-POL-001",
            category="smtp",
            title="Port 25 üzerinde AUTH advertise ediliyor ancak STARTTLS yok",
            severity="High",
            description="EHLO yanıtında AUTH görülürken STARTTLS advertise edilmedi. Bu durum yanlış istemci konfigürasyonlarında kimlik bilgilerinin şifrelenmeden iletilmesine yol açabilir.",
            recommendation="AUTH'u port 25'ten kaldırın veya STARTTLS'i zorunlu kılın. AUTH'u submission portlarına (587/465) taşıyın ve modern auth / rate-limit uygulayın.",
            evidence={"port": 25, "matrix": p25},
        ))
    elif p25.get("ok") and p25.get("auth_advertised") and p25.get("starttls_advertised"):
        ctx.add_finding(Finding(
            id="SMTP-POL-002",
            category="smtp",
            title="Port 25 üzerinde AUTH advertise ediliyor (politika gözden geçirilmeli)",
            severity="Low",
            description="Port 25 üzerinde AUTH advertise ediliyor. Bu her zaman yanlış değildir; ancak genellikle AUTH yalnızca submission portlarında (587/465) sınırlandırılır.",
            recommendation="Mümkünse AUTH'u submission portlarına taşıyın. STARTTLS zorunluluğu ve modern auth politikaları uygulayın.",
            evidence={"port": 25, "matrix": p25},
        ))

    p587 = matrix.get("587", {})
    if p587.get("ok") and not p587.get("starttls_advertised"):
        ctx.add_finding(Finding(
            id="SMTP-POL-003",
            category="smtp",
            title="Submission portu 587 üzerinde STARTTLS advertise edilmiyor",
            severity="Medium",
            description="Port 587 (submission) üzerinde STARTTLS advertise edilmedi.",
            recommendation="587 üzerinde STARTTLS'i etkinleştirin ve mümkünse TLS olmadan AUTH'a izin vermeyin.",
            evidence={"port": 587, "matrix": p587},
        ))
