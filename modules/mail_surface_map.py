import socket, ssl
from core.context import Finding
from core.console import C, banner

PORTS = [
    ("POP3", 110, False),
    ("POP3S", 995, True),
    ("IMAP", 143, False),
    ("IMAPS", 993, True),
]

def _probe(host: str, port: int, tls: bool, timeout: float):
    res = {"port": port, "tls": tls, "open": False, "banner": None, "tls_version": None}
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        if tls:
            ctx = ssl.create_default_context()
            sock = ctx.wrap_socket(sock, server_hostname=host)
            res["tls_version"] = sock.version()
        try:
            data = sock.recv(256)
            if data:
                res["banner"] = data.decode("utf-8", "ignore").strip()
        except Exception:
            pass
        res["open"] = True
        try:
            sock.close()
        except Exception:
            pass
    except Exception as e:
        res["error"] = str(e)
    return res

def run(ctx):
    if not ctx.smtp:
        return
    banner("auxiliary/scanner/mail/surface_map (SAFE)")
    host = ctx.smtp
    results = {}
    exposed = []
    for name, port, tls in PORTS:
        r = _probe(host, port, tls, ctx.timeout)
        results[name] = r
        if r.get("open"):
            exposed.append(name)
    ctx.results.setdefault("mail_surface", {})["services"] = results

    if exposed:
        ctx.add_finding(Finding(
            id="MAIL-SURF-001",
            category="mail",
            title="Ek mail protokolleri erişilebilir (POP3/IMAP)",
            severity="Low",
            description="SMTP dışında POP3/IMAP servisleri dış ağdan erişilebilir görünüyor. Bu her zaman yanlış değildir; ancak saldırı yüzeyini artırır ve legacy auth risklerini büyütebilir.",
            recommendation="Gerçek ihtiyaç yoksa POP3/IMAP'i kapatın veya yalnızca iç ağ/VPN'e kısıtlayın. Modern auth ve MFA politikalarını uygulayın.",
            evidence={"exposed": exposed, "details": results},
        ))
