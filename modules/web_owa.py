import requests
import re
from core.context import Finding
from core.utils import normalize_base_url
from core.console import C, banner

CANDIDATES = [
    "/",
    "/owa/",
    "/ecp/",
    "/EWS/Exchange.asmx",
    "/autodiscover/autodiscover.xml",
    "/Microsoft-Server-ActiveSync",
]

RECOMMENDED_HEADERS = {
    "Strict-Transport-Security": "Enable HSTS on HTTPS responses.",
    "Content-Security-Policy": "Add CSP (or at minimum frame-ancestors) suitable for OWA publishing.",
    "X-Content-Type-Options": "Set X-Content-Type-Options: nosniff.",
    "Referrer-Policy": "Set a strict Referrer-Policy (e.g., strict-origin-when-cross-origin).",
    "Permissions-Policy": "Set a restrictive Permissions-Policy.",
}

# Headers that may reveal internal hostnames (common in Exchange/OWA deployments)
BACKEND_HEADER_KEYS = [
    "X-FEServer",
    "X-DiagInfo",
    "X-CalculatedBETarget",
    "X-BackendServer",
    "X-OWA-Version",
    "X-Powered-By",
    "X-AspNet-Version",
    "Server",
]

LOGIN_PATHS = ["/owa/auth/logon.aspx", "/owa/"]

MFA_HINT_PATTERNS = [
    r"\bmfa\b",
    r"\b2fa\b",
    r"two[-\s]?factor",
    r"authenticator",
    r"verification\s*code",
    r"one[-\s]?time\s*password",
    r"\botp\b",
]

def _get_tls_fallback(session, url: str, timeout: float, allow_redirects: bool = False):
    """Try verify=True first; if certificate validation fails, retry with verify=False.
    Returns (response, insecure_used, error_str)."""
    try:
        r = session.get(url, timeout=timeout, allow_redirects=allow_redirects, verify=True)
        return r, False, None
    except requests.exceptions.SSLError as e:
        # Retry insecure to capture HTTP behavior for reporting purposes
        try:
            r = session.get(url, timeout=timeout, allow_redirects=allow_redirects, verify=False)
            return r, True, str(e)
        except Exception as e2:
            return None, False, f"{e} | retry_failed: {e2}"
    except Exception as e:
        return None, False, str(e)


def _extract_backend_hints(headers: dict) -> dict:
    out = {}
    for k in BACKEND_HEADER_KEYS:
        if k in headers:
            out[k] = headers.get(k)
    # Heuristic: detect hostname-like tokens
    joined = " ".join([str(v) for v in out.values() if v])
    hostnames = set()
    for m in re.findall(r"\b[a-zA-Z0-9][a-zA-Z0-9\-]{1,30}\\\\[a-zA-Z0-9_\-]{1,30}\b", joined):
        hostnames.add(m)
    for m in re.findall(r"\b[A-Za-z0-9\-]{1,63}(?:\.[A-Za-z0-9\-]{1,63})+\b", joined):
        hostnames.add(m)
    out["hostname_hints"] = sorted(hostnames)[:20]
    return out

def _mfa_heuristic(page_text: str) -> bool:
    t = (page_text or "").lower()
    for pat in MFA_HINT_PATTERNS:
        if re.search(pat, t, flags=re.IGNORECASE):
            return True
    # Some common words in TR/EN flows
    if "doğrulama kodu" in t or "tek kullanımlık" in t:
        return True
    return False

def run(ctx):
    if not ctx.web:
        return
    base = normalize_base_url(ctx.web)
    ctx.results.setdefault("web", {})["base_url"] = base

    banner("auxiliary/scanner/http/owa (SAFE)")

    # [1/6] Discovery
    print(f"{C.CY}[1/6]{C.W} Endpoint discovery")
    s = requests.Session()
    disc = {}
    for p in CANDIDATES:
        url = base.rstrip("/") + p
        try:
            r, insecure_used, tls_error = _get_tls_fallback(s, url, ctx.timeout, allow_redirects=False)
            if r is None:
                raise Exception(tls_error or "request_failed")
            disc[p] = {"status": r.status_code, "location": r.headers.get("Location"), "server": r.headers.get("Server")}
            if insecure_used:
                disc[p]["insecure_used"] = True
                disc[p]["tls_verify_error"] = tls_error
        except Exception as e:
            disc[p] = {"error": str(e)}
    ctx.results["web"]["discovery"] = disc

    # [2/6] TLS basic
    print(f"{C.CY}[2/6]{C.W} TLS basic (client validation)")
    try:
        r = s.get(base + "/", timeout=ctx.timeout, allow_redirects=True, verify=True)
        ctx.results["web"]["tls_basic"] = {"final_url": r.url, "status": r.status_code}
        if not r.url.lower().startswith("https://"):
            ctx.add_finding(Finding(
                id="WEB-TLS-001",
                category="web",
                title="HTTPS not enforced",
                severity="High",
                description="Final URL after redirects is not HTTPS.",
                recommendation="Force HTTPS and enable HSTS at the edge/reverse proxy/OWA publishing layer.",
                evidence={"final_url": r.url},
            ))
    except requests.exceptions.SSLError as e:
        ctx.add_finding(Finding(
            id="WEB-TLS-002",
            category="web",
            title="TLS certificate validation failed",
            severity="High",
            description="TLS certificate chain validation failed from client perspective.",
            recommendation="Fix certificate chain (include intermediate), SAN/CN mismatch, expired cert, or untrusted CA.",
            evidence={"error": str(e)},
        ))
        ctx.results["web"]["tls_basic"] = {"error": str(e)}

    # [3/6] Header fingerprinting (SAFE)
    print(f"{C.CY}[3/6]{C.W} Fingerprinting headers (possible internal host leakage)")
    try:
        r = s.get(base + "/owa/", timeout=ctx.timeout, allow_redirects=True, verify=True)
        headers = {k: v for k, v in r.headers.items()}
        hints = _extract_backend_hints(headers)
        ctx.results["web"]["fingerprint"] = {
            "url": r.url,
            "status": r.status_code,
            "headers_selected": hints,
            "insecure_used": bool(insecure_used),
            "tls_verify_error": tls_error,
        }
        if hints.get("hostname_hints"):
            ctx.add_finding(Finding(
                id="WEB-INF-001",
                category="web",
                title="Potential internal hostname disclosure via HTTP headers",
                severity="Low",
                description="Response headers contain values that appear to disclose internal hostnames or backend identifiers (heuristic).",
                recommendation="Review and minimize information leakage at reverse proxy / load balancer. Remove or rewrite diagnostic headers when possible.",
                evidence={"headers_selected": hints},
            ))
    except Exception as e:
        ctx.add_error("web.fingerprint", str(e))

    # [4/6] Security headers on /owa/
    print(f"{C.CY}[4/6]{C.W} Security headers on /owa/")
    try:
        r = s.get(base + "/owa/", timeout=ctx.timeout, allow_redirects=True, verify=True)
        headers = {k: v for k, v in r.headers.items()}
        ctx.results["web"]["headers"] = {"url": r.url, "status": r.status_code, "headers": headers}
        for h, rec in RECOMMENDED_HEADERS.items():
            if h not in headers:
                ctx.add_finding(Finding(
                    id=f"WEB-HDR-{h.upper().replace('-','')}",
                    category="web",
                    title=f"Missing security header: {h}",
                    severity="High" if h == "Strict-Transport-Security" else "Medium",
                    description=f"Response does not include {h}.",
                    recommendation=rec,
                    evidence={"url": r.url},
                ))
    except Exception as e:
        ctx.add_error("web.headers", str(e))

    # [5/6] Cookie flags
    print(f"{C.CY}[5/6]{C.W} Cookie flags (heuristic) on /owa/")
    try:
        r = s.get(base + "/owa/", timeout=ctx.timeout, allow_redirects=True, verify=True)
        sc = r.headers.get("Set-Cookie")
        ctx.results["web"]["cookies"] = {"url": r.url, "set_cookie": sc}
        if sc:
            low = sc.lower()
            if "secure" not in low:
                ctx.add_finding(Finding(
                    id="WEB-CK-001",
                    category="web",
                    title="Cookie missing Secure flag (possible)",
                    severity="Medium",
                    description="Set-Cookie does not appear to include Secure.",
                    recommendation="Ensure auth/session cookies include Secure when served over HTTPS.",
                    evidence={"set_cookie": sc[:500]},
                ))
            if "httponly" not in low:
                ctx.add_finding(Finding(
                    id="WEB-CK-002",
                    category="web",
                    title="Cookie missing HttpOnly flag (possible)",
                    severity="Medium",
                    description="Set-Cookie does not appear to include HttpOnly.",
                    recommendation="Set HttpOnly on auth/session cookies to reduce XSS impact.",
                    evidence={"set_cookie": sc[:500]},
                ))
            if "samesite" not in low:
                ctx.add_finding(Finding(
                    id="WEB-CK-003",
                    category="web",
                    title="Cookie missing SameSite attribute (possible)",
                    severity="Low",
                    description="Set-Cookie does not appear to include SameSite.",
                    recommendation="Set SameSite=Lax/Strict where compatible; document exceptions.",
                    evidence={"set_cookie": sc[:500]},
                ))
    except Exception as e:
        ctx.add_error("web.cookies", str(e))

    # [6/6] Auth policy + MFA heuristic
    print(f"{C.CY}[6/6]{C.W} Auth policy & MFA heuristic (SAFE)")
    try:
        login_url, page_text = None, ""
        for p in LOGIN_PATHS:
            r = s.get(base + p, timeout=ctx.timeout, verify=True, allow_redirects=True)
            page_text = r.text or ""
            if "logon" in page_text.lower() or "password" in page_text.lower():
                login_url = r.url
                break

        mfa_hint = _mfa_heuristic(page_text)
        ctx.results["web"]["auth_form"] = {"login_url": login_url, "mfa_hint": mfa_hint}

        # Report MFA not detected (heuristic)
        if not mfa_hint:
            ctx.add_finding(Finding(
                id="WEB-AUTH-002",
                category="web",
                title="MFA not detected in OWA login flow (heuristic)",
                severity="Medium",
                description="No clear MFA indicators were detected in the OWA login page/flow. This may be a false negative depending on deployment (e.g., MFA enforced upstream).",
                recommendation="Confirm MFA enforcement for OWA access (IdP/Reverse proxy/Entra ID/ADFS). If MFA is required, ensure it is consistently enforced and tested.",
                evidence={"login_url": login_url},
            ))

        # Optional: ONE invalid probe only; no loops
        if ctx.single_probe and login_url:
            import time as _t
            t0 = _t.time()
            resp = s.post(login_url, data={"username":"test.user","password":"InvalidPassword123!"}, timeout=ctx.timeout, allow_redirects=False, verify=True)
            dt = _t.time()-t0
            signals = []
            if dt > 1.5:
                signals.append("Possible delay/throttling")
            if resp.status_code in (429,403):
                signals.append("Request throttling/blocking (HTTP 429/403)")
            if "locked" in (resp.text or "").lower():
                signals.append("Lockout messaging hint")
            ctx.results["web"]["auth_probe"] = {"status": resp.status_code, "response_time_ms": int(dt*1000), "location": resp.headers.get("Location"), "signals": signals}
            if signals:
                ctx.add_finding(Finding(
                    id="WEB-AUTH-001",
                    category="web",
                    title="Authentication protection signals observed",
                    severity="Low",
                    description="Single safe probe indicates protective controls in the auth flow (heuristic).",
                    recommendation="Verify rate-limiting, MFA, and lockout policies are consistently enforced and monitored.",
                    evidence=ctx.results["web"]["auth_probe"],
                ))
    except Exception as e:
        ctx.add_error("web.auth_policy", str(e))
