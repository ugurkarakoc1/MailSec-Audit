import os
from core.console import banner, ok, warn
from modules import web_owa, dns_policy, smtp_transport, smtp_policy_matrix, mail_surface_map, authenticated_send_controls
from reporting.report_md import write_markdown
from reporting.report_json import write_json
from reporting.report_html import write_html

MODULES = {
    "web/owa": web_owa,
    "dns/policy": dns_policy,
    "smtp/transport": smtp_transport,
    "smtp/policy_matrix": smtp_policy_matrix,
    "mail/surface_map": mail_surface_map,
    "mail/send_controls": authenticated_send_controls,
}

def run_all(ctx, outdir="reports", fmt="markdown"):
    os.makedirs(outdir, exist_ok=True)
    banner("MailSec-Audit (SAFE)")
    ok(f"Domain: {ctx.domain or '-'}")
    ok(f"Web   : {ctx.web or '-'}")
    ok(f"SMTP  : {ctx.smtp or '-'}")
    if ctx.single_probe:
        warn("single-probe enabled: ONE invalid web auth probe will be sent (authorized use only).")
    print()

    # Run modules best-effort
    if ctx.web:
        try: MODULES["web/owa"].run(ctx)
        except Exception as e: ctx.add_error("web/owa", str(e))
    if ctx.domain:
        try: MODULES["dns/policy"].run(ctx)
        except Exception as e: ctx.add_error("dns/policy", str(e))
    if ctx.smtp:
        try: MODULES["smtp/transport"].run(ctx)
        except Exception as e: ctx.add_error("smtp/transport", str(e))
        try: MODULES["smtp/policy_matrix"].run(ctx)
        except Exception as e: ctx.add_error("smtp/policy_matrix", str(e))
        try: MODULES["mail/surface_map"].run(ctx)
        except Exception as e: ctx.add_error("mail/surface_map", str(e))
        try: MODULES["mail/send_controls"].run(ctx)
        except Exception as e: ctx.add_error("mail/send_controls", str(e))

    paths = []
    if fmt in ("markdown", "all"):
        paths.append(write_markdown(ctx, outdir))
    if fmt in ("json", "all"):
        paths.append(write_json(ctx, outdir))
    if fmt in ("html", "all"):
        paths.append(write_html(ctx, outdir))
    return paths
