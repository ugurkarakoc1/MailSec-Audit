#!/usr/bin/env python3
import argparse, os, sys
ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from core.context import ScanContext
from core.runner import run_all
from core.shell import repl

def build_parser():
    p = argparse.ArgumentParser(description="MailSec-Audit (SAFE): Web + DNS Policy + SMTP Transport")
    p.add_argument("--shell", action="store_true", help="Start MSF-style interactive shell")
    p.add_argument("--domain", default="", help="Domain to assess (for DNS policy checks), e.g. example.com")
    p.add_argument("--web", default="", help="Base web URL to assess (OWA), e.g. https://mail.example.com")
    p.add_argument("--smtp", default="", help="SMTP host to assess (port 25), e.g. mail.example.com")
    p.add_argument("--timeout", type=float, default=10.0, help="Timeout seconds (default: 10)")
    p.add_argument("--format", choices=("markdown","json","html","all"), default="all", help="Report format (default: all)")
    p.add_argument("-o", "--outdir", default="reports", help="Output directory (default: reports)")
    p.add_argument("--single-probe", action="store_true", help="ONE invalid OWA auth probe (SAFE but authorized use only)")
    p.add_argument("--dkim-selectors", default="", help="Comma-separated DKIM selectors to test, e.g. s1,s2,selector1")
    return p

def main():
    args = build_parser().parse_args()
    if args.shell:
        repl()
        return

    selectors = [s.strip() for s in (args.dkim_selectors or "").split(",") if s.strip()]
    ctx = ScanContext(
        domain=args.domain.strip(),
        web=args.web.strip(),
        smtp=args.smtp.strip(),
        timeout=args.timeout,
        single_probe=args.single_probe,
        dkim_selectors=selectors,
    )
    paths = run_all(ctx, outdir=args.outdir, fmt=args.format)
    print("\nReports:")
    for pth in paths:
        print(" -", pth)

if __name__ == "__main__":
    main()
