from dataclasses import dataclass, field
from typing import Dict, Optional, List
import shlex

from core.context import ScanContext
from core.console import banner, ok, warn, bad
from core.runner import MODULES, run_all

@dataclass
class Session:
    current: Optional[str] = None
    options: Dict[str, str] = field(default_factory=dict)

def _prompt(sess: Session) -> str:
    if sess.current:
        return f"mailsec ({sess.current}) > "
    return "mailsec > "

def _show_modules():
    banner("Available modules")
    for k in MODULES.keys():
        print(f"  - {k}")

def _show_options(sess: Session):
    banner("Options")
    for k in ["DOMAIN","WEB","SMTP","TIMEOUT","FORMAT","OUTDIR","SINGLE_PROBE","DKIM_SELECTORS"]:
        v = sess.options.get(k, "")
        print(f"  {k:14s} {v}")

def _build_ctx(sess: Session) -> ScanContext:
    dom = sess.options.get("DOMAIN","").strip()
    web = sess.options.get("WEB","").strip()
    smtp = sess.options.get("SMTP","").strip()
    timeout = float(sess.options.get("TIMEOUT","10") or "10")
    fmt = sess.options.get("FORMAT","all") or "all"
    outdir = sess.options.get("OUTDIR","reports") or "reports"
    single = (sess.options.get("SINGLE_PROBE","false").lower() in ("1","true","yes","on"))
    sels = [s.strip() for s in (sess.options.get("DKIM_SELECTORS","") or "").split(",") if s.strip()]
    ctx = ScanContext(domain=dom, web=web, smtp=smtp, timeout=timeout, single_probe=single, dkim_selectors=sels)
    return ctx

def repl():
    sess = Session(options={"TIMEOUT":"10","FORMAT":"all","OUTDIR":"reports","SINGLE_PROBE":"false"})
    banner("MailSec-Audit Shell (SAFE)")
    ok("Type 'help' for commands.")
    while True:
        try:
            line = input(_prompt(sess)).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not line:
            continue
        parts = shlex.split(line)
        cmd = parts[0].lower()
        args = parts[1:]

        if cmd in ("exit","quit"):
            break
        if cmd == "help":
            print("""Commands:
  show modules               - list modules
  use <module>               - select module (web/owa, dns/policy, smtp/transport)
  back                       - deselect module
  show options               - show current options
  set <KEY> <VALUE>          - set option (DOMAIN, WEB, SMTP, TIMEOUT, FORMAT, OUTDIR, SINGLE_PROBE, DKIM_SELECTORS)
  run                        - run selected module (or all if none selected)
  unset <KEY>                - unset an option
  exit                       - exit shell
""")
            continue
        if cmd == "show" and args and args[0] == "modules":
            _show_modules()
            continue
        if cmd == "show" and args and args[0] == "options":
            _show_options(sess)
            continue
        if cmd == "use" and args:
            mod = args[0]
            if mod not in MODULES:
                bad("Unknown module. Use: show modules")
            else:
                sess.current = mod
                ok(f"Using {mod}")
            continue
        if cmd == "back":
            sess.current = None
            continue
        if cmd == "set" and len(args) >= 2:
            k = args[0].upper()
            v = " ".join(args[1:])
            sess.options[k] = v
            ok(f"{k} => {v}")
            continue
        if cmd == "unset" and args:
            k = args[0].upper()
            sess.options.pop(k, None)
            ok(f"{k} unset")
            continue
        if cmd == "run":
            ctx = _build_ctx(sess)
            fmt = sess.options.get("FORMAT","all") or "all"
            outdir = sess.options.get("OUTDIR","reports") or "reports"
            if sess.current:
                banner(f"Running module: {sess.current}")
                try:
                    MODULES[sess.current].run(ctx)
                except Exception as e:
                    ctx.add_error(sess.current, str(e))
                paths = run_all(ctx, outdir=outdir, fmt=fmt)  # run_all writes unified report; ok for demo
            else:
                paths = run_all(ctx, outdir=outdir, fmt=fmt)
            ok("Reports written:")
            for p in paths:
                print(f"  - {p}")
            continue

        warn("Unknown command. Type 'help'.")
