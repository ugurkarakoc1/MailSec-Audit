class C:
    R = "\033[91m"
    G = "\033[92m"
    Y = "\033[93m"
    B = "\033[94m"
    CY = "\033[96m"
    W = "\033[0m"
    BOLD = "\033[1m"

def banner(title: str) -> None:
    print(f"{C.B}{C.BOLD}[*]{C.W} {title}")

def info(msg: str) -> None:
    print(f"{C.B}[*]{C.W} {msg}")

def ok(msg: str) -> None:
    print(f"{C.G}[+]{C.W} {msg}")

def warn(msg: str) -> None:
    print(f"{C.Y}[!]{C.W} {msg}")

def bad(msg: str) -> None:
    print(f"{C.R}[-]{C.W} {msg}")
