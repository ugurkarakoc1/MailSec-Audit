from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
import time

@dataclass
class Finding:
    id: str
    title: str
    severity: str  # Info/Low/Medium/High/Critical
    description: str
    recommendation: str
    evidence: Optional[Dict[str, Any]] = None
    category: str = "general"

@dataclass
class ScanContext:
    domain: str = ""
    web: str = ""      # base URL
    smtp: str = ""     # host
    timeout: float = 10.0
    quiet: bool = False
    verbose: bool = False
    single_probe: bool = False  # one invalid auth probe (optional)
    dkim_selectors: List[str] = field(default_factory=list)

    started_at: float = field(default_factory=time.time)
    results: Dict[str, Any] = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def add_finding(self, f: Finding) -> None:
        self.findings.append(f)

    def add_error(self, step: str, err: str) -> None:
        self.errors.append(f"{step}: {err}")

from core.manual_validation import ManualValidation
