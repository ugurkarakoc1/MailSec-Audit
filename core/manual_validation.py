from dataclasses import dataclass, asdict
from typing import Optional, Dict

@dataclass
class ManualValidation:
    tester: Optional[str] = None
    account: Optional[str] = None
    login_success: Optional[bool] = None
    mfa_prompted: Optional[bool] = None
    idp: Optional[str] = None
    evidence_ref: Optional[str] = None
    notes: Optional[str] = None

    def to_dict(self) -> Dict:
        return asdict(self)
