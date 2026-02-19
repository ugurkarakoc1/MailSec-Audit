from core.context import Finding
from core.console import C, banner

CHECKLIST = [
    {"id": "CHK-001", "title": "Submission portlarında (587/465) modern auth/MFA zorunlu mu?", "type": "policy"},
    {"id": "CHK-002", "title": "Port 25 üzerinde AUTH kapalı mı (veya TLS zorunlu mu)?", "type": "policy"},
    {"id": "CHK-003", "title": "Internal sender spoof (From/DisplayName) kontrolleri etkin mi?", "type": "manual"},
    {"id": "CHK-004", "title": "Inbound DMARC enforcement (quarantine/reject) uygulanıyor mu?", "type": "dns"},
    {"id": "CHK-005", "title": "Outbound mail için DKIM signing aktif mi?", "type": "dns"},
]

def run(ctx):
    banner("auxiliary/scanner/mail/send_controls (SAFE)")
    ctx.results.setdefault("send_controls", {})["checklist"] = CHECKLIST

    ctx.add_finding(Finding(
        id="MAIL-CTRL-001",
        category="mail",
        title="Gönderim kontrolleri için manuel doğrulama checklist'i",
        severity="Info",
        description="Authenticated gönderim senaryolarında From/DisplayName doğrulaması ve policy kontrollerinin doğrulanması önerilir. Bu araç otomatik mail gönderimi yapmaz; checklist rapora eklenmiştir.",
        recommendation="Yetkili test hesabı ile manuel doğrulama yapın ve kanıt referanslarını 'Manuel Doğrulama' bölümüne ekleyin.",
        evidence={"checklist_items": [c["id"] for c in CHECKLIST]},
    ))
