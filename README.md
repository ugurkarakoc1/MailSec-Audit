# MailSec-Audit (SAFE) — Web + DNS Policy + SMTP Transport

A **SAFE**, passive security assessment framework for mail infrastructure:
- **Web Access**: OWA/ECP exposure, TLS sanity, headers, cookies, auth-flow hints (no brute force)
- **DNS Policy**: SPF / DKIM / DMARC / MTA-STS / TLS-RPT
- **SMTP Transport**: banner, STARTTLS availability, TLS handshake/cert validation (best-effort), AUTH advertisement (no auth attempts)

## What it does NOT do
- No brute force / credential stuffing / spraying
- No exploitation / persistence
- No destructive testing

## Install
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Quick run (non-interactive)
```bash
python3 mailsec_audit.py --domain example.com --web https://mail.example.com --smtp mail.example.com --format all
```

## Interactive MSF-style shell (optional)
```bash
python3 mailsec_audit.py --shell
```
Example:
```
mailsec > use web/owa
mailsec (web/owa) > set WEB https://mail.example.com
mailsec (web/owa) > run

mailsec > use dns/policy
mailsec (dns/policy) > set DOMAIN example.com
mailsec (dns/policy) > run

mailsec > use smtp/transport
mailsec (smtp/transport) > set SMTP mail.example.com
mailsec (smtp/transport) > run
```

## Reports
All reports are written to `reports/` (default):
- Markdown: `mailsec_<timestamp>.md`
- JSON: `mailsec_<timestamp>.json`
- HTML: `mailsec_<timestamp>.html`


## TR HTML Rapor
Bu sürümde HTML rapor, yönetici özeti + risk matrisi + yol haritası içerecek şekilde yeniden tasarlanmıştır.


## Yeni (SAFE) Özellikler
- MFA tespiti (heuristic): OWA login akışında MFA ipuçları aranır; tespit edilemezse rapora 'heuristic' bulgu eklenir.
- Header fingerprint: Exchange/OWA diagnostic header'larında olası iç hostname sızıntısı tespiti.
- SMTP: 25/587/465 pasif kontroller (banner/EHLO/STARTTLS/TLS info/AUTH advertise).
- DNS: MX/A/AAAA/PTR keşfi + SPF/DKIM/DMARC/MTA-STS/TLS-RPT.

Not: Brute-force / credential spray özellikleri bilinçli olarak yoktur.


## Manuel Doğrulama (Önerilen)
Bu araç otomatik kullanıcı girişi / brute-force içermez. Yetkili testlerde pozitif kanıt için
manuel doğrulama bilgileri CLI üzerinden girilebilir ve rapora eklenir.

Örnek:
python3 mailsec_audit.py --domain example.com --web https://mail.example.com --smtp mail.example.com \
  --manual-validation --tester "Ahmet Y." --account "DOMAIN\\testuser" \
  --login-success yes --mfa-prompted no --idp "Entra ID" --evidence-ref "IMG-2026-01" --format all

## Ek SAFE Modüller
- smtp/policy_matrix: AUTH/STARTTLS ilişkisi ve submission politikası için özet matris (şifre denemeden)
- mail/surface_map: POP3/IMAP yüzey haritası (banner/TLS bilgi)
- mail/send_controls: internal spoof ve gönderim politikaları için checklist (manuel doğrulama ile kanıt bağlanır)



## Dashboard HTML (TR)
HTML rapor sadeleştirildi ve dashboard görünüme alındı (bordo/beyaz/gri).
