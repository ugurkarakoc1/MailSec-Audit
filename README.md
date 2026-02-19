📧 MailSec-Audit (SAFE)



🔒 SAFE & Passive Mail Security Assessment Framework

MailSec-Audit, mail altyapıları için pasif ve güvenli (SAFE) güvenlik değerlendirmesi yapan bir araçtır.
Hiçbir brute-force, exploit veya yıkıcı test içermez.

🚀 Özellikler
🌐 Web Access Analizi

OWA / ECP exposure kontrolü

TLS yapılandırma kontrolü

Security header analizi

Cookie güvenlik bayrakları

Auth-flow ipuçları (pasif)

MFA heuristic tespiti

Exchange header fingerprint (hostname leak)

🧭 DNS Policy Analizi

SPF kontrolü

DKIM varlık kontrolü

DMARC politika analizi

MTA-STS kontrolü

TLS-RPT kontrolü

MX / A / AAAA / PTR keşfi

📮 SMTP Transport Analizi

SMTP banner inceleme

STARTTLS desteği kontrolü

TLS handshake & sertifika doğrulama (best-effort)

AUTH advertise kontrolü

Port kapsamı:

25

587

465

🛡️ SAFE Tasarım Prensibi
❌ Araç şunları YAPMAZ

Brute force

Credential spraying

Exploitation

Persistence

Destructive testing

✅ Tamamen pasif ve güvenli değerlendirme odaklıdır.

⚙️ Kurulum
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
⚡ Hızlı Çalıştırma (Non-Interactive)
python3 mailsec_audit.py \
  --domain example.com \
  --web https://mail.example.com \
  --smtp mail.example.com \
  --format all
🖥️ Interactive MSF-Style Shell (Opsiyonel)
python3 mailsec_audit.py --shell
🧪 Örnek Kullanım
mailsec > use web/owa
mailsec (web/owa) > set WEB https://mail.example.com
mailsec (web/owa) > run

mailsec > use dns/policy
mailsec (dns/policy) > set DOMAIN example.com
mailsec (dns/policy) > run

mailsec > use smtp/transport
mailsec (smtp/transport) > set SMTP mail.example.com
mailsec (smtp/transport) > run
📊 Raporlar

Tüm raporlar varsayılan olarak reports/ klasörüne yazılır:

📝 Markdown → mailsec_<timestamp>.md

🧾 JSON → mailsec_<timestamp>.json

🌐 HTML → mailsec_<timestamp>.html

🇹🇷 HTML Dashboard

Yeni HTML rapor:

✨ Yönetici özeti
📉 Risk matrisi
🗺️ Yol haritası
🎨 Bordo / Beyaz / Gri dashboard tema

🧠 Yeni SAFE Özellikler

🔐 MFA heuristic detection

🧬 Header fingerprint (internal hostname leak)

📡 SMTP pasif analiz (25/587/465)

🌍 Genişletilmiş DNS keşfi

📊 Submission policy matrix

🗺️ Mail surface mapping

🔍 Manuel Doğrulama (Önerilen)

Araç otomatik login veya brute-force içermez.
Yetkili testlerde pozitif kanıt için manuel doğrulama eklenebilir.

✍️ Örnek
python3 mailsec_audit.py \
  --domain example.com \
  --web https://mail.example.com \
  --smtp mail.example.com \
  --manual-validation \
  --tester "Ahmet Y." \
  --account "DOMAIN\\testuser" \
  --login-success yes \
  --mfa-prompted no \
  --idp "Entra ID" \
  --evidence-ref "IMG-2026-01" \
  --format all
🧩 Ek SAFE Modüller
📊 smtp/policy_matrix

AUTH / STARTTLS ilişkisi ve submission politikası özet matrisi
(⚠️ şifre denemesi yapılmaz)

🗺️ mail/surface_map

POP3 / IMAP yüzey haritası
(banner + TLS bilgisi)

📬 mail/send_controls

Internal spoof ve gönderim politikaları checklist
(✔ manuel kanıt bağlanabilir)

🎯 Amaç

MailSec-Audit’in hedefi:

✅ Hızlı görünürlük

✅ Pasif güvenlik değerlendirmesi

✅ Kurumsal raporlama

✅ SAFE testing yaklaşımı

⚠️ Yasal Uyarı

Bu araç yalnızca:

✔ Yetkili güvenlik testleri

✔ Kurumsal değerlendirmeler

✔ Savunma amaçlı analizler

için kullanılmalıdır.
