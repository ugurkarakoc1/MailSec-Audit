# 📧 MailSec-Audit (SAFE)

![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Status](https://img.shields.io/badge/status-active-success.svg)
![Safety](https://img.shields.io/badge/mode-SAFE%20Passive-green.svg)
![Reports](https://img.shields.io/badge/reports-HTML%20%7C%20JSON%20%7C%20MD-bordo)

> 🔒 **SAFE & Passive Mail Security Assessment Framework**

MailSec-Audit, mail altyapıları için **pasif ve güvenli (SAFE)**
güvenlik değerlendirmesi yapan bir araçtır.\
Hiçbir brute-force, exploit veya yıkıcı test içermez.

------------------------------------------------------------------------

## 🚀 Özellikler

### 🌐 Web Access Analizi

-   OWA / ECP exposure kontrolü\
-   TLS yapılandırma kontrolü\
-   Security header analizi\
-   Cookie güvenlik bayrakları\
-   Auth-flow ipuçları (pasif)\
-   MFA heuristic tespiti\
-   Exchange header fingerprint (hostname leak)

------------------------------------------------------------------------

### 🧭 DNS Policy Analizi

-   SPF kontrolü\
-   DKIM varlık kontrolü\
-   DMARC politika analizi\
-   MTA-STS kontrolü\
-   TLS-RPT kontrolü\
-   MX / A / AAAA / PTR keşfi

------------------------------------------------------------------------

### 📮 SMTP Transport Analizi

-   SMTP banner inceleme\
-   STARTTLS desteği kontrolü\
-   TLS handshake & sertifika doğrulama (best-effort)\
-   AUTH advertise kontrolü

**Port kapsamı:** - 25\
- 587\
- 465

------------------------------------------------------------------------

## 🛡️ SAFE Tasarım Prensibi

### ❌ Araç şunları YAPMAZ

-   Brute force\
-   Credential spraying\
-   Exploitation\
-   Persistence\
-   Destructive testing

> ✅ Tamamen pasif ve güvenli değerlendirme odaklıdır.

------------------------------------------------------------------------

## ⚙️ Kurulum

``` bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

------------------------------------------------------------------------

## ⚡ Hızlı Çalıştırma (Non-Interactive)

``` bash
python3 mailsec_audit.py   --domain example.com   --web https://mail.example.com   --smtp mail.example.com   --format all
```

------------------------------------------------------------------------

## 🖥️ Interactive MSF-Style Shell (Opsiyonel)

``` bash
python3 mailsec_audit.py --shell
```

------------------------------------------------------------------------

## 📊 Raporlar

Tüm raporlar varsayılan olarak `reports/` klasörüne yazılır:

-   📝 Markdown → `mailsec_<timestamp>.md`\
-   🧾 JSON → `mailsec_<timestamp>.json`\
-   🌐 HTML → `mailsec_<timestamp>.html`

------------------------------------------------------------------------

## 🇹🇷 HTML Dashboard

Yeni HTML rapor:

✨ Yönetici özeti\
📉 Risk matrisi\
🗺️ Yol haritası\
🎨 Bordo / Beyaz / Gri dashboard tema

------------------------------------------------------------------------

## 🔍 Manuel Doğrulama (Önerilen)

Araç otomatik login veya brute-force içermez.\
Yetkili testlerde **pozitif kanıt** için manuel doğrulama eklenebilir.

------------------------------------------------------------------------

## ⚠️ Yasal Uyarı

Bu araç yalnızca:

-   ✔ Yetkili güvenlik testleri\
-   ✔ Kurumsal değerlendirmeler\
-   ✔ Savunma amaçlı analizler

için kullanılmalıdır.
