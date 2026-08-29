```
 _____ ____      _    ___ _   _
|_   _|  _ \    / \  |_ _| \ | |
  | | | |_) |  / _ \  | ||  \| |
  | | |  _ <  / ___ \ | || |\  |
  |_| |_| \_\/_/   \_\___|_| \_|

Threat Response & Automated Intelligence Network
        Purple Team CLI  |  v0.1.0-dev
```

# TRAIN Framework

**TRAIN** (Threat Response & Automated Intelligence Network) — Python, C++
və Go dillərini birləşdirən, modulyar arxitekturalı, All-in-One **Purple
Team** (Dual-Use: Red Team + Blue Team) kibertəhlükəsizlik CLI alətidir.
Şəbəkə kəşfiyyatından tutmuş, IDS/IPS-ə, web auditinə, CVE axtarışına,
compliance yoxlamasına, log korrelyasiyasına, MITRE ATT&CK
xəritələndirilməsinə, OSINT/geolokasiyaya, ikili fayl forensikasına,
şifrəli parol anbarına və fişinq təlim modelinə qədər — bütün bunlar tək
bir interaktiv terminal interfeysində (TUI) birləşdirilib.

> ⚠️ **Etik istifadə:** Bu alət yalnız öz sisteminizdə, öz laboratoriya
> mühitinizdə (VirtualBox/VMware lab) və ya yazılı icazəniz olan
> sistemlərdə istifadə üçün nəzərdə tutulub. İcazəsiz sistemlərə qarşı
> istifadəsi qanunsuzdur.

---

## 📋 Mündəricat

- [Xüsusiyyətlər](#-xüsusiyyətlər)
- [Arxitektura](#-arxitektura)
- [Quraşdırma](#-quraşdırma)
- [Əmr Bələdçisi](#-əmr-bələdçisi)
  - [Nüvə əmrləri](#nüvə-əmrləri)
  - [Şəbəkə kəşfiyyatı və IDS/IPS](#şəbəkə-kəşfiyyatı-və-idsips)
  - [Web audit](#web-audit)
  - [Zəiflik və uyğunluq auditi](#zəiflik-və-uyğunluq-auditi)
  - [Log analizi və threat hunting](#log-analizi-və-threat-hunting)
  - [OSINT və reputasiya](#osint-və-reputasiya)
  - [Binary forensika](#binary-forensika)
  - [Parol və şifrələmə](#parol-və-şifrələmə)
  - [Fişinq təlimi](#fişinq-təlimi)
- [Ekran görüntüləri](#-ekran-görüntüləri)
- [Layihə strukturu](#-layihə-strukturu)
- [Töhfə vermə](#-töhfə-vermə)

---

## ✨ Xüsusiyyətlər

| Modul | Dil | Nə edir |
|---|---|---|
| `scanner.cpp` | C++ | Çoxaxınlı TCP port skaneri + banner grabbing |
| `sniffer.go` | Go | libpcap-əsaslı Snort-tipli IDS/IPS mühərriki |
| `web_auditor.py` | Python | HTTP header/TLS/misconfig auditi + yerli proxy |
| `script_engine.py` | Python | TSE — FTP/SSH/HTTP/MySQL/PostgreSQL/MongoDB/Redis audit skriptləri |
| `cve_lookup.py` | Python | NVD API-dən CVE axtarışı + YAML şablon skaneri |
| `compliance.py` | Python | CIS Benchmark-tipli sistem uyğunluq auditi |
| `log_engine.py` | Python | SSH/nginx/PowerShell/LSASS log korrelyasiyası |
| `threat_hunter.py` | Python | MITRE ATT&CK xəritələndirilməsi + C2 beaconing aşkarlanması |
| `osint_auditor.py` | Python | DNS enum, geolokasiya/ASN, VirusTotal reputasiyası |
| `api_tester.py` | Python | REST API test və endpoint kəşfiyyatı |
| `binary_analyzer.py` | Python | PE/ELF statik forensika (header, section, entropiya) |
| `pass_auditor.py` | Python | Parol entropiyası + HaveIBeenPwned yoxlaması |
| `vault_manager.py` | Python | AES-256 şifrəli lokal parol/qeyd anbarı |
| `crypto_utils.py` | Python | Base64/Hex/URL encode-decode + hash |
| `phish_awareness.py` | Python | 44 nümunə ilə interaktiv fişinq tanıma təlimi (4 çətinlik səviyyəsi) |

---

## 🏗 Arxitektura

```
                    ┌─────────────────────┐
                    │   main.py (giriş)    │
                    └──────────┬───────────┘
                               │
                    ┌──────────▼───────────┐
                    │  core/tui_engine.py   │  ← Rich/Prompt_Toolkit TUI
                    │  (əmr registry)        │
                    └──────────┬───────────┘
                               │
              ┌────────────────┼────────────────┐
              │                │                 │
    ┌─────────▼──────┐ ┌───────▼────────┐ ┌──────▼───────┐
    │  core/bridge.py │ │ modules/*.py    │ │ native_modules│
    │  (Python↔native)│ │ (14 Python      │ │ (C++ / Go)    │
    │                 │ │  modulu)         │ │               │
    └─────────┬──────┘ └────────────────┘ └──────┬────────┘
              │                                    │
              └──────────── subprocess + JSON ──────┘
```

Python TUI mərkəzi idarəetməni edir; C++ (`scanner.cpp`) və Go
(`sniffer.go`) modulları ayrıca binary kimi kompilyasiya olunur və
`core/bridge.py` vasitəsilə subprocess olaraq çağırılır, nəticələr JSON
formatında geri ötürülür.

---

## 🚀 Quraşdırma

### Tələblər
- Linux (Kali / Ubuntu / Debian tövsiyə olunur) və ya WSL2
- Python 3.10+
- `g++` (C++17 dəstəyi ilə)
- Go 1.20+
- `libpcap-dev`

### Addımlar

```bash
# 1. Repo-nu klonla
git clone https://github.com/umidguluzada/train-framework.git
cd train-framework

# 2. Sistem asılılıqlarını quraşdır
sudo apt update
sudo apt install -y build-essential golang-go libpcap-dev redis-server

# 3. Python asılılıqlarını quraşdır
pip install -r requirements.txt --break-system-packages

# 4. C++ port skanerini kompilyasiya et
cd native_modules
g++ -std=c++17 -O2 -pthread scanner.cpp -o train_scanner

# 5. Go IDS/IPS mühərrikini kompilyasiya et
go mod init train_sniffer
go get github.com/google/gopacket
go build -o train_sniffer sniffer.go
cd ..

# 6. İşə sal
python3 main.py
```

> IDS/IPS (`sniff`/`ids-run`) canlı paket tutmaq üçün root icazəsi tələb
> edir: `sudo python3 main.py`.

---

## 📖 Əmr Bələdçisi

### Nüvə əmrləri

| Əmr | Təsvir |
|---|---|
| `set target <IP/URL>` | Cari sessiya üçün hədəfi təyin edir. Digər əmrlərin çoxu, ayrıca hədəf verilməsə, bu dəyəri istifadə edir. |
| `status` | Cari sessiya vəziyyətini (hədəf, verbose rejimi) göstərir. |
| `help` | Bütün əmrlərin siyahısını göstərir. |
| `exit` / `quit` | Proqramdan çıxır. |

### Şəbəkə kəşfiyyatı və IDS/IPS

| Əmr | Təsvir |
|---|---|
| `scan [start] [end]` | C++ çoxaxınlı port skaneri. Açıq portları, servis təxminini və banner-i göstərir. Məs: `scan 1 1024`. |
| `sniff <iface> [rules] [--ips]` | Go IDS/IPS mühərrikini işə salır. `rules.conf`-dakı Snort-tipli qaydalara uyğun canlı paketləri aşkarlayır. `--ips` verilsə, uyğun gələn mənbə IP-ni `iptables` ilə bloklayır. Məs: `sniff eth0 native_modules/rules.conf`. |
| `ids-run` | `sniff` əmrinin sinonimidir. |

### Web audit

| Əmr | Təsvir |
|---|---|
| `audit-web [url]` | HTTP təhlükəsizlik başlıqlarını (CSP, HSTS, X-Frame-Options və s.), TLS sertifikatını və tanınmış həssas yolları (`.git/config`, `.env`, `robots.txt` və s.) yoxlayır. |
| `web-proxy [port]` | Yerli, yüngül HTTP forward proxy başladır (default port 8899). Bütün keçən sorğu/cavabları canlı loglayır. Məs: `curl -x http://127.0.0.1:8899 http://example.com`. |
| `api-test <url>` | Tək bir API endpoint-ə GET+OPTIONS sorğusu göndərib status, icazə verilən metodları və cavab strukturunu göstərir. |
| `api-discover <base_url>` | Ümumi API konvensiyalarına uyğun bir sıra yolu (`/api`, `/health`, `/swagger.json` və s.) yoxlayır. |

### Zəiflik və uyğunluq auditi

| Əmr | Təsvir |
|---|---|
| `run-tse [portlar]` | TRAIN Scripting Engine — son `scan` nəticəsindəki (və ya əl ilə verilən) portlara uyğun audit yoxlamaları aparır: FTP anonim giriş, SSH banner/alqoritm, HTTP versiya açıqlanması, MySQL/PostgreSQL/MongoDB/Redis auth vəziyyəti. |
| `audit-cve <açar sözlər>` | NVD (National Vulnerability Database) API-dən CVE axtarır. `audit-cve --from-tse` son TSE nəticəsindəki banner-lərə əsasən avtomatik axtarış edir. |
| `template-scan <fayl.yaml>` | Yerli YAML şablonuna əsasən sadə HTTP-path yoxlamaları aparır (Nuclei-tipli, sadələşdirilmiş versiya). |
| `audit-compliance` | Yerli sistemdə CIS Benchmark-tipli 7 yoxlama aparır: SSH root login, parol siyasəti, world-writable fayllar, firewall statusu, audit daemon statusu. |

### Log analizi və threat hunting

| Əmr | Təsvir |
|---|---|
| `audit-logs <fayl> --format <növ>` | Log faylını parse edib strukturlaşdırılmış hadisələrə çevirir. Dəstəklənən formatlar: `auth` (SSH/sudo), `syslog`, `nginx` (HTTP access log), `json-alerts` (sniffer.go çıxışı), `powershell` (Windows Event ID 4104), `lsass` (Windows Event ID 4656/4663). Brute-force mənbələrini avtomatik aşkarlayır. |
| `hunt-mitre` | Bu sessiyada toplanmış tapıntıları (compliance, TSE, log, IDS) real MITRE ATT&CK texnika ID-lərinə (T1110, T1548, T1078 və s.) xəritələndirir. |
| `hunt-beacon` | Son `audit-logs --format nginx` nəticəsindəki zaman möhürlərini statistik təhlil edərək C2 "beaconing" (müntəzəm, avtomatlaşdırılmış əlaqə) nümunəsini aşkarlayır. |

### OSINT və reputasiya

| Əmr | Təsvir |
|---|---|
| `audit-osint <domain>` | Domenin DNS qeydlərini (A, AAAA, MX, TXT, NS, CNAME, SOA) passiv şəkildə toplayır. |
| `geo-track <ip/domain>` | IP/domenin geolokasiyasını, ISP-ni və ASN-i göstərir (ip-api.com). |
| `check-vt <hash/IP>` | VirusTotal v3 API ilə fayl hash-i və ya IP-nin reputasiyasını yoxlayır (`VT_API_KEY` mühit dəyişəni tələb olunur). |

### Binary forensika

| Əmr | Təsvir |
|---|---|
| `analyze-binary <fayl>` | PE (Windows) və ya ELF (Linux) faylının başlığını, bölmələrini (sections), entropiyasını və import olunmuş funksiyalarını göstərir — heç bir icra olmadan statik analiz. |

### Parol və şifrələmə

| Əmr | Təsvir |
|---|---|
| `audit-pass <parol> [--offline]` | Parolun entropiyasını (bit) hesablayır və HaveIBeenPwned k-anonymity API ilə məlum sızıntılarda olub-olmadığını yoxlayır (`--offline` şəbəkə sorğusunu ötürür). |
| `vault-init` | Yeni AES-256 şifrəli lokal parol anbarı yaradır (master parol tələb olunur). |
| `vault-add <ad>` | Anbara yeni bir dəyər (parol, API açarı və s.) əlavə edir. |
| `vault-get <ad>` | Anbardan bir dəyəri deşifrə edib göstərir. |
| `vault-list` | Anbardakı bütün qeyd adlarını göstərir (dəyərləri deşifrə etmədən). |
| `vault-remove <ad>` | Anbardan bir qeydi silir. |
| `encode <base64\|hex\|url> <mətn>` | Mətni verilən formata kodlaşdırır. |
| `decode <base64\|hex\|url> <mətn>` | Kodlaşdırılmış mətni deşifrə edir. |
| `hash <md5\|sha1\|sha256\|sha512> <mətn>` | Mətnin hash dəyərini hesablayır. |

### Fişinq təlimi

| Əmr | Təsvir |
|---|---|
| `phish-awareness [səviyyə]` | Təsadüfi bir nümunə fişinq/real e-poçt göstərir və red flag-ləri izah edir. Səviyyə: `easy`, `medium`, `hard`, `critical` (default: hamısı). |
| `phish-quiz [say] [səviyyə]` | İnteraktiv test — hər mesaj üçün "fişinq ya real?" sualı verir, nəticədə xal göstərir. Məs: `phish-quiz 10 hard`, `phish-quiz all critical`. |

---

## 🖼 Ekran görüntüləri

> Aşağıdakı şəkilləri öz test nəticələrinizdən əlavə edin — `docs/screenshots/`
> qovluğuna PNG faylları qoyub, aşağıdakı linkləri fayl adlarınıza uyğun
> yeniləyin.

| Xüsusiyyət | Şəkil |
|---|---|
| TUI başlanğıc ekranı | `docs/screenshots/banner.png` |
| Port skanı nəticəsi | `docs/screenshots/scan.png` |
| Canlı IDS alert | `docs/screenshots/sniff.png` |
| Web audit nəticəsi | `docs/screenshots/audit-web.png` |
| Compliance auditi | `docs/screenshots/compliance.png` |
| MITRE ATT&CK xəritələndirilməsi | `docs/screenshots/hunt-mitre.png` |
| C2 Beacon aşkarlanması | `docs/screenshots/hunt-beacon.png` |
| Fişinq testi | `docs/screenshots/phish-quiz.png` |

```markdown
![TUI Banner](docs/screenshots/banner.png)
![Port Scan](docs/screenshots/scan.png)
![Live IDS Alert](docs/screenshots/sniff.png)
```

---

## 📁 Layihə strukturu

```
train_framework/
├── main.py                      # Giriş nöqtəsi
├── requirements.txt             # Python asılılıqları
├── README.md                    # Bu fayl
│
├── core/
│   ├── tui_engine.py            # TUI, banner, əmr registry
│   └── bridge.py                # Python ↔ C++/Go körpüsü
│
├── native_modules/
│   ├── scanner.cpp              # C++ port skaneri
│   ├── sniffer.go               # Go IDS/IPS mühərriki
│   └── rules.conf               # Snort-tipli imza qaydaları
│
├── templates/
│   └── example-template.yaml    # Nümunə YAML audit şablonu
│
└── modules/
    ├── web_auditor.py
    ├── crypto_utils.py
    ├── pass_auditor.py
    ├── script_engine.py
    ├── cve_lookup.py
    ├── compliance.py
    ├── log_engine.py
    ├── threat_hunter.py
    ├── osint_auditor.py
    ├── api_tester.py
    ├── binary_analyzer.py
    ├── vault_manager.py
    └── phish_awareness.py
```

---

## 🤝 Töhfə vermə

Bu, tədris/portfolio məqsədli şəxsi bir layihədir. Fikir və düzəlişlər üçün
issue/PR açıla bilər.

## 📜 Lisenziya

Bu layihə hazırda ayrıca lisenziya faylı olmadan paylaşılır — istifadədən
əvvəl müəllif ilə əlaqə saxlayın.
