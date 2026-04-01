<div align="center">

# 🔍 recon_engine

**Professional Async Reconnaissance Framework**

[![Python](https://img.shields.io/badge/Python-3.11%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Kali-red?logo=linux)](https://www.kali.org/)
[![Async](https://img.shields.io/badge/Async-asyncio%20%2B%20httpx-purple)](https://docs.python.org/3/library/asyncio.html)

*Authorized use only*

---

[🇬🇧 English](#-english) · [🇮🇹 Italiano](#-italiano)

</div>

---

## 🇬🇧 English

### Overview

`recon_engine.py` is a high-speed, high-anonymity reconnaissance orchestrator built for security assessments. It runs six recon tools concurrently, validates every discovered subdomain against HTTP/HTTPS, and produces three structured report formats — all in a single command.

### ✨ Key Features

| Feature | Description |
|---------|-------------|
| **Async pipeline** | `theHarvester`, `photon`, `subfinder`, `dig`, `whois`, `crt.sh` run in true parallel via `asyncio.gather` |
| **DNS pre-filter** | Resolves all subdomains in parallel before HTTP validation — dead hosts never touch the network |
| **HTTP validation** | `httpx` probes port 80 and 443 **simultaneously** per host, captures status code and page title |
| **Tor / SOCKS5** | `--tor` routes all HTTP via `aiohttp_socks`; subprocess tools wrapped with `torsocks`; NEWNYM circuit rotation on 403/429 |
| **Proxy rotation** | `--proxy-list` round-robins a file of SOCKS5/HTTP proxies across tool executions |
| **UA randomisation** | Every HTTP request picks a random modern browser User-Agent |
| **Three reports** | `.json` (AI-ready hierarchy), `.md` (clickable tables), `.toon` (ASCII art summary) |
| **Structured logging** | All tool errors logged to `recon.log` — pipeline never stops on a single failure |

---

### 🏗 Architecture

```
 CLI input (domain / URL)
        │
        ▼
 ┌─────────────────────────────────────────────────┐
 │  Phase 1 — RECON  (asyncio.gather)              │
 │                                                 │
 │  theHarvester ──┐                               │
 │  photon        ─┤─→ partial parse (callback)    │
 │  subfinder     ─┤                               │
 │  dig           ─┤                               │
 │  whois         ─┤                               │
 │  crt.sh        ─┘  (aiohttp + retry backoff)    │
 └─────────────────────────────────────────────────┘
        │
        ▼
 ┌─────────────────────────────────────────────────┐
 │  Phase 2 — VALIDATE  (httpx)                    │
 │                                                 │
 │  DNS pre-filter ──→ drop unresolvable hosts     │
 │  HTTP validate  ──→ https ║ http (parallel)     │
 │                     status code + page title    │
 └─────────────────────────────────────────────────┘
        │
        ▼
 ┌─────────────────────────────────────────────────┐
 │  Phase 3 — REPORTS                              │
 │                                                 │
 │  report_<target>.json   AI-ready hierarchy      │
 │  report_<target>.md     clickable MD tables     │
 │  report_<target>.toon   ASCII art summary       │
 └─────────────────────────────────────────────────┘
```

---

### ⚙️ Requirements

#### Python packages

```bash
pip install -r requirements.txt
```

#### External tools (must be on `$PATH`)

| Tool | Install |
|------|---------|
| `theHarvester` | `apt install theharvester` or [GitHub](https://github.com/laramies/theHarvester) |
| `photon` | `pip install photon-scanner` or [GitHub](https://github.com/s0md3v/Photon) |
| `subfinder` | [GitHub Releases](https://github.com/projectdiscovery/subfinder/releases) |
| `whois` | `apt install whois` |
| `dig` | `apt install dnsutils` |
| `torsocks` | `apt install torsocks` *(only with `--tor`)* |
| `tor` | `apt install tor` *(only with `--tor`)* |

---

### 🚀 Quick Start

```bash
# Clone
git clone https://github.com/<your-username>/recon_engine.git
cd recon_engine

# Install Python dependencies
pip install -r requirements.txt

# Basic scan
python3 recon_engine.py example.com

# Skip HTTP validation (faster, less detail)
python3 recon_engine.py example.com --no-validate

# Custom timeout
python3 recon_engine.py https://target.org --timeout 120

# Route through Tor
python3 recon_engine.py target.com --tor

# Proxy rotation
python3 recon_engine.py target.com --proxy-list proxies.txt

# Tor with custom control-port password
python3 recon_engine.py target.com --tor --tor-password s3cr3t
```

---

### 🗂 Output Files

| File | Format | Content |
|------|--------|---------|
| `report_<target>.json` | JSON | Hierarchical: `meta → summary → subdomains{status,metadata} → raw{whois,dig}` |
| `report_<target>.md` | Markdown | Info table + subdomain table with clickable links for live hosts |
| `report_<target>.toon` | Plain text | ASCII art — live-host box, subdomain/IP/email lists, raw whois & dig |
| `recon.log` | Log | Timestamped tool errors and debug info |

---

### 🛡 Tuning Parameters

| Constant | Default | Description |
|----------|---------|-------------|
| `TOOL_TIMEOUT` | `300 s` | Hard limit per recon tool |
| `HARVESTER_TIMEOUT` | `45 s` | Dedicated limit for `theHarvester` |
| `VALIDATE_TIMEOUT` | `5 s` | Per-host httpx connect+read timeout |
| `VALIDATE_CONCUR` | `150` | Max simultaneous HTTP validation workers |
| `DNS_PREFLIGHT_TO` | `2.5 s` | DNS pre-filter timeout per host |

---

### ⚠️ Legal Notice

This tool is intended **exclusively** for:
- Authorized penetration testing engagements
- CTF (Capture The Flag) competitions
- Security research on systems you own or have written permission to test

Unauthorized use against systems you do not own is illegal. The authors assume no liability for misuse.

---

## 🇮🇹 Italiano

### Panoramica

`recon_engine.py` è un orchestratore di ricognizione ad alta velocità e alta anonimità, progettato per assessment di sicurezza. Esegue sei tool di recon in parallelo, valida ogni sottodominio scoperto su HTTP/HTTPS e produce tre formati di report strutturati — tutto con un singolo comando.

### ✨ Funzionalità principali

| Funzionalità | Descrizione |
|--------------|-------------|
| **Pipeline asincrona** | `theHarvester`, `photon`, `subfinder`, `dig`, `whois`, `crt.sh` girano in parallelo reale via `asyncio.gather` |
| **DNS pre-filter** | Risolve tutti i sottodomini in parallelo prima della validazione HTTP — gli host morti non toccano mai la rete |
| **Validazione HTTP** | `httpx` sonda porta 80 e 443 **simultaneamente** per ogni host, cattura status code e titolo pagina |
| **Tor / SOCKS5** | `--tor` instrada tutto l'HTTP via `aiohttp_socks`; i tool subprocess vengono avvolti con `torsocks`; rotazione del circuito NEWNYM su 403/429 |
| **Rotazione proxy** | `--proxy-list` ruota in round-robin un file di proxy SOCKS5/HTTP ad ogni esecuzione del tool |
| **Randomizzazione UA** | Ogni richiesta HTTP sceglie uno User-Agent moderno casuale |
| **Tre report** | `.json` (gerarchia AI-ready), `.md` (tabelle con link cliccabili), `.toon` (sommario ASCII art) |
| **Logging strutturato** | Tutti gli errori dei tool vengono loggati su `recon.log` — la pipeline non si blocca mai per un singolo fallimento |

---

### 🏗 Architettura

```
 Input CLI (dominio / URL)
        │
        ▼
 ┌─────────────────────────────────────────────────┐
 │  Fase 1 — RECON  (asyncio.gather)               │
 │                                                 │
 │  theHarvester ──┐                               │
 │  photon        ─┤─→ parse parziale (callback)   │
 │  subfinder     ─┤                               │
 │  dig           ─┤                               │
 │  whois         ─┤                               │
 │  crt.sh        ─┘  (aiohttp + retry backoff)    │
 └─────────────────────────────────────────────────┘
        │
        ▼
 ┌─────────────────────────────────────────────────┐
 │  Fase 2 — VALIDAZIONE  (httpx)                  │
 │                                                 │
 │  DNS pre-filter ──→ scarta host non risolvibili │
 │  HTTP validate  ──→ https ║ http (parallelo)    │
 │                     status code + titolo pagina │
 └─────────────────────────────────────────────────┘
        │
        ▼
 ┌─────────────────────────────────────────────────┐
 │  Fase 3 — REPORT                                │
 │                                                 │
 │  report_<target>.json   gerarchia AI-ready      │
 │  report_<target>.md     tabelle MD cliccabili   │
 │  report_<target>.toon   sommario ASCII art      │
 └─────────────────────────────────────────────────┘
```

---

### ⚙️ Requisiti

#### Pacchetti Python

```bash
pip install -r requirements.txt
```

#### Tool esterni (devono essere nel `$PATH`)

| Tool | Installazione |
|------|---------------|
| `theHarvester` | `apt install theharvester` oppure [GitHub](https://github.com/laramies/theHarvester) |
| `photon` | `pip install photon-scanner` oppure [GitHub](https://github.com/s0md3v/Photon) |
| `subfinder` | [GitHub Releases](https://github.com/projectdiscovery/subfinder/releases) |
| `whois` | `apt install whois` |
| `dig` | `apt install dnsutils` |
| `torsocks` | `apt install torsocks` *(solo con `--tor`)* |
| `tor` | `apt install tor` *(solo con `--tor`)* |

---

### 🚀 Avvio rapido

```bash
# Clona il repository
git clone https://github.com/<tuo-username>/recon_engine.git
cd recon_engine

# Installa le dipendenze Python
pip install -r requirements.txt

# Scansione base
python3 recon_engine.py example.com

# Salta la validazione HTTP (più veloce, meno dettagli)
python3 recon_engine.py example.com --no-validate

# Timeout personalizzato
python3 recon_engine.py https://target.org --timeout 120

# Routing attraverso Tor
python3 recon_engine.py target.com --tor

# Rotazione proxy
python3 recon_engine.py target.com --proxy-list proxies.txt

# Tor con password per la control port
python3 recon_engine.py target.com --tor --tor-password s3cr3t
```

---

### 🗂 File di output

| File | Formato | Contenuto |
|------|---------|-----------|
| `report_<target>.json` | JSON | Gerarchico: `meta → summary → subdomains{status,metadata} → raw{whois,dig}` |
| `report_<target>.md` | Markdown | Tabella info + tabella sottodomini con link cliccabili per host attivi |
| `report_<target>.toon` | Testo | ASCII art — box host attivi, liste sottodomini/IP/email, whois e dig grezzi |
| `recon.log` | Log | Errori tool e debug con timestamp |

---

### 🛡 Parametri di tuning

| Costante | Default | Descrizione |
|----------|---------|-------------|
| `TOOL_TIMEOUT` | `300 s` | Limite massimo per ogni tool di recon |
| `HARVESTER_TIMEOUT` | `45 s` | Limite dedicato per `theHarvester` |
| `VALIDATE_TIMEOUT` | `5 s` | Timeout httpx connect+read per host |
| `VALIDATE_CONCUR` | `150` | Worker HTTP simultanei massimi |
| `DNS_PREFLIGHT_TO` | `2.5 s` | Timeout pre-filtro DNS per host |

---

### ⚠️ Avviso Legale

Questo strumento è destinato **esclusivamente** a:
- Penetration test autorizzati
- Competizioni CTF (Capture The Flag)
- Ricerca di sicurezza su sistemi di propria proprietà o con permesso scritto

L'uso non autorizzato su sistemi altrui è illegale. Gli autori declinano ogni responsabilità per usi impropri.

---

<div align="center">

Made for authorized security actors · Fatto per attori della sicurezza autorizzati

</div>
