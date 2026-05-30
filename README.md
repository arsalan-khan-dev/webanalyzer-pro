<div align="center">

# WebAnalyzer v3.0

### 🔍 Production-Grade Security & Performance Analysis Platform

**Upload a ZIP · Clone a GitHub repo · Get a full audit in seconds.**  
Security scanning · Lighthouse scores · AI fix suggestions · Multi-format reports.

---

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.x-000000?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![Bandit](https://img.shields.io/badge/Security-Bandit-FF4D6D?style=for-the-badge&logo=python&logoColor=white)](https://bandit.readthedocs.io/)
[![ESLint](https://img.shields.io/badge/JS-ESLint-4B32C3?style=for-the-badge&logo=eslint&logoColor=white)](https://eslint.org/)
[![Stylelint](https://img.shields.io/badge/CSS-Stylelint-263238?style=for-the-badge&logo=stylelint&logoColor=white)](https://stylelint.io/)
[![Lighthouse](https://img.shields.io/badge/Lighthouse-CLI-F44B21?style=for-the-badge&logo=googlechrome&logoColor=white)](https://developer.chrome.com/docs/lighthouse/)
[![Grok AI](https://img.shields.io/badge/AI-Grok%20(xAI)-7B5EA7?style=for-the-badge&logo=openai&logoColor=white)](https://x.ai/)
[![ReportLab](https://img.shields.io/badge/PDF-ReportLab-E74C3C?style=for-the-badge&logo=adobeacrobatreader&logoColor=white)](https://www.reportlab.com/)
[![python-docx](https://img.shields.io/badge/DOCX-python--docx-2B579A?style=for-the-badge&logo=microsoftword&logoColor=white)](https://python-docx.readthedocs.io/)
[![Rate Limited](https://img.shields.io/badge/Rate%20Limiting-flask--limiter-00D68F?style=for-the-badge&logo=shield&logoColor=white)]()
[![License](https://img.shields.io/badge/License-MIT-brightgreen?style=for-the-badge)](LICENSE)
[![Version](https://img.shields.io/badge/Version-3.0-blue?style=for-the-badge)]()
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey?style=for-the-badge)]()

---

[**✨ Features**](#-features) • [**🚀 Quick Start**](#-quick-start) • [**📦 Dependencies**](#-dependencies) • [**🏗️ Architecture**](#️-architecture) • [**📁 Structure**](#-project-structure) • [**⚙️ Config**](#️-configuration) • [**🐳 Docker**](#-docker) • [**👤 Author**](#-author)

</div>

---

## 🌐 Overview

**WebAnalyzer v3.0** is a production-ready Flask web application that performs deep security, performance, SEO, and accessibility audits on any web project. Upload a `.zip` / `.tar.gz` archive or paste a GitHub / GitLab URL — WebAnalyzer extracts the source, runs a multi-engine scan pipeline, and delivers a full report downloadable in **HTML, PDF, DOCX, and JSON** formats.

Built with zero frontend frameworks — pure vanilla JS UI served by a single Flask file, with a hardened extraction engine, disk-quota enforcement, session-based cleanup, and optional **Grok AI** fix suggestions.

---

## ✨ Features

<table>
<tr>
<td width="50%">

### 🔐 Security Analysis
- **Bandit** static analysis for Python files
- **ESLint** (no-eval, no-implied-eval, no-new-func, XSS rules) for JS/TS
- **Stylelint** for CSS/SCSS
- Custom **RegexAnalyzer** for Python, JS, HTML, CSS, PHP, Java
- Detects: `eval()`, SQL injection, hardcoded secrets, `innerHTML` XSS, `shell=True`, pickle RCE, and more

### ⚡ Lighthouse Integration
- Spins up a temporary HTTP server per session
- Runs **Google Lighthouse CLI** headlessly via Chrome
- Returns scores for: Performance, Accessibility, Best Practices, SEO, PWA
- Graceful fallback when Lighthouse is unavailable

### 🤖 AI Fix Suggestions
- Sends top 12 issues to **xAI Grok API**
- Returns a prioritized action plan with code examples
- API key stays client-side (never stored server-side)

</td>
<td width="50%">

### 📊 Multi-Format Reports
- **HTML** — dark-themed, fully standalone
- **PDF** — via WeasyPrint (preferred) or ReportLab fallback
- **DOCX** — structured Word document via python-docx
- **JSON** — raw machine-readable output

### 📦 Multi-Source Upload
- `.zip`, `.tar`, `.tar.gz` archive upload
- GitHub / GitLab / Bitbucket URL (`git clone --depth 1`)
- Folder drag-and-drop (Chrome/Edge via `webkitGetAsEntry`)
- Multiple files in one upload

### 🛡️ Security & Infrastructure
- **Zip-slip prevention** + symlink rejection on extraction
- Per-file and total-archive size guards
- **Disk quota enforcement** (2 GB default)
- **Rate limiting** via `flask-limiter` (8 req/min default)
- Background `CleanupManager` thread with configurable TTL
- XSS-safe HTML templating via `markupsafe`
- `/health` endpoint for load balancer checks

</td>
</tr>
</table>

---

## 🚀 Quick Start

### Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| 🐍 Python | 3.10+ | [python.org](https://python.org) |
| 📦 pip | latest | included with Python |
| 🟢 Node.js | 16+ (optional) | Required for ESLint + Stylelint + Lighthouse |
| 🔵 Git | any | Required for GitHub URL cloning |
| 🌐 Google Chrome | any (optional) | Required for Lighthouse headless audit |

---

### ⚡ One-Command Run

```bash
python WebAnalyzer.py
```

> **That's it.** The app auto-installs all missing Python packages on first launch, then starts the server at `http://localhost:5000`.

---

### Step-by-Step Setup

**Step 1 — Clone the repository**

```bash
git clone https://github.com/arsalan-khan-dev/Web-Analyzer.git
cd Web-Analyzer
```

**Step 2 — (Recommended) Create a virtual environment**

```bash
# Windows
python -m venv .venv
.venv\Scripts\activate

# macOS / Linux
python3 -m venv .venv
source .venv/bin/activate
```

**Step 3 — Install Python dependencies**

```bash
pip install -r requirements.txt
```

Or let the app auto-install on first run:

```bash
python WebAnalyzer.py
```

**Step 4 — (Optional) Install Node.js tools for full scanning**

```bash
# ESLint — JavaScript/TypeScript static analysis
npm install -g eslint

# Stylelint — CSS/SCSS linting
npm install -g stylelint stylelint-config-standard

# Lighthouse — performance & accessibility scores
npm install -g lighthouse
```

**Step 5 — Run**

```bash
python WebAnalyzer.py
# → Open http://localhost:5000
```

---

## 📦 Dependencies

### Python Libraries

| Package | Version | Purpose |
|---|---|---|
| `flask` | 3.x | Web framework + routing |
| `flask-limiter[redis]` | latest | Rate limiting (8 req/min) |
| `beautifulsoup4` | 4.14.3 | HTML parsing for accessibility + SEO checks |
| `lxml` | latest | Fast HTML/XML parser (bs4 backend) |
| `requests` | latest | HTTP client for xAI Grok API calls |
| `python-docx` | latest | DOCX report generation |
| `reportlab` | latest | PDF report generation (fallback) |
| `markupsafe` | latest | XSS-safe HTML escaping |
| `pyyaml` | latest | `config.yaml` loading |
| `colorama` | latest | Colored terminal output (Windows) |
| `gunicorn` | latest | Production WSGI server (auto-used if installed) |
| `weasyprint` | optional | PDF generation (preferred over ReportLab) |
| `bandit` | optional | Python static security analysis |

**Install all at once:**

```bash
pip install flask "flask-limiter[redis]" beautifulsoup4 lxml requests \
            python-docx reportlab markupsafe pyyaml colorama gunicorn weasyprint bandit
```

Or use the requirements file:

```bash
pip install -r requirements.txt
```

### Node.js Tools (Optional but Recommended)

| Tool | Install Command | Purpose |
|---|---|---|
| ESLint | `npm i -g eslint` | JS/TS security + quality linting |
| Stylelint | `npm i -g stylelint` | CSS/SCSS rule linting |
| Lighthouse | `npm i -g lighthouse` | Performance, SEO, A11y scores |

> Without Node.js tools, the app still runs — it falls back to regex-based analysis only.

### `requirements.txt`

```txt
flask>=3.0.0
flask-limiter[redis]>=3.0.0
beautifulsoup4>=4.14.0
lxml>=5.0.0
requests>=2.31.0
python-docx>=1.1.0
reportlab>=4.0.0
markupsafe>=2.1.0
pyyaml>=6.0.0
colorama>=0.4.6
gunicorn>=21.0.0
weasyprint>=60.0
bandit>=1.7.0
```

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         BROWSER (Vanilla JS)                        │
│   Upload Archive / GitHub URL  →  /analyze                          │
│   Download Report              →  /download/<fmt>                   │
│   AI Suggestions               →  /ai_suggest                       │
└──────────────────────────┬──────────────────────────────────────────┘
                           │  HTTP + Rate Limit (flask-limiter)
┌──────────────────────────▼──────────────────────────────────────────┐
│                        FLASK APP (WebAnalyzer.py)                   │
│                                                                      │
│  ┌─────────────┐   ┌──────────────────┐   ┌──────────────────────┐ │
│  │  Extraction │   │AnalysisOrchestra-│   │  ReportGenerator     │ │
│  │  safe_zip   │   │tor               │   │  HTML / PDF          │ │
│  │  safe_tar   │──▶│  RegexAnalyzer   │──▶│  DOCX / JSON         │ │
│  │  git clone  │   │  BanditScanner   │   │  LH scores           │ │
│  └─────────────┘   │  ESLintScanner   │   │  AI suggestions      │ │
│                    │  StylelintScanner│   └──────────────────────┘ │
│  ┌─────────────┐   │  PerformanceAnal │                             │
│  │ CleanupMgr  │   │  SEOAnalyzer     │   ┌──────────────────────┐ │
│  │ (TTL 30min) │   │  A11yAnalyzer    │   │  LighthouseRunner    │ │
│  │ disk quota  │   └──────────────────┘   │  (temp HTTP server   │ │
│  └─────────────┘                          │   + headless Chrome) │ │
│                                           └──────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
                           │
               ┌───────────▼───────────┐
               │  /tmp/webanalyzer_*   │
               │  uploads + reports    │
               │  (auto-cleaned)       │
               └───────────────────────┘
```

---

## 📁 Project Structure

```
Web-Analyzer/
│
├── WebAnalyzer.py              ← Single-file application (all logic)
│   │
│   ├── _ensure_deps()          ← Auto-installs missing pip packages
│   ├── _load_config()          ← Loads config.yaml (or uses defaults)
│   │
│   ├── safe_extract_zip()      ← Zip-slip-safe ZIP extractor
│   ├── safe_extract_tar()      ← Zip-slip-safe TAR/TAR.GZ extractor
│   ├── clone_github_repo()     ← git clone --depth 1 (GitHub/GitLab/BB)
│   │
│   ├── CleanupManager          ← Background TTL cleanup + disk quota guard
│   ├── RegexAnalyzer           ← Pattern-based checks: JS/TS/Python/HTML/CSS/PHP/Java
│   ├── BanditScanner           ← Bandit CLI integration (Python files)
│   ├── ESLintScanner           ← ESLint CLI integration (JS/TS files)
│   ├── StylelintScanner        ← Stylelint CLI integration (CSS/SCSS)
│   ├── LighthouseRunner        ← Lighthouse CLI via temp HTTP server
│   ├── PerformanceAnalyzer     ← File-size based performance checks
│   ├── SEOAnalyzer             ← robots.txt, sitemap, canonical checks
│   ├── AccessibilityAnalyzer   ← skip-nav, lang attr, ARIA checks
│   ├── get_ai_suggestions()    ← xAI Grok API integration
│   ├── ReportGenerator         ← HTML / PDF / DOCX / JSON report builder
│   ├── AnalysisOrchestrator    ← Coordinates all scanners per session
│   │
│   └── Flask Routes
│       ├── GET  /              ← Serves the UI (render_template_string)
│       ├── POST /analyze       ← Main analysis endpoint
│       ├── POST /download/<fmt>← Report download (html/pdf/docx/json)
│       ├── POST /ai_suggest    ← Grok AI suggestions endpoint
│       └── GET  /health        ← Health check for load balancers
│
├── config.yaml                 ← Optional: override default settings
├── requirements.txt            ← Python dependencies
├── Dockerfile                  ← Docker container definition
├── docker-compose.yml          ← Docker Compose for easy deployment
├── webanalyzer.log             ← Rotating log file (auto-created)
└── README.md                   ← This file
```

---

## ⚙️ Configuration

Create a `config.yaml` in the project root to override any default:

```yaml
# config.yaml — WebAnalyzer configuration

debug: false
host: "0.0.0.0"
port: 5000
workers: 4                    # Gunicorn worker count

# Upload limits
max_upload_mb: 500            # Max single upload size
max_file_size_mb: 50          # Max size per extracted file
max_total_size_mb: 400        # Max total extracted size per session
disk_quota_gb: 2.0            # Global /tmp disk quota

# Rate limiting
rate_limit: "8 per minute"    # flask-limiter format

# Session
session_ttl_minutes: 30       # Auto-cleanup after this many minutes

# AI (optional)
xai_api_key: ""               # Set here or via XAI_API_KEY env var

# Logging
log_file: "webanalyzer.log"
log_level: "INFO"             # DEBUG | INFO | WARNING | ERROR

# Directories to skip during scan
exclude_dirs:
  - ".git"
  - "node_modules"
  - "__pycache__"
  - ".venv"
  - "venv"
  - "dist"
  - "build"
```

**Environment variable override:**

```bash
export XAI_API_KEY="your-xai-api-key-here"
export WEBANALYZER_CONFIG="/path/to/custom_config.yaml"
python WebAnalyzer.py
```

---

## 🔍 Analysis Engines

| Engine | Language(s) | Type | Requires |
|---|---|---|---|
| `RegexAnalyzer` | JS, TS, Python, HTML, CSS, PHP, Java | Pattern matching | Nothing (built-in) |
| `BanditScanner` | Python | Static AST analysis | `pip install bandit` |
| `ESLintScanner` | JavaScript, TypeScript, JSX, TSX | Lint rules | `npm i -g eslint` |
| `StylelintScanner` | CSS, SCSS | CSS rules | `npm i -g stylelint` |
| `LighthouseRunner` | HTML (whole site) | Performance audit | `npm i -g lighthouse` + Chrome |
| `PerformanceAnalyzer` | All | File size checks | Nothing (built-in) |
| `SEOAnalyzer` | HTML | robots.txt, sitemap | Nothing (built-in) |
| `AccessibilityAnalyzer` | HTML | WCAG basics | Nothing (built-in) |

---

## 🐳 Docker

**Run with Docker (zero local setup):**

```bash
# Build
docker build -t webanalyzer .

# Run
docker run -p 5000:5000 -e XAI_API_KEY=your_key webanalyzer
```

**Or with Docker Compose:**

```bash
docker-compose up --build
```

> Open `http://localhost:5000` after startup.

---

## 🛡️ Security Notes

- All archive extraction is protected against **zip-slip path traversal**
- Symlinks, hard links, block/char devices in archives are **silently skipped**
- All HTML output is **XSS-escaped** via `markupsafe.escape()`
- xAI API keys are **never stored** server-side — sent per request only
- Git clones are restricted to `github.com`, `gitlab.com`, `bitbucket.org`
- Sessions are **auto-deleted** after 30 minutes (configurable)

---

## 📡 API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Serves the full UI |
| `POST` | `/analyze` | Upload archive or JSON `{"github_url": "..."}` |
| `POST` | `/download/html` | Download HTML report |
| `POST` | `/download/pdf` | Download PDF report |
| `POST` | `/download/docx` | Download Word report |
| `POST` | `/download/json` | Download JSON report |
| `POST` | `/ai_suggest` | Get Grok AI fix suggestions |
| `GET` | `/health` | Health check → `{"status": "ok"}` |

---

## 🤝 Contributing

```bash
# Fork → branch → commit → PR
git checkout -b feature/new-scanner
git commit -m "feat: add SAST scanner for Go files"
git push origin feature/new-scanner
```

---

## 📄 License

Licensed under the **MIT License** — free to use, modify, and distribute with attribution.

---

## 👤 Author

<div align="center">

**Arsalan Khan**

[![GitHub](https://img.shields.io/badge/GitHub-arsalan--khan--dev-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/arsalan-khan-dev)
[![Repository](https://img.shields.io/badge/Repo-Web--Analyzer-4a7ec7?style=for-the-badge&logo=github&logoColor=white)](https://github.com/arsalan-khan-dev/Web-Analyzer)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-arsalan--khan-0A66C2?style=for-the-badge&logo=linkedin&logoColor=white)](https://linkedin.com/in/-arsalan-khan)

</div>

---

<div align="center">

**Built with precision. Secured by design.**

*© 2025 WebAnalyzer v3.0 · Built by Arsalan Khan*

</div>
