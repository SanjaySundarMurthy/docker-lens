# 🔍 Docker Lens

**Docker Image Analyzer & Optimizer CLI** — Lint Dockerfiles, analyze images, scan vulnerabilities, and optimize size with beautiful terminal output.

[![PyPI version](https://badge.fury.io/py/docker-lens.svg)](https://pypi.org/project/docker-lens/)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## ✨ Features

| Feature | Description | Docker Required? |
|---------|-------------|:----------------:|
| 📝 **Dockerfile Linter** | 35 best-practice rules across 4 categories | ❌ No |
| 🐳 **Image Analyzer** | Layer breakdown, metadata, scoring | ✅ Yes |
| 🔐 **Security Scanner** | CVE vulnerability detection with built-in database | ✅ Yes |
| ⚡ **Efficiency Optimizer** | Size reduction suggestions with estimated savings | ✅ Yes |
| 🔄 **Image Comparison** | Side-by-side comparison of two images | ✅ Yes |
| 📜 **Build History** | Full layer history viewer | ✅ Yes |
| 🎬 **Demo Mode** | Full demo with sample data — no Docker needed! | ❌ No |
| 📊 **JSON Reports** | Export any result to structured JSON | — |

## 🚀 Quick Start

### Installation

```bash
pip install docker-lens
```

### Try It Now (No Docker Required!)

```bash
# Run the demo — shows all features with sample data
docker-lens demo

# Lint a Dockerfile — works without Docker
docker-lens lint Dockerfile

# List all 35 lint rules
docker-lens rules
```

### With Docker

```bash
# Analyze an image
docker-lens analyze nginx:latest

# Security scan
docker-lens scan python:3.11

# Optimization suggestions
docker-lens optimize node:18

# Compare two images
docker-lens compare python:3.11 python:3.11-slim

# View build history
docker-lens history nginx:latest
```

## 📝 Dockerfile Linter — 35 Rules

The linter checks your Dockerfile against 35 best-practice rules across 4 categories:

### 🔒 Security (SEC001–SEC010)
| Rule | Description |
|------|-------------|
| SEC001 | Missing USER instruction — container runs as root |
| SEC002 | Using sudo in RUN commands |
| SEC003 | Secrets/passwords hardcoded in ENV |
| SEC004 | Unpinned base image tag (using :latest) |
| SEC005 | Installing SSH server in container |
| SEC006 | Using curl\|bash pattern (remote code execution risk) |
| SEC007 | Using ADD instead of COPY for local files |
| SEC008 | Exposing sensitive port 22 (SSH) |
| SEC009 | Running with --privileged flag |
| SEC010 | No HEALTHCHECK instruction |

### ⚡ Efficiency (EFF001–EFF010)
| Rule | Description |
|------|-------------|
| EFF001 | Missing --no-install-recommends in apt-get |
| EFF002 | apt-get cache not cleaned in same layer |
| EFF003 | Multiple consecutive RUN instructions |
| EFF004 | No multi-stage build when build tools are present |
| EFF005 | Missing --no-cache for apk |
| EFF006 | Missing --no-cache-dir for pip |
| EFF007 | Using large base image (full variant) |
| EFF008 | Separate chmod/chown layer |
| EFF009 | Large COPY before dependency install |
| EFF010 | npm install without --production |

### 🔧 Maintainability (MNT001–MNT010)
| Rule | Description |
|------|-------------|
| MNT001 | No LABEL metadata |
| MNT002 | Using deprecated MAINTAINER |
| MNT003 | Missing WORKDIR instruction |
| MNT004 | Relative WORKDIR path |
| MNT005 | Using shell form for CMD/ENTRYPOINT |
| MNT006 | No EXPOSE instruction |
| MNT007 | Missing .dockerignore |
| MNT008 | Unpinned package versions |
| MNT009 | Multiple FROM without naming (AS) |
| MNT010 | No description LABEL |

### 🛡️ Reliability (REL001–REL005)
| Rule | Description |
|------|-------------|
| REL001 | Multiple CMD instructions |
| REL002 | No SHELL pipefail for pipes |
| REL003 | Multiple ENTRYPOINT instructions |
| REL004 | COPY before package install |
| REL005 | apt-get install without -y flag |

## 🔐 Security Scanner

Scans Docker images against a curated vulnerability database of well-known CVEs:

- **OpenSSL** vulnerabilities (CVE-2023-5678, CVE-2023-5363)
- **curl** vulnerabilities (CVE-2023-46218, CVE-2022-43551)
- **zlib** heap overflow (CVE-2022-37434)
- **glibc** Looney Tunables (CVE-2023-4911)
- **nginx** HTTP/2 Rapid Reset (CVE-2023-44487)
- And more...

```bash
docker-lens scan nginx:1.25.3 --json report.json
```

## ⚡ Efficiency Optimizer

Analyzes your image and suggests concrete optimizations:

- **Base Image Alternatives** — Switch from full → slim → alpine with size estimates
- **Package Cache Cleanup** — Detect uncleaned apt/pip/npm caches
- **Multi-Stage Build** — Detect build tools in final image
- **Layer Optimization** — Reduce layer count, find oversized layers

## 📊 JSON Export

Export any result to structured JSON for CI/CD integration:

```bash
docker-lens lint Dockerfile --json lint-report.json
docker-lens scan nginx:latest --json security-report.json
docker-lens optimize python:3.11 --json efficiency-report.json
```

## 🎬 Demo Mode

See Docker Lens in action without Docker installed:

```bash
docker-lens demo
```

This runs through all 4 analysis types with realistic sample data, showing the beautiful terminal output.

## 🛠️ Development

```bash
# Clone and install
git clone https://github.com/SanjaySundarMurthy/docker-lens.git
cd docker-lens
pip install -e ".[dev]"

# Run tests
pytest -v

# Lint
ruff check .
```

## 📦 Tech Stack

- **Python 3.9+** — Core runtime
- **Click** — CLI framework
- **Rich** — Beautiful terminal rendering
- **Docker SDK** — Docker API integration

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

## 👤 Author

**Sanjay S** — DevOps Engineer  
[GitHub](https://github.com/SanjaySundarMurthy) · [PyPI](https://pypi.org/user/SanjaySundarMurthy/)
