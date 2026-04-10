# LLM-powered Advisory Triage for OT-Security (LAT-OT)

[![Research](https://img.shields.io/badge/Research-Master%20Thesis-blue)](docs/DESIGN.md)
[![Status](https://img.shields.io/badge/Status-Advanced%20Multi--Agent%20System-orange)]()

## 🎯 The Mission
LAT-OT is a research-driven framework designed to automate the triage of security advisories (CSAF/VEX) for Operational Technology (OT). It solves the **"Last Mile"** of vulnerability management: **Contextualization and Decision-Making**.

---

## 🚀 Advanced Features (April 2026)

### 1. Multi-Agent Reasoning Engine
LAT-OT simulates a 3-agent expert panel to ensure high-precision triage without hallucinations:
- **Technical Analyst Agent:** Deep-dives into CVE & EPSS data.
- **OT Safety Engineer Agent:** Analyzes Purdue Levels and physical risk.
- **Compliance Orchestrator Agent:** Synthesizes the debate into audit-ready VEX documents.

### 2. Deep Context Asset Modeling
Goes beyond simple CPE matching by considering:
- **Compensatory Controls:** Firewalls, Data Diodes, and Read-only SD Cards.
- **Network Topology:** Analyzing the "Network Neighbors" to determine lateral movement risk.

### 3. Triage Dashboard (Port 9001)
A professional Dark-Mode interface to visualize Multi-Agent debate results and the final VEX-compliant risk scores.

---

## 🏗️ Technical Workflow
1. **Ingest:** Parse CSAF/VEX JSON from vendors (Siemens, Schneider).
2. **Contextualize:** Map vulnerabilities to OT assets with deep operational context.
3. **Debate:** Run the Multi-Agent reasoning loop.
4. **Report:** Generate standardized VEX reports and visualize in the Dashboard.

## 🚀 Quick Start
```bash
# 1. Install dependencies
pip install Flask requests

# 2. Run the Multi-Agent Batch Analysis
PYTHONPATH=. python3 src/batch_processor.py

# 3. Start the Triage Dashboard
python3 src/web_ui/app.py
```

---

## 🎓 Academic Background
Developed by **Isato Pac** for the **M.Sc. Cyber Security** at **Hochschule Aalen** (2026).
