# LLM-powered Advisory Triage for OT-Security (LAT-OT)

[![Open Source](https://img.shields.io/badge/Open%20Source-Yes-brightgreen)](https://github.com/itopac-cmyk/LAT-OT)
[![Status](https://img.shields.io/badge/Status-Advanced%20Research%20Prototype-blue)](https://github.com/itopac-cmyk/LAT-OT)
[![Framework](https://img.shields.io/badge/Framework-SSVC%20%2F%20CSAF%20%2F%20VEX-orange)](https://docs.oasis-open.org/csaf)

## 🎯 The Mission: Closing the "Last Mile" of OT-Triage
LAT-OT is a research-driven framework designed to automate the triage of security advisories (CSAF/VEX) for Operational Technology (OT). 

While existing tools focus on **Publishing** and **Matching**, LAT-OT addresses the **"Last Mile"**: **Contextualization and Decision-Making**. By leveraging the reasoning capabilities of Large Language Models (LLMs) like **Claude Max** or local models like **Qwen3**, LAT-OT correlates advisories with specific industrial context to generate actionable, audit-ready mitigation steps.

---

## 🚀 Key Features (Master Thesis Scope)

### 1. Audit-Ready XAI (Explainable AI)
Every recommendation (PATCH / MITIGATE / ACCEPT) is backed by a **Decision-Factor-Scorecard**. Instead of a "Black Box" response, the system quantifies the influence of:
*   **Safety Relevance:** Impact on human safety and physical interlocks.
*   **Purdue Level Context:** Risk based on the asset's layer in the industrial network.
*   **Reachability:** Real-world exploitability considering air-gaps and internet exposure.
*   **Remediation Feasibility:** Evaluation of vendor-provided fixes.

### 2. SSVC-Based Reasoning Engine
Implementation of the **Stakeholder-Specific Vulnerability Categorization (SSVC)** framework:
*   **Exploitation:** (None, PoC, Active)
*   **Automatable:** (No, Partial, Yes)
*   **Technical Impact:** (Partial, Total)
*   **Mission & Wellbeing:** (Minimal, Critical)

### 3. Native CSAF/VEX Integration
*   **CSAF Ingestion:** Robust parsing of machine-readable advisories from vendors like **Siemens** and **Schneider Electric**.
*   **VEX Generation:** Automated creation of **Vulnerability Exploitability eXchange (VEX)** documents, feeding LLM-reasoning back into standardized security workflows.

### 4. Data Sovereignty (On-Premise LLM)
Optimized for OT environments where data privacy is paramount. Supports local inference via **Ollama (Qwen3)** on edge hardware (e.g., Apple Silicon M4 Pro).

---

## 🏗️ Research Architecture
The system follows a rigorous **Design Science Research (DSRM)** approach:
1.  **Ingestion:** Extracts CVE, CPE, and CVSS data.
2.  **Contextualization:** Correlates with 3 synthetic OT inventories (Manufacturing, Energy, Water).
3.  **Triage:** Generates high-precision prompts with few-shot examples.
4.  **Evaluation:** Measures performance using **Cohen's Kappa**, Precision, and Recall against an Expert Panel.

---

## 🎓 Academic Background
Developed by **Isato Pac** for the **M.Sc. Cyber Security** at **Hochschule Aalen (Aalen University)** under the supervision of **Dr. Andreas Aschenbrenner**.

## 🛠️ Getting Started
```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run a batch analysis across all inventories
PYTHONPATH=. python3 src/batch_processor.py

# 3. View the generated audit-ready prompts
cat reports/batch/prompt_*.txt
```
