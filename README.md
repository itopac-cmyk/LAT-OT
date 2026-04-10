# LLM-powered Advisory Triage for OT-Security (LAT-OT)

[![Open Source](https://img.shields.io/badge/Open%20Source-Yes-brightgreen)](https://github.com/itopac-cmyk/LAT-OT)
[![Status](https://img.shields.io/badge/Status-Active%20Prototype-blue)](https://github.com/itopac-cmyk/LAT-OT)

## 🎯 The Mission
LAT-OT is an open-source framework designed to automate the triage of security advisories for Operational Technology (OT) operators. In an era where "Zero-Day" vulnerabilities are becoming the norm, manual assessment of advisories (CSAF/VEX) is no longer feasible. We leverage the reasoning capabilities of **Claude Max** to correlate advisories with specific industrial asset inventories and prioritize mitigation steps in near real-time.

---

## 🛠️ Current Project Status (Implemented)
We have already built the core components of the ingestion and triage pipeline:

1.  **CSAF/VEX Parser:** A high-efficiency Python parser that extracts critical vulnerability data (CPEs, CVEs, Remediations) from complex CSAF JSON files.
2.  **Asset Inventory Engine:** Supports loading local OT asset inventories (CSV/JSON) with specific operational context (firmware, location, criticality, internet exposure).
3.  **Triage Prompt Synthesizer:** A logic engine that correlates advisories with assets and generates a structured "Chain-of-Thought" prompt for the LLM.
4.  **VEX Generator:** A module that converts LLM-based reasoning back into machine-readable **VEX (Vulnerability Exploitability eXchange)** format.

---

## 🗺️ Roadmap (Upcoming Features)
*   [ ] **Phase 1: Claude API Integration** - Direct integration with Anthropic's Claude API for automated real-time triage.
*   [ ] **Phase 2: RAG Pipeline** - Integrating technical manuals and network topology diagrams via Retrieval-Augmented Generation (RAG) for even higher precision.
*   [ ] **Phase 3: Multi-Format Support** - Expanding support to include CVRF, CycloneDX, and unstructured advisory text.
*   [ ] **Phase 4: OT Operator Web-UI** - A simple, secure dashboard for viewing triaged alerts and VEX reports.

---

## 🏗️ System Architecture
See our [Design Document](docs/DESIGN.md) for a deep dive into the architecture and our strategy for mitigating LLM hallucinations in critical infrastructure.

---

## 🎓 Academic Background
This project is developed by **Isato Pac** as part of the **M.Sc. Cyber Security** program at **Hochschule Aalen (Aalen University)**, focusing on protecting critical infrastructure through AI-driven security automation.

## 🚀 Getting Started (Prototype)
You can test the core logic today:
1.  Check `data/examples/` for sample CSAF and Asset files.
2.  Run the Triage Engine: `PYTHONPATH=. python3 src/triage/triage_engine.py` to see the generated prompt for Claude.
