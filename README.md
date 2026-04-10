# LLM-powered Advisory Triage for OT-Security (LAT-OT)

[![Open Source](https://img.shields.io/badge/Open%20Source-Yes-brightgreen)](https://github.com/itopac-cmyk/LAT-OT)

## Project Vision
Automating the triage of security advisories for Operational Technology (OT) operators using Large Language Models.

### The Problem
OT environments are flooded with IT-centric security advisories. Manual assessment is slow, error-prone, and requires high-level expertise that is scarce.

### Our Solution (LAT-OT)
An open-source framework to:
1. **Analyze** incoming CSAF/VEX/CVE data.
2. **Correlate** with local industrial asset inventories.
3. **Reason** (via Claude Max) about real-world exploitability.
4. **Prioritize** mitigation steps for plant operators.

## Technical Roadmap
- [ ] Phase 1: CSAF/VEX JSON Ingestion & Basic CPE Matching.
- [ ] Phase 2: LLM Integration (Claude API) for Contextual Analysis.
- [ ] Phase 3: Automated VEX Reporting (Vulnerability Exploitability eXchange).
- [ ] Phase 4: Network Topology Integration for Reachability Analysis.

## Academic Context
Developed at **Hochschule Aalen (M.Sc. Cyber Security)** to address critical infrastructure protection challenges.

---
*For more details, see [docs/DESIGN.md](docs/DESIGN.md).*
