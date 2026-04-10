# LAT-OT System Design

## Architecture Overview
LAT-OT is designed to bridge the gap between complex IT security advisories and the operational reality of OT environments.

### 1. Ingestion Layer
- **CSAF/VEX Parser:** Consumes machine-readable advisories (JSON).
- **Asset Inventory Interface:** Imports asset data from common OT management tools (e.g., Clarion, Nozomi, CSV/Excel).

### 2. Analysis Layer (LLM powered)
- **Precise Matching:** LLM-based correlation between advisory-affected CPEs/products and local assets.
- **Exploitability Analysis:** Reasoning about whether a vulnerability is reachable in the specific network topology.
- **VEX Status Generation:** Automating the transition from advisory to VEX (Vulnerability Exploitability eXchange).

### 3. Reporting Layer
- **OT Operator Briefing:** Natural language summary of risk (Impact: Low/Medium/High/Critical).
- **Mitigation Workflow:** Step-by-step guidance for plant technicians.

## Mitigation of Hallucinations
- **RAG (Retrieval Augmented Generation):** Grounding LLM responses in actual advisory text sections.
- **Verification Loop:** Self-consistency checks and mandatory citation of source fields.
