# LAT-OT Architecture & XAI Design Deep-Dive

## 1. Context-Aware Ingestion
LAT-OT does not just "read" advisories; it contextually maps them. 
*   **CSAF Parsing:** We extract not only CVSS scores but also vendor-specific remediation metadata and product trees to build a highly granular view of the threat.
*   **Inventory Mapping:** Assets are enriched with metadata based on the **Purdue Reference Model** and **ISA/IEC 62443 Security Levels**.

## 2. The XAI Scoring Rubric
To prevent LLM "Black Box" reasoning, LAT-OT employs a forced-reasoning rubric in its prompting strategy.

### SSVC Decision Points
We use the **Stakeholder-Specific Vulnerability Categorization (SSVC)** model to guide the LLM's logic:
*   **Exploitation:** Grounded in real-world evidence.
*   **Automatable:** Analyzing if the threat is scriptable/wormable.
*   **Technical Impact:** Evaluating impact on the CIA triad for the specific device.
*   **Mission & Wellbeing:** Determining the impact on production and human life.

### The Decision-Factor-Scorecard
The LLM is required to generate a structured JSON object containing:
1.  **Factor:** (e.g., Safety Relevance)
2.  **Value:** (e.g., TRUE)
3.  **Influence:** (Positive | Negative | Neutral)
4.  **Weight:** (Low | Medium | High | Critical)
5.  **Note:** Audit-ready reasoning text.

## 3. VEX Output Integration
The result of the LLM analysis is mapped back to the **Vulnerability Exploitability eXchange (VEX)** standard. This ensures that the AI-driven triage is not an isolated report but an active participant in a machine-readable security ecosystem.

## 4. Evaluation Methodology
To scientifically validate the triage quality, LAT-OT uses:
*   **Cohen's Kappa (κ):** To measure inter-rater reliability between the LLM and the Expert Panel.
*   **Precision & Recall:** Focused specifically on the "PATCH" recommendation to minimize false negatives in critical infrastructure.
*   **Decision-Factor Scorecard Validation:** Evaluating not just the final choice, but the correctness of the individual factors that led to it.

## 5. Deployment Options
*   **Cloud (Claude Max):** Maximum reasoning capability for deep analysis.
*   **On-Premise (Ollama/Qwen3):** Data sovereignty for OT networks with no internet connectivity.
