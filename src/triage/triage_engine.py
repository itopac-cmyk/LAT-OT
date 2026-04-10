import json
import logging
from typing import List, Dict

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class TriageEngine:
    def __init__(self, vulnerabilities: List[Dict], assets: List[Dict]):
        self.vulnerabilities = vulnerabilities
        self.assets = assets

    def _match_assets(self, affected_cpes: List[str]) -> List[Dict]:
        """Correlates affected CPEs with the local asset inventory."""
        matched = []
        for asset in self.assets:
            if asset.get('cpe') in affected_cpes:
                matched.append(asset)
        return matched

    def generate_ssvc_prompt(self) -> str:
        """
        Deep XAI Triage Engine.
        Implements a multi-dimensional OT risk rubric for verifiable reasoning.
        """
        prompt_parts = []
        
        system_instr = """SYSTEM: You are a Lead OT Security Architect for Critical Infrastructure.
Your task is to triage security advisories using a high-precision, audit-ready version of the SSVC framework.

### OT-RISK SCORING RUBRIC (XAI):
For every decision factor, use the following evidence levels:
1. EXPLOITATION: [None | POC available | Active exploitation in the wild]
2. AUTOMATABLE: [No | Partial (requires user action) | Yes (Wormable/Scriptable)]
3. TECHNICAL IMPACT: [None | Partial (DoS/Config change) | Total (RCE/Device Takeover)]
4. MISSION IMPACT: [None | Minimal (Monitoring lost) | Critical (Physical safety or production loss)]

### CORE REASONING MANDATE:
- You MUST provide a 'Decision-Factor-Scorecard'.
- For every factor (Safety, Purdue Level, Reachability), you must state the 'Influence' [Positive | Negative | Neutral] and a 'Weight' [Low | Medium | High].
- Hallucination Check: If the Advisory does not mention a specific protocol (e.g. MQTT), do NOT assume it is vulnerable.
"""
        prompt_parts.append(system_instr)

        # Few-Shot Example for high-precision XAI
        few_shot = """
### EXAMPLE OF AUDIT-READY ANALYSIS:
ADVISORY: CVE-2024-9999 (RCE in Siemens Web Server)
ASSET: PLC-PROD-01 (S7-1500, Purdue L1, Safety: True)
{
  "asset_id": "PLC-PROD-01",
  "recommendation": "PATCH",
  "vex_status": "known_affected",
  "risk_level": "Critical",
  "ssvc_decision_points": {
    "exploitation": "Active exploitation in the wild (+1 Risk)",
    "automatable": "Yes (+1 Risk)",
    "technical_impact": "Total - RCE (+1 Risk)",
    "mission_impact": "Critical - Safety-Relevant PLC (+1 Risk)"
  },
  "decision_factor_scorecard": [
    {"factor": "Safety Relevance", "value": "TRUE", "influence": "Critical Positive", "weight": "Highest", "note": "Impact on human safety interlocks mandates immediate action."},
    {"factor": "Purdue Level", "value": "Level 1", "influence": "Positive", "weight": "High", "note": "Direct physical process control layer increases impact severity."},
    {"factor": "Internet Exposure", "value": "FALSE", "influence": "Negative", "weight": "Medium", "note": "Air-gap lowers external risk but internal lateral movement is not mitigated."},
    {"factor": "Patch Availability", "value": "v2.9.4 Available", "influence": "Negative", "weight": "High", "note": "Existing fix reduces residual risk once applied."}
  ],
  "justification_chain_of_thought": "Starting with Technical Impact: RCE on a Level 1 PLC. Considering Mission Impact: Asset is safety-relevant, so RCE equals potential safety bypass. Cross-referencing Exploitation: Wild exploits reported. Conclusion: Even without internet exposure, the combined weight of Safety and Purdue Level 1 dictates a PATCH recommendation within 24h.",
  "action": "Isolate Cell 1 network and schedule patch during next shift change."
}
"""
        prompt_parts.append(few_shot)

        for vuln in self.vulnerabilities:
            affected_cpes = vuln.get('affected_products', [])
            matched_assets = self._match_assets(affected_cpes)
            
            if not matched_assets:
                continue

            cvss = vuln.get('cvss_v3', {})
            vuln_context = f"\n### CURRENT ADVISORY: {vuln.get('cve')} - {vuln.get('title')}\n"
            vuln_context += f"Description: {vuln.get('description')}\n"
            vuln_context += f"CVSS v3: {cvss.get('baseScore', 'N/A')} ({cvss.get('baseSeverity', 'N/A')}) | Vector: {cvss.get('vectorString', 'N/A')}\n"
            vuln_context += f"Vendor Remediations: {json.dumps(vuln.get('remediations', []), indent=2)}\n"
            prompt_parts.append(vuln_context)

            asset_context = "\n### LOCAL ASSET CONTEXT:\n"
            for asset in matched_assets:
                asset_context += f"- Asset ID: {asset['asset_id']} ({asset['name']})\n"
                asset_context += f"  Purdue: {asset.get('purdue_level')} | Safety-Rel: {asset.get('safety_relevant')}\n"
                asset_context += f"  Internet: {asset.get('internet_exposed')} | Criticality: {asset.get('criticality')}\n"
                asset_context += f"  IEC 62443 Target SL: {asset.get('iec62443_sl_target')} | FW: {asset.get('firmware')}\n"
            prompt_parts.append(asset_context)

            prompt_parts.append("\n### TASK: Perform the audit-ready triage as shown in the example and return valid JSON.")

        return "".join(prompt_parts)

if __name__ == "__main__":
    import os
    from src.parser.csaf_parser import CSAFParser
    from src.utils.asset_loader import AssetLoader

    # Test Run
    with open("data/raw/siemens/ssa-285644.json", 'r') as f:
        advisory_data = json.load(f)
    
    loader = AssetLoader()
    asset_data = loader.load_from_csv("data/inventories/manufacturing.csv")

    parser = CSAFParser(advisory_data)
    vulns = parser.extract_vulnerabilities()
    
    engine = TriageEngine(vulns, asset_data)
    print(engine.generate_ssvc_prompt())
