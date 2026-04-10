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
        """Generates a high-precision prompt based on the SSVC decision points from the Exposé."""
        prompt_parts = []
        
        system_instr = """SYSTEM: You are an OT Security Analyst for Critical Infrastructure.
Your task is to triage security advisories using the SSVC (Stakeholder-Specific Vulnerability Categorization) framework.

CORE RULES:
1. Base analysis ONLY on provided Advisory Data and Asset Context.
2. Structure reasoning using SSVC Decision Points: Exploitation, Automatable, Technical Impact, Mission & Wellbeing.
3. Be EXTREMELY cautious about safety-relevant assets (Purdue Level 1/2, Safety-Relevance=True).
4. Provide a Decision-Factor-Scorecard for every affected asset.

### EXAMPLE OF HIGH-QUALITY ANALYSIS (FEW-SHOT):
ADVISORY: CVE-2023-1234 (RCE in Web Server)
ASSET: PLC-01 (Purdue L1, Safety: True, Internet: False)
{
  "asset_id": "PLC-01",
  "recommendation": "PATCH",
  "vex_status": "known_affected",
  "risk_level": "Critical",
  "decision_factor_scorecard": {
     "cvss_severity": "9.8 (Critical)",
     "safety_relevance": "Asset is safety-relevant, RCE could bypass safety interlocks.",
     "purdue_level_context": "Level 1 - Core control logic layer.",
     "patch_machbarkeit": "Vendor fix available."
  },
  "justification_chain_of_thought": "Exploitation is possible via the web server. Although not internet-exposed, an internal lateral movement could reach this L1 asset. Given its safety-relevance, the mission impact of a compromised PLC is unacceptable.",
  "action": "Disable web server immediately if not needed; otherwise, patch in next maintenance window."
}
"""
        prompt_parts.append(system_instr)

        for vuln in self.vulnerabilities:
            affected_cpes = vuln.get('affected_products', [])
            matched_assets = self._match_assets(affected_cpes)
            
            if not matched_assets:
                continue

            # ADVISORY DATA
            vuln_context = f"\n### ADVISORY: {vuln.get('cve')} - {vuln.get('title')}\n"
            vuln_context += f"Technical Description: {vuln.get('description')}\n"
            vuln_context += f"Remediation: {vuln.get('remediations')[0].get('details') if vuln.get('remediations') else 'No remediation data'}\n"
            prompt_parts.append(vuln_context)

            # ASSET CONTEXT
            asset_context = "\n### ASSETS POTENTIALLY AFFECTED:\n"
            for asset in matched_assets:
                asset_context += f"- Asset ID: {asset['asset_id']} ({asset['name']})\n"
                asset_context += f"  Purdue Level: {asset.get('purdue_level')} | Safety-Relevant: {asset.get('safety_relevant')}\n"
                asset_context += f"  Internet Exposed: {asset.get('internet_exposed')} | Target SL (IEC 62443): {asset.get('iec62443_sl_target')}\n"
                asset_context += f"  Current Firmware: {asset.get('firmware')}\n"
            prompt_parts.append(asset_context)

            # TASK & OUTPUT FORMAT (XAI focused)
            task_request = """
### ANALYSIS TASK:
For each asset, determine the final recommendation (PATCH / MITIGATE / ACCEPT) by reasoning through:
1. EXPLOITATION (Is there active exploit code? Is the asset reachable?)
2. AUTOMATABLE (Can an attacker automate the exploitation at scale?)
3. TECHNICAL IMPACT (Does it affect Integrity, Availability, or Safety?)
4. MISSION & WELLBEING (Impact on plant operation and human safety?)

### EXPECTED OUTPUT (JSON ONLY):
[
  {
    "asset_id": "ASSET-ID",
    "recommendation": "PATCH | MITIGATE | ACCEPT",
    "vex_status": "known_affected | not_affected | under_investigation",
    "risk_level": "Low | Medium | High | Critical",
    "decision_factor_scorecard": {
       "cvss_severity": "Score/Impact",
       "safety_relevance": "How it influenced the decision",
       "purdue_level_context": "Impact of network segment",
       "patch_machbarkeit": "Is a patch available and applicable?"
    },
    "justification_chain_of_thought": "Step-by-step reasoning citing advisory data",
    "action": "Immediate tactical step for plant operator"
  }
]
"""
            prompt_parts.append(task_request)

        return "".join(prompt_parts)

if __name__ == "__main__":
    import os
    from src.parser.csaf_parser import CSAFParser
    from src.utils.asset_loader import AssetLoader

    # Test Run
    with open("data/examples/sample_advisory.json", 'r') as f:
        advisory_data = json.load(f)
    
    loader = AssetLoader()
    asset_data = loader.load_from_csv("data/examples/assets.csv")

    parser = CSAFParser(advisory_data)
    vulns = parser.extract_vulnerabilities()
    
    engine = TriageEngine(vulns, asset_data)
    print(engine.generate_ssvc_prompt())
