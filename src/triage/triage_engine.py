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
            # Simple exact match (can be improved with prefix/wildcard matching)
            if asset.get('cpe') in affected_cpes:
                matched.append(asset)
        return matched

    def generate_claude_prompt(self) -> str:
        """Constructs a high-precision prompt for Claude Max/Sonnet."""
        prompt_parts = []
        
        # System Instructions (to minimize hallucinations)
        system_instr = """SYSTEM: You are an OT Security Analyst specializing in Critical Infrastructure.
Your task is to triage security advisories against a specific asset inventory.
RULES:
1. Base your assessment ONLY on the provided Advisory Data and Asset Context.
2. If the data is insufficient to determine impact, state "UNKNOWN" and explain why.
3. Use a Chain-of-Thought approach: reason step-by-step before giving the final rating.
4. Cite specific fields from the Advisory Data for your findings.
5. Provide a VEX-style status (e.g., 'known_affected', 'not_affected', 'under_investigation').
"""
        prompt_parts.append(system_instr)

        for vuln in self.vulnerabilities:
            affected_cpes = vuln.get('affected_products', [])
            matched_assets = self._match_assets(affected_cpes)
            
            if not matched_assets:
                continue

            # Section: Advisory Data
            vuln_context = f"\n### ADVISORY DATA: {vuln.get('cve')} - {vuln.get('title')}\n"
            vuln_context += f"Description: {vuln.get('description')}\n"
            vuln_context += f"Recommended Fix: {vuln.get('remediations')[0].get('details') if vuln.get('remediations') else 'None provided'}\n"
            prompt_parts.append(vuln_context)

            # Section: Asset Context
            asset_context = "\n### ASSET CONTEXT (Potentially Affected Assets):\n"
            for asset in matched_assets:
                asset_context += f"- Asset ID: {asset['asset_id']} ({asset['name']})\n"
                asset_context += f"  CPE: {asset['cpe']}\n"
                asset_context += f"  Firmware: {asset['firmware']}\n"
                asset_context += f"  Exposed to Internet: {asset['is_exposed_to_internet']}\n"
                asset_context += f"  Criticality: {asset['criticality']}\n"
            prompt_parts.append(asset_context)

            # Section: Analysis Request
            analysis_request = """
### TASK:
1. Determine if the assets are actually affected based on the description and firmware.
2. Evaluate the operational risk (considering Internet exposure and criticality).
3. Recommend an immediate action for the plant operator.
4. Provide the final VEX Status and Risk Level (Low/Medium/High/Critical).

### OUTPUT FORMAT (IMPORTANT):
Return your final assessment in the following JSON format:
[
  {
    "asset_id": "ASSET-ID",
    "vex_status": "known_affected | not_affected | under_investigation",
    "risk_level": "Low | Medium | High | Critical",
    "justification": "Detailed reasoning here",
    "action": "Recommended action here"
  }
]
"""
            prompt_parts.append(analysis_request)

        return "".join(prompt_parts)

if __name__ == "__main__":
    # Test with previous components
    from src.parser.csaf_parser import CSAFParser
    
    # Load Sample Advisory
    with open("data/examples/sample_advisory.json", 'r') as f:
        advisory_data = json.load(f)
    
    # Load Sample Assets
    with open("data/examples/assets.json", 'r') as f:
        asset_data = json.load(f)

    # Parse & Engine Run
    parser = CSAFParser(advisory_data)
    vulns = parser.extract_vulnerabilities()
    
    engine = TriageEngine(vulns, asset_data)
    final_prompt = engine.generate_claude_prompt()
    
    print("-" * 30 + " GENERATED CLAUDE PROMPT " + "-" * 30)
    print(final_prompt)
