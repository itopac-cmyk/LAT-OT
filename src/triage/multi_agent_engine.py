import json
import logging
from typing import List, Dict

logger = logging.getLogger(__name__)

class MultiAgentTriage:
    def __init__(self, vulnerabilities: List[Dict], assets: List[Dict]):
        self.vulnerabilities = vulnerabilities
        self.assets = assets

    def generate_multi_agent_prompt(self) -> str:
        """
        Creates a prompt that simulates a 3-agent expert panel debate.
        This is significantly more robust than a single persona prompt.
        """
        prompt_parts = []
        
        # General Context
        prompt_parts.append("SYSTEM: You are an autonomous Multi-Agent Triage Orchestrator.")
        
        # AGENT 1: Security Analyst (Focussed on technical exploitability)
        prompt_parts.append("\n### AGENT ROLE 1: [TECHNICAL SECURITY ANALYST]")
        prompt_parts.append("Goal: Analyze the CVE and EPSS data. Focus on the 'Technical Impact' and 'Exploitation' likelihood.")
        
        # AGENT 2: OT Safety Engineer (Focussed on physical process & safety)
        prompt_parts.append("\n### AGENT ROLE 2: [OT SAFETY & PROCESS ENGINEER]")
        prompt_parts.append("Goal: Analyze the Purdue Level and Safety Relevance. Focus on the 'Mission & Wellbeing' impact.")
        
        # AGENT 3: Compliance & VEX Lead (Final Decision)
        prompt_parts.append("\n### AGENT ROLE 3: [VEX COMPLIANCE LEAD]")
        prompt_parts.append("Goal: Synthesize both views into a final VEX status and provide an audit-ready scorecard.")

        # Data Injection
        for vuln in self.vulnerabilities:
            prompt_parts.append(f"\n--- TRIAGE CASE: {vuln.get('cve')} ---")
            prompt_parts.append(f"ADVISORY DATA: {json.dumps(vuln, indent=2)}")
            
            # Matched Assets with Deep Context
            prompt_parts.append("\nTARGET ASSETS:")
            for asset in self.assets:
                # We show assets even if not matched by CPE to allow LLM-assisted matching
                prompt_parts.append(f"- {asset['asset_id']}: {asset['name']} (CPE: {asset['cpe']}, FW: {asset['firmware']}, Controls: {asset.get('compensatory_controls')})")

            # The Challenge
            prompt_parts.append("""
### THE DEBATE TASK:
1. [Security Analyst] provides a technical exploitability score.
2. [Safety Engineer] identifies if compensatory controls (e.g., Data Diodes) mitigate the technical risk.
3. [VEX Lead] provides the final JSON output based on the consensus.

### EXPECTED JSON OUTPUT:
[
  {
    "asset_id": "...",
    "recommendation": "...",
    "agent_debate_summary": {
       "security_view": "Technical exploitability analysis",
       "safety_view": "Impact on physical process and safety interlocks",
       "mitigation_view": "Effectiveness of existing compensatory controls"
    },
    "ssvc_scorecard": { ... },
    "vex_status": "..."
  }
]
""")
        return "".join(prompt_parts)
