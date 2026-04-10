import json
import datetime
from typing import Dict, List

class VEXGenerator:
    def __init__(self, original_advisory_id: str):
        self.advisory_id = original_advisory_id
        self.timestamp = datetime.datetime.now().isoformat()

    def generate_vex_report(self, cve: str, analysis_results: List[Dict]) -> Dict:
        """
        Generates an audit-ready VEX report with deep XAI (Scorecard & SSVC reasoning).
        """
        vex_json = {
            "document": {
                "category": "csaf_vex",
                "publisher": {
                    "category": "other",
                    "name": "LAT-OT XAI-Triage System"
                },
                "title": f"Audit-Ready VEX for {cve}",
                "tracking": {
                    "id": f"VEX-XAI-{self.advisory_id}",
                    "status": "final",
                    "version": "1.0",
                    "initial_release_date": self.timestamp,
                    "current_release_date": self.timestamp
                }
            },
            "vulnerabilities": [
                {
                    "cve": cve,
                    "product_status": {
                        "known_affected": [],
                        "not_affected": [],
                        "under_investigation": []
                    },
                    "threats": [],
                    "notes": []
                }
            ]
        }

        for result in analysis_results:
            asset_id = result.get('asset_id')
            status = result.get('vex_status', 'under_investigation')
            
            # 1. Product Status
            if status in vex_json["vulnerabilities"][0]["product_status"]:
                vex_json["vulnerabilities"][0]["product_status"][status].append(asset_id)
            
            # 2. SSVC Decision Points as Metadata
            ssvc = result.get('ssvc_decision_points', {})
            ssvc_text = ", ".join([f"{k}: {v}" for k, v in ssvc.items()])
            
            # 3. Decision Scorecard as Impact Statement
            scorecard = result.get('decision_factor_scorecard', [])
            scorecard_formatted = "\n".join([
                f"- {f.get('factor')}: {f.get('value')} (Influence: {f.get('influence')}, Weight: {f.get('weight')}) - {f.get('note')}"
                for f in scorecard
            ])

            # Combine into a formal Threat Note
            impact_details = (
                f"Asset: {asset_id}\n"
                f"Recommendation: {result.get('recommendation')} (Risk: {result.get('risk_level')})\n"
                f"SSVC Profile: {ssvc_text}\n"
                f"Decision Scorecard:\n{scorecard_formatted}\n"
                f"Justification: {result.get('justification_chain_of_thought')}\n"
                f"Recommended Action: {result.get('action')}"
            )
            
            vex_json["vulnerabilities"][0]["threats"].append({
                "category": "impact_statement",
                "details": impact_details,
                "product_ids": [asset_id]
            })

        return vex_json

if __name__ == "__main__":
    # Simulate high-precision result
    sample_analysis = [
        {
          "asset_id": "PLC-01",
          "recommendation": "PATCH",
          "vex_status": "known_affected",
          "risk_level": "Critical",
          "ssvc_decision_points": {
            "exploitation": "Active exploitation",
            "automatable": "Yes",
            "technical_impact": "Total",
            "mission_impact": "Critical"
          },
          "decision_factor_scorecard": [
            {"factor": "Safety", "value": "TRUE", "influence": "Positive", "weight": "High", "note": "Safety PLC requires highest protection."}
          ],
          "justification_chain_of_thought": "Reasoning steps...",
          "action": "Patch now."
        }
    ]
    gen = VEXGenerator("SSA-123456")
    print(json.dumps(gen.generate_vex_report("CVE-2024-001", sample_analysis), indent=2))
