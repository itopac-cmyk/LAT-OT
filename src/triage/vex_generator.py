import json
import datetime
from typing import Dict, List

class VEXGenerator:
    def __init__(self, original_advisory_id: str):
        self.advisory_id = original_advisory_id
        self.timestamp = datetime.datetime.now().isoformat()

    def generate_vex_report(self, cve: str, analysis_results: List[Dict]) -> Dict:
        """
        Creates an advanced CSAF/VEX report incorporating SSVC decisions and XAI scorecards.
        """
        vex_json = {
            "document": {
                "category": "csaf_vex",
                "publisher": {
                    "category": "other",
                    "name": "LAT-OT Triage System (SSVC-Powered)"
                },
                "title": f"VEX for {cve} - Local Asset Triage",
                "tracking": {
                    "id": f"VEX-LAT-{self.advisory_id}",
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
                    "threats": []
                }
            ]
        }

        for result in analysis_results:
            status = result.get('vex_status', 'under_investigation')
            asset_id = result.get('asset_id')
            
            # Mapping status
            if status in vex_json["vulnerabilities"][0]["product_status"]:
                vex_json["vulnerabilities"][0]["product_status"][status].append(asset_id)
            
            # Detailed threat analysis (The Decision-Factor-Scorecard)
            scorecard = result.get('decision_factor_scorecard', {})
            scorecard_text = " | ".join([f"{k}: {v}" for k, v in scorecard.items()])
            
            vex_json["vulnerabilities"][0]["threats"].append({
                "category": "impact_statement",
                "details": (
                    f"Asset {asset_id} Recommendation: {result.get('recommendation')} ({result.get('risk_level')}). "
                    f"Justification: {result.get('justification_chain_of_thought')}. "
                    f"Scorecard: {scorecard_text}. "
                    f"Action: {result.get('action')}"
                ),
                "product_ids": [asset_id]
            })

        return vex_json

if __name__ == "__main__":
    # Test with mockup data mirroring the new engine output
    sample_analysis = [
        {
            "asset_id": "PLC-PROD-01",
            "recommendation": "PATCH",
            "vex_status": "known_affected",
            "risk_level": "High",
            "decision_factor_scorecard": {
               "cvss_severity": "9.8 (Critical)",
               "safety_relevance": "High (Purdue Level 1)",
               "purdue_level_context": "Deeply integrated in production cell",
               "patch_machbarkeit": "Firmware v2.9.4 available"
            },
            "justification_chain_of_thought": "Firmware v2.9.2 is below the required v2.9.4. Vulnerability allows RCE.",
            "action": "Immediate update in next maintenance slot."
        }
    ]
    
    gen = VEXGenerator("LAT-OT-2026-001")
    report = gen.generate_vex_report("CVE-2026-9999", sample_analysis)
    print(json.dumps(report, indent=2))
EOF
