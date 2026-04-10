import json
import datetime
from typing import Dict, List

class VEXGenerator:
    def __init__(self, original_advisory_id: str):
        self.advisory_id = original_advisory_id
        self.timestamp = datetime.datetime.now().isoformat()

    def generate_vex_report(self, cve: str, analysis_results: List[Dict]) -> Dict:
        """
        Creates a simplified CSAF/VEX compliant JSON structure.
        analysis_results: List of {asset_id, vex_status, justification, action}
        """
        vex_json = {
            "document": {
                "category": "csaf_vex",
                "publisher": {
                    "category": "other",
                    "name": "LAT-OT Triage System"
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

        # Populating VEX status from Claude's analysis
        for result in analysis_results:
            status = result.get('vex_status', 'under_investigation')
            asset_id = result.get('asset_id')
            
            # Add to the appropriate status category
            if status in vex_json["vulnerabilities"][0]["product_status"]:
                vex_json["vulnerabilities"][0]["product_status"][status].append(asset_id)
            
            # Add justification as a threat note
            vex_json["vulnerabilities"][0]["threats"].append({
                "category": "impact_statement",
                "details": f"Asset {asset_id}: {result.get('justification')}. Recommended Action: {result.get('action')}",
                "product_ids": [asset_id]
            })

        return vex_json

if __name__ == "__main__":
    # Simulate a result from Claude
    sample_analysis = [
        {
            "asset_id": "PLC-PROD-01",
            "vex_status": "known_affected",
            "justification": "Firmware v2.9.2 is below the required v2.9.4. Integrated web server is active.",
            "action": "Schedule firmware update for next maintenance window."
        }
    ]
    
    gen = VEXGenerator("LAT-OT-2026-001")
    report = gen.generate_vex_report("CVE-2026-9999", sample_analysis)
    print(json.dumps(report, indent=2))
