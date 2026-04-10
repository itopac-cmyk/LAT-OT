import csv
import os
import json
from typing import List, Dict

class ExpertTemplateGenerator:
    def __init__(self, advisory_id: str, assets: List[Dict], cve_id: str):
        self.advisory_id = advisory_id
        self.assets = assets
        self.cve_id = cve_id

    def generate_csv(self, output_path: str):
        """Generates a CSV for experts to fill in their evaluations."""
        headers = ['asset_id', 'asset_name', 'cve_id', 'recommendation', 'justification']
        
        with open(output_path, mode='w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            writer.writerow(['# EXPLAINER:', 'Valid recommendations: PATCH, MITIGATE, ACCEPT', '', '', ''])
            
            for asset in self.assets:
                writer.writerow([
                    asset.get('asset_id'),
                    asset.get('name'),
                    self.cve_id,
                    '', # Placeholder for expert recommendation
                    ''  # Placeholder for expert justification
                ])
        print(f"Expert template generated at: {output_path}")

if __name__ == "__main__":
    # Test data
    sample_assets = [
        {"asset_id": "PLC-PROD-01", "name": "S7-1500 CPU"},
        {"asset_id": "HMI-PROD-02", "name": "WinCC Panel"}
    ]
    gen = ExpertTemplateGenerator("LAT-OT-2026-001", sample_assets, "CVE-2026-9999")
    gen.generate_csv("data/examples/expert_template.csv")
