import json
import logging
from typing import Dict, List, Optional

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CSAFParser:
    def __init__(self, json_data: Dict):
        self.data = json_data
        self.product_map = self._build_product_map()

    def _build_product_map(self) -> Dict[str, str]:
        """Maps ProductID to CPE name for easier asset correlation."""
        mapping = {}
        # CSAF stores product info in the product_tree
        try:
            for product in self.data.get('product_tree', {}).get('full_product_names', []):
                pid = product.get('product_id')
                cpe = product.get('product_identification_helper', {}).get('cpe')
                if pid and cpe:
                    mapping[pid] = cpe
        except Exception as e:
            logger.error(f"Error building product map: {e}")
        return mapping

    def extract_vulnerabilities(self) -> List[Dict]:
        """Extracts critical vulnerability data for LLM processing."""
        vulnerabilities = []
        for vuln in self.data.get('vulnerabilities', []):
            extracted = {
                "cve": vuln.get('cve'),
                "title": vuln.get('title'),
                "description": self._get_vuln_note(vuln, 'description'),
                "affected_products": [],
                "remediations": []
            }

            # Map affected Product IDs back to CPEs
            for pid in vuln.get('product_status', {}).get('known_affected', []):
                if pid in self.product_map:
                    extracted["affected_products"].append(self.product_map[pid])

            # Extract remediations
            for rem in vuln.get('remediations', []):
                extracted["remediations"].append({
                    "category": rem.get('category'),
                    "details": rem.get('details')
                })

            vulnerabilities.append(extracted)
        return vulnerabilities

    def _get_vuln_note(self, vuln: Dict, category: str) -> str:
        """Helper to extract specific notes (like description)."""
        for note in vuln.get('notes', []):
            if note.get('category') == category:
                return note.get('text', "")
        return ""

if __name__ == "__main__":
    import sys
    import os

    # Quick test run
    file_path = "data/examples/sample_advisory.json"
    if os.path.exists(file_path):
        with open(file_path, 'r') as f:
            data = json.load(f)
            parser = CSAFParser(data)
            vulns = parser.extract_vulnerabilities()
            print(json.dumps(vulns, indent=2))
