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
        """Extracts critical vulnerability data including CVSS v3 and detailed remediations."""
        vulnerabilities = []
        for vuln in self.data.get('vulnerabilities', []):
            extracted = {
                "cve": vuln.get('cve'),
                "title": vuln.get('title'),
                "description": self._get_vuln_note(vuln, 'description'),
                "cvss_v3": self._get_cvss_v3(vuln),
                "affected_products": [],
                "remediations": []
            }

            # Map affected Product IDs back to CPEs
            for status_type in ['known_affected', 'first_affected', 'last_affected']:
                for pid in vuln.get('product_status', {}).get(status_type, []):
                    if pid in self.product_map:
                        extracted["affected_products"].append(self.product_map[pid])

            # Extract detailed remediations
            for rem in vuln.get('remediations', []):
                extracted["remediations"].append({
                    "category": rem.get('category'),
                    "details": rem.get('details'),
                    "url": rem.get('url'),
                    "restart_required": rem.get('restart_required')
                })

            vulnerabilities.append(extracted)
        return vulnerabilities

    def _get_cvss_v3(self, vuln: Dict) -> Optional[Dict]:
        """Extracts CVSS v3.x score and vector string."""
        scores = vuln.get('scores', [])
        for score in scores:
            cvss_v3 = score.get('cvss_v3')
            if cvss_v3:
                return {
                    "baseScore": cvss_v3.get('baseScore'),
                    "baseSeverity": cvss_v3.get('baseSeverity'),
                    "vectorString": cvss_v3.get('vectorString')
                }
        return None

    def _get_vuln_note(self, vuln: Dict, category: str) -> str:
        """Helper to extract specific notes."""
        for note in vuln.get('notes', []):
            if note.get('category') == category:
                return note.get('text', "")
        return ""

if __name__ == "__main__":
    # Test with sample if exists
    import os
    file_path = "data/examples/sample_advisory.json"
    if os.path.exists(file_path):
        with open(file_path, 'r') as f:
            parser = CSAFParser(json.load(f))
            print(json.dumps(parser.extract_vulnerabilities(), indent=2))
