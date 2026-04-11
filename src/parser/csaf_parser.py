import json
import logging
from typing import Dict, List, Optional

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CSAFParser:
    def __init__(self, json_data: Dict):
        self.data = json_data or {}
        self.product_map = self._build_product_map()

    def _build_product_map(self) -> Dict[str, str]:
        """Robust mapping of ProductID to CPE with safety checks."""
        mapping = {}
        try:
            full_names = self.data.get('product_tree', {}).get('full_product_names', [])
            if not isinstance(full_names, list): return {}
            
            for product in full_names:
                pid = product.get('product_id')
                helper = product.get('product_identification_helper', {})
                cpe = helper.get('cpe') if isinstance(helper, dict) else None
                if pid and cpe:
                    mapping[pid] = cpe
        except Exception as e:
            logger.error(f"Error building product map: {e}")
        return mapping

    def extract_vulnerabilities(self) -> List[Dict]:
        """Extracts critical data with deep safety checks for missing nested fields."""
        vulnerabilities = []
        vuln_list = self.data.get('vulnerabilities', [])
        if not isinstance(vuln_list, list): return []

        for vuln in vuln_list:
            if not isinstance(vuln, dict): continue
            
            extracted = {
                "cve": vuln.get('cve', 'UNKNOWN-CVE'),
                "title": vuln.get('title', 'No Title'),
                "description": self._get_vuln_note(vuln, 'description'),
                "cvss_v3": self._get_cvss_v3(vuln),
                "affected_products": [],
                "remediations": []
            }

            # Product Status (handle multiple possible keys)
            status = vuln.get('product_status', {})
            if isinstance(status, dict):
                for status_type in ['known_affected', 'first_affected', 'last_affected']:
                    pids = status.get(status_type, [])
                    if isinstance(pids, list):
                        for pid in pids:
                            if pid in self.product_map:
                                extracted["affected_products"].append(self.product_map[pid])

            # Remediations
            rems = vuln.get('remediations', [])
            if isinstance(rems, list):
                for rem in rems:
                    if isinstance(rem, dict):
                        extracted["remediations"].append({
                            "category": rem.get('category', 'vendor_fix'),
                            "details": rem.get('details', 'No details provided'),
                            "url": rem.get('url')
                        })

            vulnerabilities.append(extracted)
        return vulnerabilities

    def _get_cvss_v3(self, vuln: Dict) -> Optional[Dict]:
        scores = vuln.get('scores', [])
        if not isinstance(scores, list): return None
        for score in scores:
            if not isinstance(score, dict): continue
            cvss_v3 = score.get('cvss_v3')
            if cvss_v3 and isinstance(cvss_v3, dict):
                return {
                    "baseScore": cvss_v3.get('baseScore'),
                    "baseSeverity": cvss_v3.get('baseSeverity'),
                    "vectorString": cvss_v3.get('vectorString')
                }
        return None

    def _get_vuln_note(self, vuln: Dict, category: str) -> str:
        notes = vuln.get('notes', [])
        if not isinstance(notes, list): return ""
        for note in notes:
            if isinstance(note, dict) and note.get('category') == category:
                return note.get('text', "")
        return ""
