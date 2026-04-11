import csv
import json
import os
import logging
from typing import List, Dict

logger = logging.getLogger(__name__)

class AssetLoader:
    @staticmethod
    def load_from_csv(file_path: str) -> List[Dict]:
        """Loads assets from a CSV file with robust encoding and null handling."""
        assets = []
        if not os.path.exists(file_path):
            logger.error(f"Asset file not found: {file_path}")
            return []
        
        try:
            with open(file_path, mode='r', encoding='utf-8-sig') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    # Fix: Handle None types in CSV fields (empty columns)
                    clean_row = {
                        str(k).strip(): (str(v).strip() if v is not None else "") 
                        for k, v in row.items() if k is not None
                    }
                    if 'internet_exposed' in clean_row:
                        clean_row['internet_exposed'] = clean_row['internet_exposed'].lower() == 'true'
                    assets.append(clean_row)
            return assets
        except Exception as e:
            logger.error(f"Critical error loading CSV {file_path}: {e}")
            return []

    @staticmethod
    def load_from_json(file_path: str) -> List[Dict]:
        if not os.path.exists(file_path): return []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error loading JSON {file_path}: {e}")
            return []
