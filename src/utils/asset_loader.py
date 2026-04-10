import csv
import json
import os
from typing import List, Dict

class AssetLoader:
    @staticmethod
    def load_from_csv(file_path: str) -> List[Dict]:
        """Loads assets from a CSV file."""
        assets = []
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Asset file not found: {file_path}")
        
        with open(file_path, mode='r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Convert string boolean to actual boolean
                row['is_exposed_to_internet'] = row.get('is_exposed_to_internet', 'false').lower() == 'true'
                assets.append(row)
        return assets

    @staticmethod
    def load_from_json(file_path: str) -> List[Dict]:
        """Loads assets from a JSON file."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Asset file not found: {file_path}")
            
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)

if __name__ == "__main__":
    # Quick test
    loader = AssetLoader()
    csv_assets = loader.load_from_csv("data/examples/assets.csv")
    print(f"Loaded {len(csv_assets)} assets from CSV:")
    print(json.dumps(csv_assets[0], indent=2))
