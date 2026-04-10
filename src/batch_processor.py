import os
import json
import logging
import csv
from datetime import datetime
from src.parser.csaf_parser import CSAFParser
from src.utils.asset_loader import AssetLoader
from src.triage.triage_engine import TriageEngine
from src.triage.vex_generator import VEXGenerator
from src.llm.local_llm import LocalLLM

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

class BatchProcessor:
    def __init__(self, raw_dir="data/raw", inventory_dir="data/inventories", output_dir="reports/batch"):
        self.raw_dir = raw_dir
        self.inventory_dir = inventory_dir
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self.summary = []

    def run_all(self, use_llm=False):
        """Iterates through all advisories and all inventories."""
        advisories = self._get_files(self.raw_dir, ".json")
        inventories = self._get_files(self.inventory_dir, ".csv")

        logger.info(f"Starting batch run: {len(advisories)} advisories vs {len(inventories)} inventories.")

        for adv_path in advisories:
            for inv_path in inventories:
                self._process_pair(adv_path, inv_path, use_llm)

        self._save_summary()

    def _get_files(self, directory, extension):
        file_list = []
        for root, _, files in os.walk(directory):
            for file in files:
                if file.endswith(extension):
                    file_list.append(os.path.join(root, file))
        return file_list

    def _process_pair(self, adv_path, inv_path, use_llm):
        adv_name = os.path.basename(adv_path)
        inv_name = os.path.basename(inv_path)
        pair_id = f"{adv_name}_vs_{inv_name}"
        
        logger.info(f"Processing: {pair_id}")

        try:
            # 1. Load & Parse
            with open(adv_path, 'r') as f:
                adv_json = json.load(f)
            
            loader = AssetLoader()
            assets = loader.load_from_csv(inv_path)
            
            parser = CSAFParser(adv_json)
            vulns = parser.extract_vulnerabilities()
            
            # 2. Triage Logic
            engine = TriageEngine(vulns, assets)
            prompt = engine.generate_ssvc_prompt()

            # Check if there were any matches
            if "### ASSETS POTENTIALLY AFFECTED:" not in prompt:
                self.summary.append({"pair": pair_id, "status": "no_match", "matches": 0})
                return

            # count matches
            match_count = prompt.count("Asset ID:")
            
            # 3. LLM Analysis (Optional)
            results = None
            if use_llm:
                llm = LocalLLM()
                response = llm.analyze(prompt)
                try:
                    results = json.loads(response)
                    # Generate VEX
                    doc_id = adv_json.get("document", {}).get("tracking", {}).get("id", adv_name)
                    vex_gen = VEXGenerator(doc_id)
                    vex_report = vex_gen.generate_vex_report(vulns[0]['cve'], results)
                    
                    with open(os.path.join(self.output_dir, f"vex_{pair_id}.json"), 'w') as f:
                        json.dump(vex_report, f, indent=2)
                except Exception as e:
                    logger.error(f"LLM parsing failed for {pair_id}: {e}")

            # 4. Save Prompt
            with open(os.path.join(self.output_dir, f"prompt_{pair_id}.txt"), 'w') as f:
                f.write(prompt)

            self.summary.append({
                "pair": pair_id,
                "status": "success",
                "matches": match_count,
                "llm_analyzed": use_llm and results is not None
            })

        except Exception as e:
            logger.error(f"Failed to process {pair_id}: {e}")
            self.summary.append({"pair": pair_id, "status": "error", "error": str(e)})

    def _save_summary(self):
        summary_path = os.path.join(self.output_dir, "batch_summary.json")
        with open(summary_path, 'w') as f:
            json.dump({
                "timestamp": datetime.now().isoformat(),
                "results": self.summary
            }, f, indent=2)
        logger.info(f"Batch summary saved to: {summary_path}")

if __name__ == "__main__":
    processor = BatchProcessor()
    # By default, we only generate prompts to avoid waiting for LLM in dev
    processor.run_all(use_llm=False)
