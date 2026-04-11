import os
import json
import logging
from datetime import datetime
from src.parser.csaf_parser import CSAFParser
from src.utils.asset_loader import AssetLoader
from src.triage.multi_agent_engine import MultiAgentTriage
from src.triage.vex_generator import VEXGenerator
from src.llm.local_llm import LocalLLM

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class BatchProcessor:
    def __init__(self, raw_dir="data/raw", inventory_dir="data/inventories", output_dir="reports/batch"):
        # Absolute paths for safety
        self.base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.raw_dir = os.path.join(self.base_dir, raw_dir)
        self.inventory_dir = os.path.join(self.base_dir, inventory_dir)
        self.output_dir = os.path.join(self.base_dir, output_dir)
        os.makedirs(self.output_dir, exist_ok=True)
        self.summary = []

    def run_all(self, use_llm=False):
        """Robust batch runner."""
        advisories = [os.path.join(r, f) for r, d, files in os.walk(self.raw_dir) for f in files if f.endswith(".json")]
        inventories = [os.path.join(r, f) for r, d, files in os.walk(self.inventory_dir) for f in files if f.endswith(".csv")]

        if not advisories or not inventories:
            logger.error("Missing input data (advisories or inventories).")
            return

        logger.info(f"Batch Start: {len(advisories)} advisories, {len(inventories)} inventories.")

        for adv in advisories:
            for inv in inventories:
                self._process_pair(adv, inv, use_llm)

        self._save_summary()

    def _process_pair(self, adv_path, inv_path, use_llm):
        pair_id = f"{os.path.basename(adv_path)}_vs_{os.path.basename(inv_path)}"
        logger.info(f"Processing {pair_id}")

        try:
            with open(adv_path, 'r', encoding='utf-8-sig') as f:
                adv_json = json.load(f)
            
            assets = AssetLoader.load_from_csv(inv_path)
            if not assets: return

            parser = CSAFParser(adv_json)
            vulns = parser.extract_vulnerabilities()
            if not vulns: return

            engine = MultiAgentTriage(vulns, assets)
            prompt = engine.generate_multi_agent_prompt()

            if "TRIAGE CASE:" not in prompt:
                self.summary.append({"pair": pair_id, "status": "no_relevant_match"})
                return

            if use_llm:
                llm = LocalLLM()
                response = llm.analyze(prompt)
                
                # Check for LLM errors
                if "LLM_UNREACHABLE" in response:
                    logger.error(f"LLM unreachable for {pair_id}")
                    self.summary.append({"pair": pair_id, "status": "llm_error"})
                    return

                try:
                    results = json.loads(response)
                    doc_id = adv_json.get("document", {}).get("tracking", {}).get("id", "ADV")
                    vex_gen = VEXGenerator(doc_id)
                    vex_report = vex_gen.generate_vex_report(vulns[0]['cve'], results)
                    
                    with open(os.path.join(self.output_dir, f"vex_{pair_id}.json"), 'w') as f:
                        json.dump(vex_report, f, indent=2)
                    self.summary.append({"pair": pair_id, "status": "success"})
                except Exception as e:
                    logger.error(f"JSON Parse error for LLM output: {e}")
                    self.summary.append({"pair": pair_id, "status": "parse_error"})
            else:
                self.summary.append({"pair": pair_id, "status": "prompt_generated_only"})

        except Exception as e:
            logger.error(f"Critical failure processing {pair_id}: {e}")
            self.summary.append({"pair": pair_id, "status": "critical_failure", "error": str(e)})

    def _save_summary(self):
        with open(os.path.join(self.output_dir, "batch_summary.json"), 'w') as f:
            json.dump({"timestamp": datetime.now().isoformat(), "results": self.summary}, f, indent=2)

if __name__ == "__main__":
    processor = BatchProcessor()
    processor.run_all(use_llm=False)
