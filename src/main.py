import argparse
import json
import os
import logging
from src.parser.csaf_parser import CSAFParser
from src.utils.asset_loader import AssetLoader
from src.triage.triage_engine import TriageEngine
from src.triage.vex_generator import VEXGenerator

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

def main():
    parser = argparse.ArgumentParser(description="LAT-OT Triage Orchestrator")
    parser.add_argument("--advisory", required=True, help="Path to the CSAF/VEX JSON advisory")
    parser.add_argument("--inventory", required=True, help="Path to the Asset Inventory CSV")
    parser.add_argument("--output-prompt", help="Save the generated prompt to a file")
    parser.add_argument("--output-vex", help="Path to save the final VEX report (after LLM processing)")
    
    args = parser.parse_args()

    # 1. Load Data
    logger.info(f"Loading advisory: {args.advisory}")
    if not os.path.exists(args.advisory):
        logger.error(f"Advisory file not found: {args.advisory}")
        return

    with open(args.advisory, 'r') as f:
        advisory_json = json.load(f)

    logger.info(f"Loading inventory: {args.inventory}")
    loader = AssetLoader()
    assets = loader.load_from_csv(args.inventory)

    # 2. Parse Advisory
    csaf_parser = CSAFParser(advisory_json)
    vulnerabilities = csaf_parser.extract_vulnerabilities()
    
    if not vulnerabilities:
        logger.warning("No vulnerabilities found in advisory.")
        return

    # 3. Triage Engine (Correlate and Generate Prompt)
    triage_engine = TriageEngine(vulnerabilities, assets)
    ssvc_prompt = triage_engine.generate_ssvc_prompt()

    if not ssvc_prompt or "### ASSETS POTENTIALLY AFFECTED:" not in ssvc_prompt:
        logger.info("No matching assets found for this advisory. No triage required.")
        return

    # 4. Output results
    if args.output_prompt:
        with open(args.output_prompt, 'w') as f:
            f.write(ssvc_prompt)
        logger.info(f"SSVC Prompt saved to: {args.output_prompt}")
    else:
        print("\n" + "="*20 + " GENERATED SSVC PROMPT " + "="*20)
        print(ssvc_prompt)

    logger.info("Ready for LLM processing. Use Phase 2 scripts for Claude API integration.")

if __name__ == "__main__":
    main()
EOF
