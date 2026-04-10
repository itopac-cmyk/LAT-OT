import argparse
import json
import os
import logging
from src.parser.csaf_parser import CSAFParser
from src.utils.asset_loader import AssetLoader
from src.triage.triage_engine import TriageEngine
from src.triage.vex_generator import VEXGenerator
from src.llm.local_llm import LocalLLM

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

def main():
    parser = argparse.ArgumentParser(description="LAT-OT Triage Orchestrator (SSVC Powered)")
    parser.add_argument("--advisory", required=True, help="Path to the CSAF/VEX JSON advisory")
    parser.add_argument("--inventory", required=True, help="Path to the Asset Inventory CSV")
    parser.add_argument("--local-llm", action="store_true", help="Run local analysis via Ollama (Qwen3)")
    parser.add_argument("--output-prompt", help="Save the generated prompt to a file")
    parser.add_argument("--output-vex", help="Path to save the final VEX report (JSON)")
    
    args = parser.parse_args()

    # 1. Load Data
    logger.info(f"Loading advisory: {args.advisory}")
    if not os.path.exists(args.advisory):
        logger.error(f"Advisory file not found: {args.advisory}")
        return

    with open(args.advisory, 'r') as f:
        advisory_json = json.load(f)
        doc_id = advisory_json.get("document", {}).get("tracking", {}).get("id", "UNKNOWN-ADVISORY")

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

    # 4. Handle Output
    if args.output_prompt:
        with open(args.output_prompt, 'w') as f:
            f.write(ssvc_prompt)
        logger.info(f"SSVC Prompt saved to: {args.output_prompt}")

    # 5. Local LLM Analysis (The "Reasoning" Step)
    if args.local_llm:
        local_llm = LocalLLM()
        response_text = local_llm.analyze(ssvc_prompt)
        
        try:
            analysis_results = json.loads(response_text)
            logger.info("Local LLM analysis completed successfully.")
            
            # Generate VEX Report
            vex_gen = VEXGenerator(doc_id)
            # Assuming one CVE for simplicity in this example
            cve_id = vulnerabilities[0].get("cve", "UNKNOWN-CVE")
            vex_report = vex_gen.generate_vex_report(cve_id, analysis_results)
            
            if args.output_vex:
                with open(args.output_vex, 'w') as f:
                    json.dump(vex_report, f, indent=2)
                logger.info(f"VEX Report saved to: {args.output_vex}")
            else:
                print("\n" + "="*20 + " FINAL VEX REPORT " + "="*20)
                print(json.dumps(vex_report, indent=2))

        except json.JSONDecodeError:
            logger.error("Failed to parse LLM response as JSON. Check prompt or LLM status.")
            print("\n" + "="*20 + " RAW LLM RESPONSE " + "="*20)
            print(response_text)
    else:
        # Just show the prompt if no LLM was requested
        if not args.output_prompt:
            print("\n" + "="*20 + " GENERATED SSVC PROMPT " + "="*20)
            print(ssvc_prompt)
            logger.info("Ready for LLM processing. Use --local-llm to trigger local analysis.")

if __name__ == "__main__":
    main()
EOF
