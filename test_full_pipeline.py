import subprocess
import os
import json
import logging
import sys

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("E2E-TEST")

def test_lat_ot():
    logger.info("Starting End-to-End Test for LAT-OT...")
    
    # 1. Clean old reports
    if os.path.exists("reports/batch/batch_summary.json"):
        os.remove("reports/batch/batch_summary.json")

    # 2. Run Batch Processor (Prompt Generation only to be safe)
    logger.info("Step 1: Running Batch Processor...")
    res = subprocess.run(["python3", "src/batch_processor.py"], capture_output=True, text=True, env={**os.environ, "PYTHONPATH": "."})
    
    if res.returncode != 0:
        logger.error(f"Batch Processor failed: {res.stderr}")
        return False

    # 3. Check for summary file
    if not os.path.exists("reports/batch/batch_summary.json"):
        logger.error("Summary file not created!")
        return False

    with open("reports/batch/batch_summary.json", 'r') as f:
        summary = json.load(f)
        logger.info(f"Success! Processed {len(summary['results'])} pairs.")

    # 4. Check Web UI startability
    logger.info("Step 2: Testing Web UI (Smoke Test)...")
    # Determine the correct python interpreter (use the one from venv if active)
    python_exe = sys.executable
    try:
        import flask
        # We start it briefly and kill it
        proc = subprocess.Popen([python_exe, "src/web_ui/app.py"], env={**os.environ, "PYTHONPATH": "."})
        import time
        time.sleep(3)
        if proc.poll() is None:
            logger.info("Web UI started successfully.")
            proc.terminate()
        else:
            logger.error("Web UI failed to start.")
            return False
    except ImportError:
        logger.warning("Flask not installed in this environment. Skipping Web UI smoke test.")



    logger.info("LAT-OT E2E TEST PASSED.")
    return True

if __name__ == "__main__":
    if test_lat_ot():
        print("\n✅ LAT-OT is STABLE and READY.")
    else:
        print("\n❌ LAT-OT TEST FAILED.")
        exit(1)
