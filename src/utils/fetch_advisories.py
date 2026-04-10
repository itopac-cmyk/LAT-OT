import requests
import os
import logging
import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def fetch_cisa_ics_samples(limit=10):
    """Fetches real ICS-CERT CSAF advisories from CISA's official GitHub mirroring."""
    # This is a reliable mirror of current CISA ICS-CERT advisories
    base_repo_url = "https://raw.githubusercontent.com/cisagov/CSAF/main/advisories/cisa/"
    
    # We'll use a few recent known advisory IDs for testing
    # In a production version, we would parse the CISA provider-metadata.json
    sample_ids = [
        "icsa-24-046-01", "icsa-24-051-01", "icsa-24-072-01", 
        "icsa-24-074-01", "icsa-24-074-02", "icsa-24-074-03"
    ]
    
    for adv_id in sample_ids[:limit]:
        filename = f"{adv_id}.json"
        url = f"{base_repo_url}{filename}"
        
        logger.info(f"Downloading CISA ICS advisory: {filename}")
        try:
            res = requests.get(url, timeout=10)
            res.raise_for_status()
            
            # Save to cisa folder
            dest_path = f"data/raw/cisa/{filename}"
            with open(dest_path, 'wb') as f:
                f.write(res.content)
            logger.info(f"Saved to {dest_path}")
        except Exception as e:
            logger.error(f"Error downloading {adv_id}: {e}")

if __name__ == "__main__":
    fetch_cisa_ics_samples(limit=5)
