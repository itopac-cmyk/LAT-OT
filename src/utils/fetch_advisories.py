import requests
import os
import logging
import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def fetch_siemens_samples(limit=5):
    """Fetches sample CSAF files from Siemens ProductCERT."""
    # Siemens CSAF index
    index_url = "https://cert-portal.siemens.com/productcert/csaf/index.txt"
    base_url = "https://cert-portal.siemens.com/productcert/csaf/"
    
    try:
        logger.info("Fetching Siemens CSAF index...")
        response = requests.get(index_url)
        response.raise_for_status()
        
        # Get individual file names from index
        files = response.text.splitlines()[:limit]
        
        for filename in files:
            if not filename.endswith('.json'): continue
            
            logger.info(f"Downloading Siemens advisory: {filename}")
            file_url = f"{base_url}{filename}"
            res = requests.get(file_url)
            
            with open(f"data/raw/siemens/{filename}", 'wb') as f:
                f.write(res.content)
                
    except Exception as e:
        logger.error(f"Error fetching Siemens advisories: {e}")

def fetch_cisa_ics_samples(limit=5):
    """Fetches sample ICS advisories from CISA (via GitHub or API)."""
    # Using a common repository or direct URLs for demonstration
    # CISA often mirrors these in their CSAF aggregator.
    # For now, we'll use a direct link to a few known ICS advisories.
    sample_urls = [
        "https://raw.githubusercontent.com/cisagov/CSAF/main/advisories/cisa/icsa-24-046-01.json",
        "https://raw.githubusercontent.com/cisagov/CSAF/main/advisories/cisa/icsa-24-051-01.json"
    ]
    
    for url in sample_urls:
        filename = url.split('/')[-1]
        logger.info(f"Downloading CISA ICS advisory: {filename}")
        try:
            res = requests.get(url)
            with open(f"data/raw/cisa/{filename}", 'wb') as f:
                f.write(res.content)
        except Exception as e:
            logger.error(f"Error downloading {url}: {e}")

if __name__ == "__main__":
    fetch_siemens_samples(limit=3)
    fetch_cisa_ics_samples()
