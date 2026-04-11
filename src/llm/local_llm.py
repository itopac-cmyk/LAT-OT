import requests
import json
import logging
import time

logger = logging.getLogger(__name__)

class LocalLLM:
    def __init__(self, model="qwen3:14b", base_url="http://localhost:11434"):
        self.model = model
        self.base_url = f"{base_url}/api/generate"

    def analyze(self, prompt: str, retries=2) -> str:
        """Sends a prompt to the local Ollama instance with retry logic."""
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "format": "json"
        }

        for attempt in range(retries + 1):
            try:
                logger.info(f"Sending prompt to LLM (Attempt {attempt+1}/{retries+1})...")
                response = requests.post(self.base_url, json=payload, timeout=180) # Large timeout for deep reasoning
                response.raise_for_status()
                return response.json().get("response", "")
            except Exception as e:
                logger.warning(f"LLM Connection failed: {e}")
                if attempt < retries:
                    time.sleep(2)
                else:
                    return json.dumps({"error": "LLM_UNREACHABLE", "details": str(e)})
