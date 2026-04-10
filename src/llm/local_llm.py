import requests
import json
import logging

logger = logging.getLogger(__name__)

class LocalLLM:
    def __init__(self, model="qwen3:14b", base_url="http://localhost:11434"):
        self.model = model
        self.base_url = f"{base_url}/api/generate"

    def analyze(self, prompt: str) -> str:
        """Sends a prompt to the local Ollama instance and returns the response."""
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "format": "json"  # Ensure Ollama knows we expect structured JSON
        }

        try:
            logger.info(f"Sending prompt to local LLM ({self.model})...")
            response = requests.post(self.base_url, json=payload, timeout=120)
            response.raise_for_status()
            
            result = response.json()
            return result.get("response", "")
        except requests.exceptions.RequestException as e:
            logger.error(f"Error communicating with Ollama: {e}")
            return json.dumps({
                "error": "Local LLM unreachable. Ensure Ollama is running.",
                "details": str(e)
            })

if __name__ == "__main__":
    # Quick connectivity test
    llm = LocalLLM()
    print("Testing local LLM connection...")
    # This will likely fail if Ollama is not running, but serves as a placeholder
    test_res = llm.analyze("Return a JSON object with 'status': 'ready'")
    print(test_res)
