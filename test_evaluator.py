import json
from src.utils.evaluator import TriageEvaluator

expert = [
    {"asset_id": "PLC-PROD-01", "recommendation": "PATCH"},
    {"asset_id": "IED-PROT-01", "recommendation": "PATCH"},
    {"asset_id": "HMI-PROD-01", "recommendation": "MITIGATE"}
]

llm = [
    {"asset_id": "PLC-PROD-01", "recommendation": "PATCH"},      # Correct
    {"asset_id": "IED-PROT-01", "recommendation": "MITIGATE"},   # Incorrect (Expert says PATCH)
    {"asset_id": "HMI-PROD-01", "recommendation": "MITIGATE"}    # Correct
]

evaluator = TriageEvaluator(llm, expert)
print(json.dumps(evaluator.run_evaluation(), indent=2))
