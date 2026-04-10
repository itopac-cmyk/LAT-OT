import json
import logging
from typing import List, Dict
import math

# Using simple sklearn-like metrics for Kappa calculation
def cohens_kappa(y1: List[str], y2: List[str], categories: List[str]) -> float:
    """Calculates Cohen's Kappa for two raters with specified categories."""
    if len(y1) != len(y2): return 0.0
    
    n = len(y1)
    if n == 0: return 0.0
    
    # Observer agreement
    po = sum(1 for a, b in zip(y1, y2) if a == b) / n
    
    # Expected agreement by chance
    pe = 0.0
    for cat in categories:
        p1 = sum(1 for x in y1 if x == cat) / n
        p2 = sum(1 for x in y2 if x == cat) / n
        pe += (p1 * p2)
        
    if pe == 1: return 1.0 # Perfect agreement by chance?
    return (po - pe) / (1 - pe)

class TriageEvaluator:
    def __init__(self, llm_results: List[Dict], expert_results: List[Dict]):
        self.llm = llm_results
        self.expert = expert_results
        self.categories = ["PATCH", "MITIGATE", "ACCEPT"]

    def run_evaluation(self) -> Dict:
        """Runs the comparison between LLM and Expert Panel."""
        # Align data by asset_id
        y_llm = []
        y_expert = []
        
        matches = 0
        total_time_llm = 0
        total_time_expert = 0 # In a real test, we'd have this data
        
        for e in self.expert:
            asset_id = e['asset_id']
            # Find corresponding LLM result
            l = next((x for x in self.llm if x['asset_id'] == asset_id), None)
            
            if l:
                y_llm.append(l['recommendation'])
                y_expert.append(e['recommendation'])
                if l['recommendation'] == e['recommendation']:
                    matches += 1

        kappa = cohens_kappa(y_llm, y_expert, self.categories)
        accuracy = matches / len(y_expert) if y_expert else 0
        
        # Calculate Precision/Recall for 'PATCH' (the most critical)
        tp = sum(1 for a, b in zip(y_llm, y_expert) if a == 'PATCH' and b == 'PATCH')
        fp = sum(1 for a, b in zip(y_llm, y_expert) if a == 'PATCH' and b != 'PATCH')
        fn = sum(1 for a, b in zip(y_llm, y_expert) if a != 'PATCH' and b == 'PATCH')
        
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0

        return {
            "cohens_kappa": round(kappa, 3),
            "accuracy": round(accuracy, 3),
            "precision_patch": round(precision, 3),
            "recall_patch": round(recall, 3),
            "total_cases": len(y_expert),
            "status": "Target reached (Kappa >= 0.6)" if kappa >= 0.6 else "Needs improvement"
        }

if __name__ == "__main__":
    # Test Data: Hypothetical Expert Panel vs LLM
    expert = [
        {"asset_id": "PLC-1", "recommendation": "PATCH"},
        {"asset_id": "PLC-2", "recommendation": "MITIGATE"},
        {"asset_id": "PLC-3", "recommendation": "ACCEPT"},
        {"asset_id": "PLC-4", "recommendation": "PATCH"}
    ]
    
    llm = [
        {"asset_id": "PLC-1", "recommendation": "PATCH"},      # Correct
        {"asset_id": "PLC-2", "recommendation": "PATCH"},      # Over-scoring (FP)
        {"asset_id": "PLC-3", "recommendation": "ACCEPT"},     # Correct
        {"asset_id": "PLC-4", "recommendation": "PATCH"}       # Correct
    ]
    
    evaluator = TriageEvaluator(llm, expert)
    results = evaluator.run_evaluation()
    print("-" * 20 + " EVALUATION METRICS " + "-" * 20)
    print(json.dumps(results, indent=2))
