import os
import yaml
from typing import List, Dict, Any
from models.technology import Technology, EvidenceRule

def load_rules(rules_dir: str = "rules") -> List[Technology]:
    """
    Loads technology detection rules from all .yaml files in a directory.
    """
    technologies: List[Technology] = []
    for filename in os.listdir(rules_dir):
        if filename.endswith(".yaml") or filename.endswith(".yml"):
            filepath = os.path.join(rules_dir, filename)
            with open(filepath, "r") as f:
                rules_data = yaml.safe_load(f)
                if not rules_data:
                    continue
                
                for rule_data in rules_data:
                    # Basic validation
                    if not all(k in rule_data for k in ["name", "category", "evidence"]):
                        print(f"Skipping invalid rule in {filename}: {rule_data}")
                        continue

                    evidence_rules = []
                    for evidence_item in rule_data["evidence"]:
                        evidence_rules.append(
                            EvidenceRule(
                                type=evidence_item.get("type"),
                                name=evidence_item.get("name"),
                                pattern=evidence_item.get("pattern"),
                                value=evidence_item.get("value"),
                                confidence=evidence_item.get("confidence", 0.5),
                            )
                        )
                    
                    technologies.append(
                        Technology(
                            name=rule_data["name"],
                            category=rule_data["category"],
                            evidence_rules=evidence_rules,
                            version=rule_data.get("version")
                        )
                    )
    return technologies

# Example usage (for testing)
if __name__ == "__main__":
    loaded_technologies = load_rules()
    print(f"Loaded {len(loaded_technologies)} technologies.")
    for tech in loaded_technologies:
        print(f"  - {tech.name} ({tech.category})")
        for rule in tech.evidence_rules:
            print(f"    - Evidence: type={rule.type}, name={rule.name}, pattern={rule.pattern}, value={rule.value}, confidence={rule.confidence}")

