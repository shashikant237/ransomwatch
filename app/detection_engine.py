"""Rule-based detection engine for RansomWatch.
Evaluates behavioral features against configurable heuristic thresholds.
Computes an explainable rule threat score and identifies key contributors.
"""

from typing import List, Dict, Any, Tuple
from app.schemas import BehavioralFeatures, RuleEvaluationResult, ContributorIndicator
from app.rules_config import DEFAULT_RULES, DEFAULT_WEIGHT_CONFIG
from app.feature_extractor import FEATURE_METADATA


class DetectionEngine:
    def __init__(self, rules: List[Dict[str, Any]] = None, weight_config: Dict[str, Any] = None):
        self.rules: List[Dict[str, Any]] = rules or [r.copy() for r in DEFAULT_RULES]
        self.weight_config: Dict[str, Any] = weight_config or DEFAULT_WEIGHT_CONFIG.copy()

    def update_rules(self, new_rules: List[Dict[str, Any]], rule_weight_ratio: float = None, ml_weight_ratio: float = None):
        """Safely updates rule thresholds and weights."""
        rule_map = {r["rule_id"]: r for r in new_rules}
        for current_rule in self.rules:
            rid = current_rule["rule_id"]
            if rid in rule_map:
                current_rule["threshold"] = max(0.0, float(rule_map[rid].get("threshold", current_rule["threshold"])))
                current_rule["weight"] = max(0.0, float(rule_map[rid].get("weight", current_rule["weight"])))
                current_rule["enabled"] = bool(rule_map[rid].get("enabled", current_rule["enabled"]))

        if rule_weight_ratio is not None and ml_weight_ratio is not None:
            total = rule_weight_ratio + ml_weight_ratio
            if total > 0:
                self.weight_config["rule_weight_ratio"] = round(rule_weight_ratio / total, 3)
                self.weight_config["ml_weight_ratio"] = round(ml_weight_ratio / total, 3)

        self.weight_config["max_possible_rule_sum"] = sum(
            r["weight"] for r in self.rules if r.get("enabled", True)
        )

    def evaluate(self, features: BehavioralFeatures) -> Tuple[float, List[RuleEvaluationResult], List[ContributorIndicator]]:
        """Evaluates behavioral features against active rules.
        Returns:
            - normalized_rule_score (0.0 to 100.0)
            - list of RuleEvaluationResult
            - list of ContributorIndicator (sorted descending by threat impact)
        """
        features_dict = features.model_dump()
        rule_results: List[RuleEvaluationResult] = []
        contributors: List[ContributorIndicator] = []

        total_triggered_weight = 0.0
        max_possible_weight = sum(r["weight"] for r in self.rules if r.get("enabled", True))
        if max_possible_weight <= 0:
            max_possible_weight = 100.0

        for rule in self.rules:
            if not rule.get("enabled", True):
                continue

            feature_key = rule["feature_key"]
            actual_val = float(features_dict.get(feature_key, 0.0))
            threshold = float(rule["threshold"])
            weight = float(rule["weight"])

            triggered = actual_val >= threshold
            contribution = weight if triggered else 0.0

            if triggered:
                total_triggered_weight += contribution

            eval_res = RuleEvaluationResult(
                rule_id=rule["rule_id"],
                rule_name=rule["name"],
                triggered=triggered,
                threshold=threshold,
                actual_value=actual_val,
                weight=weight,
                score_contribution=round(contribution, 2),
                description=rule["description"]
            )
            rule_results.append(eval_res)

            # Analyze feature contribution for explainability
            meta = FEATURE_METADATA.get(feature_key, {})
            display_name = meta.get("display_name", feature_key.replace("_", " ").title())
            baseline = meta.get("benign_baseline", 0.0)

            # Measure severity ratio against threshold and baseline
            if triggered:
                margin = (actual_val - threshold) / max(threshold, 0.1)
                if margin >= 2.0 or actual_val >= (threshold * 3.0):
                    severity = "CRITICAL"
                elif margin >= 0.5:
                    severity = "HIGH"
                else:
                    severity = "MEDIUM"
                contributors.append(ContributorIndicator(
                    feature_name=feature_key,
                    display_name=display_name,
                    value=round(actual_val, 2),
                    threshold=threshold,
                    contribution=round(contribution, 2),
                    severity=severity
                ))
            elif actual_val > baseline * 1.5:
                # Approaching threshold
                contributors.append(ContributorIndicator(
                    feature_name=feature_key,
                    display_name=display_name,
                    value=round(actual_val, 2),
                    threshold=threshold,
                    contribution=0.0,
                    severity="LOW"
                ))

        # Normalize score into 0-100 scale
        normalized_rule_score = round(min(100.0, (total_triggered_weight / max_possible_weight) * 100.0), 2)

        # Sort top contributors: highest contribution first, then by value
        contributors.sort(key=lambda c: (c.contribution, c.value), reverse=True)

        return normalized_rule_score, rule_results, contributors
