"""Detection aggregation module for combining evidence from multiple analyzers.

This module provides intelligent confidence boosting when the same technology
is detected by multiple analyzers. It merges duplicate detections and increases
confidence based on the number and quality of evidence sources.
"""
from typing import List, Dict, Set, Tuple
from models.detection import Detection
import logging

logger = logging.getLogger(__name__)


class DetectionAggregator:
    """Aggregates and enhances detections from multiple analyzers."""

    # Confidence multipliers based on number of independent sources
    CONFIDENCE_MULTIPLIERS = {
        1: 1.0,      # Single source: no boost
        2: 1.15,     # Two sources: 15% boost
        3: 1.25,     # Three sources: 25% boost
        4: 1.35,     # Four sources: 35% boost
        5: 1.50,     # Five sources: 50% boost
    }

    # Evidence type weights for confidence calculation
    EVIDENCE_WEIGHTS = {
        "header": 0.9,
        "html_pattern": 0.8,
        "cookie": 0.85,
        "certificate_issuer": 0.95,
        "certificate_cn": 0.95,
        "api_response": 0.9,
        "error_message": 0.85,
        "script_src": 0.75,
        "css_link": 0.7,
        "favicon_hash": 0.95,
        "sri_hash": 0.95,
        "dns_record": 0.8,
        "admin_page": 0.9,
        "api_endpoint": 0.85,
        "graphql_introspection": 0.95,
    }

    @staticmethod
    def aggregate(detections: List[Detection]) -> List[Detection]:
        """
        Aggregate detections from multiple analyzers.
        
        Merges duplicate detections (same technology) and boosts confidence
        based on number of independent evidence sources.
        
        Args:
            detections: List of detections from all analyzers
            
        Returns:
            List of aggregated detections with boosted confidence
        """
        if not detections:
            return []

        # Group detections by technology name
        grouped: Dict[str, List[Detection]] = {}
        for detection in detections:
            key = f"{detection.name}|{detection.category}"
            if key not in grouped:
                grouped[key] = []
            grouped[key].append(detection)

        # Aggregate each group
        aggregated = []
        for tech_key, tech_detections in grouped.items():
            aggregated_detection = DetectionAggregator._merge_detections(tech_detections)
            aggregated.append(aggregated_detection)

        # Sort by confidence (highest first)
        aggregated.sort(key=lambda d: d.confidence, reverse=True)

        return aggregated

    @staticmethod
    def _merge_detections(detections: List[Detection]) -> Detection:
        """
        Merge multiple detections of the same technology.
        
        Takes the detection with highest confidence and boosts it based on
        the number of independent evidence sources.
        """
        if not detections:
            return detections[0]

        if len(detections) == 1:
            return detections[0]

        # Use the detection with the highest base confidence
        primary = max(detections, key=lambda d: d.confidence)

        # Count unique evidence types
        unique_evidence_types = set(d.evidence.type for d in detections)
        evidence_count = len(unique_evidence_types)

        # Calculate confidence boost
        multiplier = DetectionAggregator.CONFIDENCE_MULTIPLIERS.get(
            min(evidence_count, 5),  # Cap at 5 sources
            1.5
        )

        # Boost confidence
        boosted_confidence = min(primary.confidence * multiplier, 1.0)

        logger.debug(
            f"Aggregated {primary.name}: "
            f"{primary.confidence:.2f} → {boosted_confidence:.2f} "
            f"({evidence_count} evidence types)"
        )

        # Create new detection with boosted confidence
        aggregated = Detection(
            name=primary.name,
            category=primary.category,
            confidence=boosted_confidence,
            evidence=primary.evidence,
            version=primary.version,
        )

        return aggregated

    @staticmethod
    def get_confidence_boost(evidence_types: Set[str]) -> float:
        """
        Get confidence boost factor for given evidence types.
        
        Args:
            evidence_types: Set of evidence type strings
            
        Returns:
            Boost multiplier (e.g., 1.25 for 25% boost)
        """
        count = len(evidence_types)
        return DetectionAggregator.CONFIDENCE_MULTIPLIERS.get(
            min(count, 5),
            1.5
        )

    @staticmethod
    def calculate_weighted_confidence(detections: List[Detection]) -> float:
        """
        Calculate weighted average confidence for same technology.
        
        Uses evidence type weights for better accuracy.
        
        Args:
            detections: List of detections for same technology
            
        Returns:
            Weighted average confidence score
        """
        if not detections:
            return 0.0

        total_weight = 0.0
        weighted_sum = 0.0

        for detection in detections:
            # Get weight for this evidence type
            weight = DetectionAggregator.EVIDENCE_WEIGHTS.get(
                detection.evidence.type,
                0.7  # Default weight for unknown types
            )

            weighted_sum += detection.confidence * weight
            total_weight += weight

        if total_weight == 0:
            return 0.0

        return min(weighted_sum / total_weight, 1.0)
