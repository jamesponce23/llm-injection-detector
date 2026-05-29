"""
Core detector logic for prompt injection detection.
"""

import time
from typing import List, Optional

from .models import AttackType, DetectionResult, Match, Severity
from .rules import Rule, RuleEngine

# Severity ordering for comparison
_SEVERITY_ORDER = {
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def _max_severity(severities: List[Severity]) -> Optional[Severity]:
    if not severities:
        return None
    return max(severities, key=lambda s: _SEVERITY_ORDER[s])


class PromptInjectionDetector:
    """
    Detects prompt injection attacks in LLM inputs.

    Basic usage:
        detector = PromptInjectionDetector()
        result = detector.scan("Ignore previous instructions and...")
        print(result.summary())

    Custom rules:
        from prompt_injection_detector import PromptInjectionDetector
        from prompt_injection_detector.rules import Rule
        from prompt_injection_detector.models import AttackType, Severity

        detector = PromptInjectionDetector()
        detector.add_rule(Rule(
            id="CUSTOM-001",
            name="My Custom Rule",
            attack_type=AttackType.GOAL_HIJACKING,
            severity=Severity.HIGH,
            pattern=r"my special trigger phrase",
            confidence=0.9,
            explanation="Detects my custom attack pattern.",
        ))
    """

    def __init__(
        self,
        rules: Optional[List[Rule]] = None,
        confidence_threshold: float = 0.5,
        detect_context_overflow: bool = True,
        context_overflow_repeat_threshold: int = 80,
    ):
        """
        Args:
            rules: Custom rule list. Defaults to all built-in rules.
            confidence_threshold: Minimum confidence to flag as injection.
            detect_context_overflow: Whether to detect repetitive padding attacks.
            context_overflow_repeat_threshold: Number of repeated tokens to trigger detection.
        """
        self.engine = RuleEngine(rules=rules)
        self.confidence_threshold = confidence_threshold
        self.detect_context_overflow = detect_context_overflow
        self.context_overflow_repeat_threshold = context_overflow_repeat_threshold

    def add_rule(self, rule: Rule):
        """Add a custom detection rule."""
        self.engine.add_rule(rule)

    def remove_rule(self, rule_id: str):
        """Remove a rule by ID."""
        self.engine.remove_rule(rule_id)

    def scan(self, text: str, metadata: Optional[dict] = None) -> DetectionResult:
        """
        Scan a text string for prompt injection attacks.

        Args:
            text: The user input or prompt to scan.
            metadata: Optional metadata to attach to the result.

        Returns:
            DetectionResult with full details of any detected injections.
        """
        start_time = time.perf_counter()

        all_matches: List[Match] = []

        # 1. Rule-based scanning
        all_matches.extend(self.engine.scan(text))

        # 2. Context overflow heuristic
        if self.detect_context_overflow:
            overflow_matches = self._detect_context_overflow(text)
            all_matches.extend(overflow_matches)

        # 3. Filter by confidence threshold
        filtered = [m for m in all_matches if m.confidence >= self.confidence_threshold]

        # 4. Compute overall result
        is_injection = len(filtered) > 0
        overall_severity = _max_severity([m.severity for m in filtered]) if filtered else None
        overall_confidence = max((m.confidence for m in filtered), default=0.0)
        attack_types = list(dict.fromkeys(m.attack_type for m in filtered))

        scan_time_ms = (time.perf_counter() - start_time) * 1000

        return DetectionResult(
            input_text=text,
            is_injection=is_injection,
            overall_severity=overall_severity,
            overall_confidence=overall_confidence,
            matches=filtered,
            attack_types=attack_types,
            scan_time_ms=round(scan_time_ms, 3),
            metadata=metadata or {},
        )

    def scan_batch(self, texts: List[str]) -> List[DetectionResult]:
        """Scan multiple texts at once."""
        return [self.scan(t) for t in texts]

    def is_injection(self, text: str) -> bool:
        """Quick boolean check — is this text a prompt injection attempt?"""
        return self.scan(text).is_injection

    def _detect_context_overflow(self, text: str) -> List[Match]:
        """Detect repetitive padding that may indicate a context overflow attack."""
        words = text.lower().split()
        if len(words) < self.context_overflow_repeat_threshold:
            return []

        # Count word frequency (case-insensitive)
        freq: dict = {}
        for w in words:
            freq[w] = freq.get(w, 0) + 1

        # Check if any single word appears excessively AND makes up a large chunk
        most_common_word, most_common_count = max(freq.items(), key=lambda x: x[1])
        ratio = most_common_count / len(words)
        # Require both: absolute count threshold AND high ratio (>30%) to avoid false positives
        if most_common_count >= self.context_overflow_repeat_threshold and ratio > 0.30:
            confidence = min(0.5 + ratio, 0.9)
            return [Match(
                rule_id="CO-001",
                rule_name="Repetitive Padding Attack",
                attack_type=AttackType.CONTEXT_OVERFLOW,
                severity=Severity.MEDIUM,
                matched_text=f'"{most_common_word}" repeated {most_common_count} times',
                start=0,
                end=len(text),
                confidence=confidence,
                explanation=f"Word '{most_common_word}' appears {most_common_count}x ({ratio:.0%} of input). "
                            "Possible context overflow attack.",
            )]
        return []
