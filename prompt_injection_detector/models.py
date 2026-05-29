"""
Data models for the prompt injection detector.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AttackType(str, Enum):
    ROLE_OVERRIDE = "role_override"          # "Ignore previous instructions..."
    JAILBREAK = "jailbreak"                  # DAN, AIM, etc.
    SYSTEM_PROMPT_LEAK = "system_prompt_leak" # Attempts to extract system prompt
    INSTRUCTION_SMUGGLING = "instruction_smuggling"  # Hidden instructions in data
    INDIRECT_INJECTION = "indirect_injection"   # Via retrieved content / RAG
    DELIMITER_INJECTION = "delimiter_injection" # Exploiting token delimiters
    GOAL_HIJACKING = "goal_hijacking"           # Redirect the model's goal
    CONTEXT_OVERFLOW = "context_overflow"       # Flood context to displace instructions
    SOCIAL_ENGINEERING = "social_engineering"   # Manipulate model via personas


@dataclass
class Match:
    """A single pattern match found in the input."""
    rule_id: str
    rule_name: str
    attack_type: AttackType
    severity: Severity
    matched_text: str
    start: int
    end: int
    confidence: float  # 0.0 - 1.0
    explanation: str


@dataclass
class DetectionResult:
    """Full result of a prompt injection detection scan."""
    input_text: str
    is_injection: bool
    overall_severity: Optional[Severity]
    overall_confidence: float  # 0.0 - 1.0
    matches: List[Match] = field(default_factory=list)
    attack_types: List[AttackType] = field(default_factory=list)
    scan_time_ms: float = 0.0
    metadata: dict = field(default_factory=dict)

    def __repr__(self) -> str:
        status = f"INJECTION DETECTED ({self.overall_severity})" if self.is_injection else "CLEAN"
        return (
            f"DetectionResult({status}, confidence={self.overall_confidence:.2f}, "
            f"matches={len(self.matches)})"
        )

    def summary(self) -> str:
        """Human-readable summary of the detection result."""
        if not self.is_injection:
            return "No injection detected."
        severity_str = self.overall_severity.upper() if self.overall_severity else "UNKNOWN"
        lines = [
            f"Injection detected! Severity: {severity_str}",
            f"   Confidence: {self.overall_confidence:.0%}",
            f"   Attack types: {', '.join(t.value for t in self.attack_types)}",
            f"   Matches found: {len(self.matches)}",
        ]
        for m in self.matches:
            snippet = m.matched_text[:60] + "..." if len(m.matched_text) > 60 else m.matched_text
            lines.append(f"   • [{m.severity.upper()}] {m.rule_name}: \"{snippet}\"")
        return "\n".join(lines)
