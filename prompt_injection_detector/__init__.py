"""
prompt-injection-detector
A lightweight, extensible library for detecting LLM prompt injection attacks.
"""

from .detector import PromptInjectionDetector
from .models import DetectionResult, Match, Severity, AttackType
from .rules import RuleEngine

__version__ = "0.1.0"
__all__ = ["PromptInjectionDetector", "DetectionResult", "Match", "Severity", "AttackType", "RuleEngine"]
