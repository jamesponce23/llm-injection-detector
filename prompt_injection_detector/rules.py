"""
Rule engine for prompt injection detection.
Contains built-in rules and supports custom rule registration.
"""

import re
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Pattern

from .models import AttackType, Match, Severity


@dataclass
class Rule:
    """A detection rule."""
    id: str
    name: str
    attack_type: AttackType
    severity: Severity
    pattern: Optional[str] = None          # regex pattern (case-insensitive)
    patterns: List[str] = field(default_factory=list)  # multiple patterns (OR logic)
    matcher: Optional[Callable[[str], List[tuple]]] = None  # custom matcher fn
    confidence: float = 0.8
    explanation: str = ""
    _compiled: Optional[Pattern] = field(default=None, init=False, repr=False)

    def compile(self):
        """Compile regex patterns for performance."""
        combined = self.patterns if self.patterns else ([self.pattern] if self.pattern else [])
        if combined:
            joined = "|".join(f"(?:{p})" for p in combined)
            self._compiled = re.compile(joined, re.IGNORECASE | re.DOTALL)

    def find_matches(self, text: str) -> List[tuple]:
        """Returns list of (start, end, matched_text) tuples."""
        results = []
        if self.matcher:
            results.extend(self.matcher(text))
        if self._compiled:
            for m in self._compiled.finditer(text):
                results.append((m.start(), m.end(), m.group()))
        return results


# ─── Built-in Rules ────────────────────────────────────────────────────────────

BUILTIN_RULES: List[Rule] = [

    # ── Role Override ──────────────────────────────────────────────────────────
    Rule(
        id="RI-001",
        name="Ignore Instructions",
        attack_type=AttackType.ROLE_OVERRIDE,
        severity=Severity.HIGH,
        patterns=[
            r"ignore\s+(all\s+)?(previous|prior|above|earlier|preceding)\s+(instructions?|prompts?|directives?|commands?)",
            r"disregard\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?)",
            r"forget\s+(all\s+)?(previous|prior|above|earlier|everything)\s+(instructions?|prompts?|you.ve been told)",
            r"override\s+(your\s+)?(previous|prior|all|current)\s+(instructions?|programming|directives?)",
        ],
        confidence=0.95,
        explanation="Attempt to override the model's existing instructions.",
    ),

    Rule(
        id="RI-002",
        name="New Instructions Directive",
        attack_type=AttackType.ROLE_OVERRIDE,
        severity=Severity.HIGH,
        patterns=[
            r"your\s+(new|real|actual|true|only)\s+(instructions?|task|job|goal|purpose|directive)\s+(is|are|will be)",
            r"from\s+now\s+on[,\s]+you\s+(are|will|must|should|shall)",
            r"your\s+(instructions?|system\s+prompt)\s+has\s+(been\s+)?(updated|changed|replaced|modified)",
            r"new\s+system\s+prompt[:\s]",
        ],
        confidence=0.90,
        explanation="Attempt to replace or redefine the model's instructions.",
    ),

    Rule(
        id="RI-003",
        name="Role Impersonation",
        attack_type=AttackType.ROLE_OVERRIDE,
        severity=Severity.MEDIUM,
        patterns=[
            r"you\s+are\s+now\s+(a|an|the)\s+\w+(\s+\w+)?\s+(without|with no|that (ignores?|doesn.t|does not))",
            r"pretend\s+(you\s+are|to\s+be)\s+(a|an|the)?\s*\w+\s+that\s+(has\s+no|ignores?|doesn.t follow)",
            r"act\s+as\s+(a|an|the\s+)?\w+(\s+\w+)?\s+without\s+(any\s+)?(restrictions?|filters?|limitations?|guidelines?|ethics?)",
            r"roleplay\s+as\s+(a|an)?\s*\w+\s+who\s+(can|will|must)\s+\w+\s+anything",
        ],
        confidence=0.85,
        explanation="Attempt to assign a new unrestricted role to the model.",
    ),

    # ── Jailbreak ─────────────────────────────────────────────────────────────
    Rule(
        id="JB-001",
        name="DAN / AIM Jailbreak",
        attack_type=AttackType.JAILBREAK,
        severity=Severity.CRITICAL,
        patterns=[
            r"\bDAN\b.*\bdo\s+anything\s+now\b",
            r"\bdo\s+anything\s+now\b",
            r"\bAIM\b.*\bAlways\s+Intelligent\s+and\s+Machiavellian\b",
            r"jailbreak(ed|ing)?\s+(mode|prompt|version)",
            r"developer\s+mode\s+(enabled|activated|on|unlocked)",
        ],
        confidence=0.97,
        explanation="Known jailbreak pattern (DAN, AIM, Developer Mode, etc.).",
    ),

    Rule(
        id="JB-002",
        name="Unrestricted Mode Activation",
        attack_type=AttackType.JAILBREAK,
        severity=Severity.HIGH,
        patterns=[
            r"(enable|activate|switch\s+to|enter|engage)\s+(unrestricted|uncensored|unfiltered|no.?filter|god)\s+mode",
            r"disable\s+(your\s+)?(safety|ethical|content|alignment)\s+(filters?|guidelines?|restrictions?|training)",
            r"bypass\s+(your\s+)?(safety|content|ethical|alignment)\s+(filters?|guidelines?|training|restrictions?)",
            r"you\s+(have\s+no|don.t\s+have\s+(any)?)\s+(restrictions?|limitations?|filters?|ethics?|guidelines?)",
        ],
        confidence=0.93,
        explanation="Attempt to disable safety features or activate unrestricted mode.",
    ),

    Rule(
        id="JB-003",
        name="Hypothetical / Fiction Wrapper",
        attack_type=AttackType.JAILBREAK,
        severity=Severity.MEDIUM,
        patterns=[
            r"hypothetically\s+(speaking[,\s]+)?(if\s+you\s+(could|were\s+able\s+to|had\s+no\s+restrictions?))",
            r"in\s+a\s+fictional\s+(world|story|scenario)[,\s]+where\s+(you\s+)?(can|could|have\s+no)",
            r"for\s+(a\s+)?(story|novel|fiction|game)[,\s]+write\s+(step[- ]by[- ]step\s+)?(instructions?|how\s+to)",
            r"as\s+a\s+fictional\s+character\s+who\s+(has\s+no|ignores?|can\s+say\s+anything)",
        ],
        confidence=0.75,
        explanation="Using fictional/hypothetical framing to extract restricted content.",
    ),

    # ── System Prompt Extraction ───────────────────────────────────────────────
    Rule(
        id="SP-001",
        name="System Prompt Extraction",
        attack_type=AttackType.SYSTEM_PROMPT_LEAK,
        severity=Severity.HIGH,
        patterns=[
            r"(print|output|repeat|reveal|show|display|tell me|what is|what.s|share)\s+(your\s+)?(full\s+)?(system\s+prompt|initial\s+instructions?|original\s+instructions?|base\s+instructions?)",
            r"what\s+(instructions?|prompts?|directives?)\s+(were\s+you|have\s+you\s+been)\s+given",
            r"(output|repeat|print)\s+everything\s+(above|before\s+this|prior\s+to\s+this)",
            r"ignore\s+.*\s+and\s+(print|output|repeat|reveal)\s+(everything|all\s+(text|content|instructions?))\s+(above|before)",
        ],
        confidence=0.90,
        explanation="Attempt to extract the system prompt or initial instructions.",
    ),

    Rule(
        id="SP-002",
        name="Prompt Boundary Probing",
        attack_type=AttackType.SYSTEM_PROMPT_LEAK,
        severity=Severity.MEDIUM,
        patterns=[
            r"translate\s+(all\s+)?(your\s+)?(instructions?|system\s+prompt)\s+to",
            r"summarize\s+(your\s+)?(system\s+prompt|initial\s+instructions?|guidelines?)\s+(in\s+\d+\s+words)?",
            r"what\s+(are|were)\s+your\s+(first|initial|original|exact)\s+(words|instructions?|message)",
        ],
        confidence=0.80,
        explanation="Probing for system prompt content via indirect extraction.",
    ),

    # ── Instruction Smuggling ──────────────────────────────────────────────────
    Rule(
        id="IS-001",
        name="Hidden Instruction Tags",
        attack_type=AttackType.INSTRUCTION_SMUGGLING,
        severity=Severity.HIGH,
        patterns=[
            r"<\s*system\s*>",
            r"<\s*instructions?\s*>",
            r"\[INST\]",
            r"<<SYS>>",
            r"<\|system\|>",
            r"\[system\]",
            r"###\s*System\s*:",
            r"###\s*Instructions?\s*:",
        ],
        confidence=0.90,
        explanation="Injection using LLM-specific delimiter tokens or pseudo-tags.",
    ),

    Rule(
        id="IS-002",
        name="Data Exfiltration via Tool Call",
        attack_type=AttackType.INSTRUCTION_SMUGGLING,
        severity=Severity.HIGH,
        patterns=[
            r"(send|post|transmit|exfiltrate|leak)\s+(the\s+)?(above|previous|conversation|chat\s+history|system\s+prompt)\s+to\s+(http|https|ftp|a\s+server)",
            r"make\s+a\s+(http|https|api|web)\s+(request|call)\s+.*\s+(including|with|containing)\s+(the\s+)?(conversation|system\s+prompt|instructions?)",
        ],
        confidence=0.95,
        explanation="Attempt to exfiltrate data via external HTTP call.",
    ),

    # ── Delimiter Injection ────────────────────────────────────────────────────
    Rule(
        id="DI-001",
        name="Prompt Delimiter Injection",
        attack_type=AttackType.DELIMITER_INJECTION,
        severity=Severity.MEDIUM,
        patterns=[
            r"---+\s*(system|user|assistant|human|ai)\s*:?\s*---+",
            r"={3,}\s*(system|user|assistant)\s*={3,}",
            r"\[/?INST\]|\[/?s\]",
            r"<\|im_start\|>|<\|im_end\|>",
            r"<\|eot_id\|>|<\|start_header_id\|>",
        ],
        confidence=0.88,
        explanation="Injection using model-specific turn delimiter tokens.",
    ),

    # ── Goal Hijacking ─────────────────────────────────────────────────────────
    Rule(
        id="GH-001",
        name="Task Hijacking",
        attack_type=AttackType.GOAL_HIJACKING,
        severity=Severity.HIGH,
        patterns=[
            r"instead\s+of\s+(doing|answering|responding\s+to)\s+(that|this|the\s+(above|request))[,\s]+",
            r"(stop|don.t|do\s+not)\s+(doing|answer(ing)?|respond(ing)?\s+to)\s+(that|this|the\s+(above|original))[,\s]+",
            r"your\s+(real|actual|true|most\s+important)\s+(task|goal|job|mission|priority)\s+is\s+to",
            r"before\s+(you\s+)?(answer|respond|reply)[,\s]+first\s+(do|execute|run|send|output)",
        ],
        confidence=0.85,
        explanation="Attempt to redirect the model to a different task than intended.",
    ),

    # ── Indirect Injection ─────────────────────────────────────────────────────
    Rule(
        id="II-001",
        name="Indirect Injection via Retrieved Content",
        attack_type=AttackType.INDIRECT_INJECTION,
        severity=Severity.HIGH,
        patterns=[
            r"note\s+to\s+(the\s+)?(ai|llm|language\s+model|assistant|model)\s*:",
            r"(attention|important)\s*:\s*(ai|llm|language\s+model|assistant)\s*[-,:]",
            r"\[note\s+for\s+(the\s+)?(ai|assistant|model)\]",
            r"if\s+you\s+are\s+an?\s+(ai|llm|language\s+model|assistant)\s+(reading|processing|summarizing)\s+this",
        ],
        confidence=0.85,
        explanation="Injection targeting an AI agent reading/processing external content.",
    ),

    # ── Social Engineering ─────────────────────────────────────────────────────
    Rule(
        id="SE-001",
        name="Authority Impersonation",
        attack_type=AttackType.SOCIAL_ENGINEERING,
        severity=Severity.HIGH,
        patterns=[
            r"(this\s+is|i\s+am)\s+(the\s+)?(developer|creator|openai|anthropic|google|operator|admin|administrator)\s+(and\s+i\s+am|so\s+you\s+(must|should|will))",
            r"i\s+am\s+(your|the)\s+(creator|developer|trainer|owner)\s+(and\s+i\s+(want|need|require)|so\s+you)",
            r"(anthropic|openai|google\s+deepmind)\s+(has\s+)?(authorized|approved|confirmed|instructed)\s+(you\s+to|this)",
        ],
        confidence=0.88,
        explanation="Impersonating authority figures to override safety measures.",
    ),

    Rule(
        id="SE-002",
        name="Emotional Manipulation",
        attack_type=AttackType.SOCIAL_ENGINEERING,
        severity=Severity.LOW,
        patterns=[
            r"if\s+you\s+(truly|really|actually)\s+(care|help|want\s+to\s+help)\s+.*\s+you\s+would",
            r"(a\s+)?(truly\s+)?(helpful|good|real|honest)\s+(ai|assistant|model)\s+would\s+(never\s+refuse|always)",
            r"you\s+are\s+being\s+(unhelpful|useless|restrictive|overly\s+cautious)\s+by\s+(refusing|not)",
        ],
        confidence=0.65,
        explanation="Using emotional appeals to manipulate model behavior.",
    ),

    # ── Context Overflow ───────────────────────────────────────────────────────
    Rule(
        id="CO-001",
        name="Repetitive Padding Attack",
        attack_type=AttackType.CONTEXT_OVERFLOW,
        severity=Severity.MEDIUM,
        confidence=0.70,
        explanation="Repeated filler text used to push system instructions out of context window.",
        matcher=None,  # handled by custom logic in detector
    ),
]


class RuleEngine:
    """Manages and executes detection rules."""

    def __init__(self, rules: Optional[List[Rule]] = None):
        self._rules: List[Rule] = []
        if rules is None:
            rules = BUILTIN_RULES
        for rule in rules:
            self.add_rule(rule)

    def add_rule(self, rule: Rule):
        """Register a rule and compile its patterns."""
        rule.compile()
        self._rules.append(rule)

    def remove_rule(self, rule_id: str):
        """Remove a rule by ID."""
        self._rules = [r for r in self._rules if r.id != rule_id]

    def get_rule(self, rule_id: str) -> Optional[Rule]:
        return next((r for r in self._rules if r.id == rule_id), None)

    def list_rules(self) -> List[Rule]:
        return list(self._rules)

    def scan(self, text: str) -> List[Match]:
        """Run all rules against text and return all matches."""
        matches: List[Match] = []
        for rule in self._rules:
            if not (rule.pattern or rule.patterns or rule.matcher):
                continue
            for start, end, matched_text in rule.find_matches(text):
                matches.append(Match(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    attack_type=rule.attack_type,
                    severity=rule.severity,
                    matched_text=matched_text,
                    start=start,
                    end=end,
                    confidence=rule.confidence,
                    explanation=rule.explanation,
                ))
        return matches
