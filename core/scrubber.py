import re
import time
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from core.aho_corasick import AhoCorasick

_PII_PATTERNS: Dict[str, str] = {
    "EMAIL":       r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
    "PHONE_IN":    r"\+?91[-\s]?\d{10}|\b[6-9]\d{9}\b",
    "PHONE_US":    r"\b\d{3}[-.\s]\d{3}[-.\s]\d{4}\b",
    "CREDIT_CARD": r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
    "SSN":         r"\b\d{3}-\d{2}-\d{4}\b",
    "IP_ADDRESS":  r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "UUID":        r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"
                   r"-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
    "JWT":         r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
    "API_KEY_GEN": r"\b(?:sk|pk|api|key|token|secret)[-_][a-zA-Z0-9]{16,}\b",
    "AWS_KEY":     r"\bAKIA[0-9A-Z]{16}\b",
    "GITHUB_PAT":  r"\bghp_[A-Za-z0-9]{36}\b",
    "OPENAI_KEY":  r"\bsk-[A-Za-z0-9]{48}\b",
}

_COMPILED: Dict[str, re.Pattern] = {
    label: re.compile(pattern, re.IGNORECASE)
    for label, pattern in _PII_PATTERNS.items()
}


@dataclass
class ScrubResult:
    original: str
    sanitized: str
    redactions: List[Dict]
    processing_ms: float
    ac_matches: int = 0
    regex_matches: int = 0


class Scrubber:
    def __init__(self, extra_keywords: List[str] | None = None):
        self._ac = AhoCorasick()
        keywords = extra_keywords or []
        for kw in keywords:
            self._ac.add_pattern(kw.lower())
        if keywords:
            self._ac.build()
        self._has_ac = bool(keywords)

    def scrub(self, text: str, ac_engine: AhoCorasick | None = None) -> ScrubResult:
        t0 = time.perf_counter()
        redactions: List[Dict] = []

        # --- Regex layer ---
        for label, pattern in _COMPILED.items():
            for m in pattern.finditer(text):
                redactions.append({
                    "label": label,
                    "value": m.group(),
                    "start": m.start(),
                    "end":   m.end(),
                    "layer": "regex",
                })

        regex_count = len(redactions)

        # --- Aho-Corasick layer ---
        ac_count = 0
        ac_to_use = ac_engine if ac_engine is not None else (self._ac if self._has_ac else None)
        if ac_to_use is not None:
            for start, pattern in ac_to_use.search(text.lower()):
                redactions.append({
                    "label": "KEYWORD",
                    "value": text[start: start + len(pattern)],
                    "start": start,
                    "end":   start + len(pattern),
                    "layer": "aho_corasick",
                })
                ac_count += 1

        # --- Apply redactions ---
        redactions.sort(key=lambda r: r["start"])
        redactions = _resolve_overlaps(redactions)
        sanitized = _apply_redactions(text, redactions)

        elapsed_ms = (time.perf_counter() - t0) * 1000

        return ScrubResult(
            original=text,
            sanitized=sanitized,
            redactions=redactions,
            processing_ms=round(elapsed_ms, 3),
            ac_matches=ac_count,
            regex_matches=regex_count,
        )


def _resolve_overlaps(redactions: List[Dict]) -> List[Dict]:
    result = []
    last_end = -1
    for r in redactions:
        if r["start"] >= last_end:
            result.append(r)
            last_end = r["end"]
    return result


def _apply_redactions(text: str, redactions: List[Dict]) -> str:
    parts = []
    cursor = 0
    for r in redactions:
        parts.append(text[cursor: r["start"]])
        parts.append(f"[{r['label']}]")
        cursor = r["end"]
    parts.append(text[cursor:])
    return "".join(parts)
