"""Phishing detection module: URL analysis, content analysis, confusable detection.

Uses a local reputation model with built-in defaults and user-extendable rules.
Scored heuristic: 0-30 safe, 31-60 suspicious, 61+ phishing.
"""

import json
import os
import re
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse


_CONFUSABLE_MAP = {
    "a": "a",  # Cyrillic a
    "e": "e",  # Cyrillic e
    "o": "o",  # Cyrillic o
    "c": "c",  # Cyrillic es
    "y": "y",  # Cyrillic u
    "x": "x",  # Cyrillic ha
    "i": "i",  # Cyrillic dotted i
    "k": "k",  # Cyrillic ka
    "p": "p",  # Cyrillic er
    "m": "m",  # Cyrillic em
    "t": "t",  # Cyrillic te
    "b": "b",  # Cyrillic ve
    "h": "h",  # Cyrillic en
    "n": "n",  # Cyrillic pe
    "r": "r",  # Cyrillic ghe
    "ο": "o",  # Greek omicron
    "ν": "v",  # Greek nu
    "Ι": "I",  # Greek iota capital
    "і": "i",  # Cyrillic i
    "а": "a",  # Cyrillic a (lowercase)
    "е": "e",  # Cyrillic e (lowercase)
    "о": "o",  # Cyrillic o (lowercase)
    "с": "c",  # Cyrillic es (lowercase)
    "у": "y",  # Cyrillic u (lowercase)
    "х": "x",  # Cyrillic ha (lowercase)
    "р": "p",  # Cyrillic er (lowercase)
    "к": "k",  # Cyrillic ka (lowercase)
    "м": "m",  # Cyrillic em (lowercase)
    "т": "t",  # Cyrillic te (lowercase)
    "в": "b",  # Cyrillic ve (lowercase)
    "н": "h",  # Cyrillic en (lowercase)
    "п": "n",  # Cyrillic pe (lowercase)
    "г": "r",  # Cyrillic ghe (lowercase)
}

_PAYMENT_KEYWORDS = re.compile(
    r"(?:credit\s*card|card\s*number|cvv|cvc|expir|cardholder"
    r"|otp|one.time.pass|seed\s*phrase|recovery\s*phrase"
    r"|wallet\s*(?:address|phrase|password)"
    r"|private\s*key|mnemonic|passphrase)",
    re.IGNORECASE,
)

_OBFUSCATION_PATTERNS = re.compile(
    r"(?:eval\s*\(\s*(?:atob|String\.fromCharCode|unescape)\s*\()"
    r"|(?:atob|fromCharCode|unescape)\s*\(\s*[\"'][A-Za-z0-9+/=]{80,}[\"']\s*\)",
    re.IGNORECASE,
)

_HIDDEN_IFRAME = re.compile(
    r"<iframe[^>]*(?:hidden|display\s*:\s*none|width\s*=\s*[\"']?[01][\"']|height\s*=\s*[\"']?[01][\"'])",
    re.IGNORECASE,
)

_PASSWORD_INPUT = re.compile(
    r"<input[^>]*type\s*=\s*[\"']password[\"']",
    re.IGNORECASE,
)

_FORM_ACTION_CROSS_ORIGIN = re.compile(
    r"<form[^>]*action\s*=\s*[\"'](https?://[^\"']+)[\"']",
    re.IGNORECASE,
)

_SCRIPT_TAG = re.compile(r"<script[^>]*>([\s\S]*?)</script>", re.IGNORECASE)

_VISIBLE_TEXT = re.compile(r"(?<=>)[^<]+(?=<)", re.IGNORECASE)

_BRAND_TEXT_PATTERNS: dict[str, re.Pattern] = {}

_XN_PREFIX = re.compile(r"^xn--")


@dataclass
class ThreatAssessment:
    score: int
    verdict: str  # "safe", "suspicious", "phishing"
    reasons: list[str] = field(default_factory=list)
    phase: str = "url"
    matched_brand: Optional[str] = None


_COMMON_TLDS = frozenset({
    "com", "org", "net", "edu", "gov", "mil", "io", "co", "uk", "de", "me", "tk",
    "info", "biz", "app", "dev", "shop", "online", "site", "cc", "tv", "xyz",
})


@dataclass
class ReputationData:
    blocked_domains: set[str] = field(default_factory=set)
    blocked_url_prefixes: list[str] = field(default_factory=list)
    protected_brands: list[dict[str, Any]] = field(default_factory=list)
    suspicious_keywords: set[str] = field(default_factory=set)

    def brand_tokens(self) -> set[str]:
        tokens = set()
        for brand in self.protected_brands:
            name = brand.get("name", "")
            if name:
                tokens.add(name.lower())
            for domain in brand.get("domains", []):
                for part in domain.lower().split("."):
                    if part and part not in _COMMON_TLDS:
                        tokens.add(part)
        return tokens

    def trusted_hosts_for_brand_token(self, token: str) -> set[str]:
        result = set()
        for brand in self.protected_brands:
            name = brand.get("name", "").lower()
            domains = [d.lower() for d in brand.get("domains", [])]
            if token == name or token in {d.split(".")[0] for d in domains if d}:
                for domain in domains:
                    result.add(domain)
                    parts = domain.split(".")
                    for i in range(1, len(parts)):
                        suffix = ".".join(parts[i:])
                        if "." in suffix:
                            result.add(suffix)
        return result

    def find_brand_for_token(self, token: str) -> Optional[str]:
        token_lower = token.lower()
        for brand in self.protected_brands:
            name = brand.get("name", "").lower()
            if token_lower == name:
                return brand.get("name")
            for domain in brand.get("domains", []):
                if token_lower == domain.lower().split(".")[0]:
                    return brand.get("name")
        return None


def _load_builtin_defaults() -> ReputationData:
    builtin_path = Path(__file__).resolve().parents[1] / "assets" / "phishing_defaults.json"
    return _load_rules_from_json(builtin_path) or ReputationData()


def _load_rules_from_json(path: Path) -> Optional[ReputationData]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    return ReputationData(
        blocked_domains=set(str(d) for d in data.get("blocked_domains", []) if isinstance(d, str)),
        blocked_url_prefixes=[str(p) for p in data.get("blocked_url_prefixes", []) if isinstance(p, str)],
        protected_brands=[
            {"name": str(b.get("name", "")), "domains": [str(d) for d in b.get("domains", [])]}
            for b in data.get("protected_brands", []) if isinstance(b, dict) and b.get("name")
        ],
        suspicious_keywords=set(str(k) for k in data.get("suspicious_keywords", []) if isinstance(k, str)),
    )


def load_reputation(user_rules_path: Optional[Path] = None) -> ReputationData:
    builtin = _load_builtin_defaults()

    if user_rules_path is not None and user_rules_path.exists():
        user = _load_rules_from_json(user_rules_path)
        if user is not None:
            merged = ReputationData(
                blocked_domains=builtin.blocked_domains | user.blocked_domains,
                blocked_url_prefixes=list(dict.fromkeys(builtin.blocked_url_prefixes + user.blocked_url_prefixes)),
                protected_brands=builtin.protected_brands + user.protected_brands,
                suspicious_keywords=builtin.suspicious_keywords | user.suspicious_keywords,
            )
            return merged

    if user_rules_path is not None and not user_rules_path.exists():
        try:
            user_rules_path.parent.mkdir(parents=True, exist_ok=True)
            with open(user_rules_path, "w", encoding="utf-8") as f:
                json.dump({"blocked_domains": [], "blocked_url_prefixes": [], "protected_brands": [], "suspicious_keywords": []}, f, indent=2)
        except OSError:
            pass

    return builtin


def load_user_rules_raw(user_rules_path: Path) -> dict:
    try:
        with open(user_rules_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        data = {}
    if not isinstance(data, dict):
        data = {}
    return data


def save_user_rules(user_rules_path: Path, rules: dict) -> None:
    user_rules_path.parent.mkdir(parents=True, exist_ok=True)
    with open(user_rules_path, "w", encoding="utf-8") as f:
        json.dump(rules, f, indent=2)


def _is_ipv4(host: str) -> bool:
    parts = host.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) < 256 for p in parts)
    except (ValueError, TypeError):
        return False


def _normalize_confusable(text: str) -> str:
    text = text.lower()
    text = unicodedata.normalize("NFKC", text)
    result = []
    for ch in text:
        result.append(_CONFUSABLE_MAP.get(ch, ch))
    text = "".join(result)
    text = text.replace("1", "l").replace("0", "o").replace("@", "a")
    return text


def _brand_token_matches_hostname(hostname: str, reputation: ReputationData) -> list[str]:
    reasons = []
    normalized_hostname = hostname.lower()
    tokens = reputation.brand_tokens()
    labels = normalized_hostname.split(".")

    for label in labels:
        if not label:
            continue
        norm_label = _normalize_confusable(label)
        for token in tokens:
            if not token:
                continue
            if norm_label == token or norm_label == _normalize_confusable(token):
                trusted_hosts = reputation.trusted_hosts_for_brand_token(token)
                is_trusted = any(
                    normalized_hostname == th or normalized_hostname.endswith("." + th)
                    for th in trusted_hosts
                )
                if not is_trusted:
                    brand_name = reputation.find_brand_for_token(token)
                    if brand_name:
                        reasons.append(f"hostname label '{label}' matches protected brand '{brand_name}' but host is not trusted")
                    else:
                        reasons.append(f"hostname label '{label}' matches a protected brand token but host is not trusted")
    return reasons


def assess_url(url: str, reputation: ReputationData) -> ThreatAssessment:
    score = 0
    reasons = []
    matched_brand: Optional[str] = None

    parsed = urlparse(url)
    host = parsed.hostname or ""
    scheme = parsed.scheme

    # Reputation checks first
    host_lower = host.lower()
    if host_lower in reputation.blocked_domains:
        return ThreatAssessment(score=100, verdict="phishing", reasons=[f"blocked domain: {host}"], phase="url")

    normalized_url = url.lower()
    for prefix in reputation.blocked_url_prefixes:
        if normalized_url.startswith(prefix.lower()):
            return ThreatAssessment(score=100, verdict="phishing", reasons=[f"blocked URL prefix: {prefix}"], phase="url")

    if _is_ipv4(host):
        score += 30
        reasons.append("host is an IPv4 address")

    if scheme == "http":
        score += 15
        reasons.append("scheme is http, not https")

    path_and_query = (parsed.path + ("?" + parsed.query if parsed.query else "")).lower()
    for keyword in reputation.suspicious_keywords:
        if keyword in path_and_query or keyword in host_lower:
            score += 15
            reasons.append(f"contains suspicious keyword: '{keyword}'")
            break

    if len(host) > 35:
        score += 10
        reasons.append("hostname length > 35")

    if len(host.split(".")) >= 4:
        score += 10
        reasons.append("hostname has 4+ labels")

    for label in host.split("."):
        if label and _XN_PREFIX.match(label):
            score += 25
            reasons.append(f"punycode label detected: {label}")
            break

    brand_reasons = _brand_token_matches_hostname(host, reputation)
    if brand_reasons:
        score += 25
        reasons.extend(brand_reasons)
        from re import search as re_search
        for r in brand_reasons:
            m = re_search(r"brand '(\w+)'", r)
            if m:
                matched_brand = m.group(1)
                break

    verdict = _score_verdict(score)
    return ThreatAssessment(score=score, verdict=verdict, reasons=reasons, phase="url", matched_brand=matched_brand)


def assess_content(url: str, html: str, reputation: ReputationData) -> ThreatAssessment:
    score = 0
    reasons = []

    if not html or "<html" not in html.lower() and "<body" not in html.lower():
        return ThreatAssessment(score=0, verdict="safe", reasons=[], phase="content")

    if _PASSWORD_INPUT.search(html):
        score += 20
        reasons.append("page contains a password input")

    payment_hits = _PAYMENT_KEYWORDS.findall(html)
    if payment_hits:
        score += 25
        reasons.append(f"page mentions sensitive payment/crypto terms: {', '.join(set(payment_hits))}")

    parsed = urlparse(url)
    current_host = (parsed.hostname or "").lower()

    for fm in _FORM_ACTION_CROSS_ORIGIN.finditer(html):
        action_url = fm.group(1)
        action_parsed = urlparse(action_url)
        action_host = (action_parsed.hostname or "").lower()
        if action_host and action_host != current_host:
            score += 30
            reasons.append(f"form submits to different host: {action_host}")
            break

    if _HIDDEN_IFRAME.search(html):
        score += 15
        reasons.append("hidden or tiny iframe detected")

    scripts = _SCRIPT_TAG.findall(html)
    for script in scripts:
        if _OBFUSCATION_PATTERNS.search(script):
            score += 20
            reasons.append("obfuscated script detected (eval/atob/fromCharCode/unescape)")
            break

    text_matches = _VISIBLE_TEXT.findall(html)
    visible_text = " ".join(text_matches)
    brand_text_reasons = _check_brand_text_content(current_host, visible_text, reputation)
    if brand_text_reasons:
        score += 25
        reasons.extend(brand_text_reasons)

    verdict = _score_verdict(score)
    return ThreatAssessment(score=score, verdict=verdict, reasons=reasons, phase="content")


def _check_brand_text_content(host: str, visible_text: str, reputation: ReputationData) -> list[str]:
    reasons = []
    lower_text = visible_text.lower()
    for brand in reputation.protected_brands:
        brand_name = brand.get("name", "")
        name_lower = brand_name.lower()
        if name_lower in lower_text:
            trusted = [d.lower() for d in brand.get("domains", [])]
            is_trusted = any(host == t or host.endswith("." + t) for t in trusted)
            if not is_trusted:
                reasons.append(f"page text references '{brand_name}' but host '{host}' is not trusted for this brand")
    return reasons


def _score_verdict(score: int) -> str:
    if score >= 61:
        return "phishing"
    elif score >= 31:
        return "suspicious"
    return "safe"


def merge_assessments(
    url_assessment: ThreatAssessment,
    content_assessment: ThreatAssessment,
) -> ThreatAssessment:
    merged_score = url_assessment.score + content_assessment.score
    merged_reasons = list(url_assessment.reasons) + list(content_assessment.reasons)
    verdict = _score_verdict(merged_score)
    matched_brand = url_assessment.matched_brand or content_assessment.matched_brand
    return ThreatAssessment(
        score=merged_score,
        verdict=verdict,
        reasons=merged_reasons,
        phase="merged",
        matched_brand=matched_brand,
    )
