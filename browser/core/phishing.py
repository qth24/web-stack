"""Phishing detection module: signal-based policy engine with optional reputation.

V2: replaces additive heuristic with category-capped signal scoring,
suppressors for benign patterns, and a structured decision policy.
Core protection works fully offline; external reputation is optional.
"""

import json
import re
import time
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional, Callable
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

_COMMON_TLDS = frozenset({
    "com", "org", "net", "edu", "gov", "mil", "io", "co", "uk", "de", "me", "tk",
    "info", "biz", "app", "dev", "shop", "online", "site", "cc", "tv", "xyz",
})

_CREDENTIAL_INPUT_RE = re.compile(
    r"<input[^>]*("
    r"type\s*=\s*[\"'](?:password)[\"']"
    r"|(?:name|id|placeholder)\s*=\s*[\"'](?:"
    r"pass(?:word|wd|code)?|"
    r"pwd|"
    r"pin|"
    r"(?:credit\s*|)card\s*(?:number|num|no)?|"
    r"cc\s*(?:number|num|no)?|"
    r"cvv|cvc|csc|"
    r"expir(?:y|ation|e)\s*(?:date)?|"
    r"otp|one\s*time\s*(?:pass|code|pin)|"
    r"(?:seed|recovery|mnemonic)\s*(?:phrase|words|code)?|"
    r"private\s*key|"
    r"passphrase|"
    r"secret\s*(?:phrase|key|code)"
    r")[\"']"
    r")",
    re.IGNORECASE,
)

_OBFUSCATION_PATTERNS = re.compile(
    r"(?:eval\s*\(\s*(?:atob|String\.fromCharCode|unescape)\s*\()"
    r"|(?:atob|fromCharCode|unescape)\s*\(\s*[\"'][A-Za-z0-9+/=]{80,}[\"']\s*\)",
    re.IGNORECASE,
)

_FORM_ACTION_CROSS_ORIGIN = re.compile(
    r"<form[^>]*action\s*=\s*[\"'](https?://[^\"']+)[\"']",
    re.IGNORECASE,
)

_FORM_TAG_RE = re.compile(r"<form[\s>]", re.IGNORECASE)

_IFRAME_RE = re.compile(
    r"<iframe[^>]*(?:hidden|display\s*:\s*none|width\s*=\s*[\"']?[01][\"']|height\s*=\s*[\"']?[01][\"'])",
    re.IGNORECASE,
)

_SCRIPT_TAG_RE = re.compile(r"<script[^>]*>([\s\S]*?)</script>", re.IGNORECASE)

_XN_PREFIX = re.compile(r"^xn--")

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

_HEADING_RE = re.compile(r"<(h[12])[^>]*>(.*?)</\1>", re.IGNORECASE | re.DOTALL)

_FORM_BODY_RE = re.compile(r"<form[^>]*>([\s\S]*?)</form>", re.IGNORECASE | re.DOTALL)

_LABEL_RE = re.compile(r"<label[^>]*>(.*?)</label>", re.IGNORECASE | re.DOTALL)

_INPUT_ATTRS_RE = re.compile(
    r"<input[^>]*(?:name|id|placeholder)\s*=\s*[\"']([^\"']+)[\"']",
    re.IGNORECASE,
)

_BUTTON_RE = re.compile(r"<(?:button|input)[^>]*>", re.IGNORECASE)

_SUBMIT_TEXT_RE = re.compile(
    r"<(?:button|input)[^>]*(?:>([^<]*)</(?:button)>"
    r"|value\s*=\s*[\"']([^\"']+)[\"'])",
    re.IGNORECASE,
)

_HTML_TAG_RE = re.compile(r"<[^>]+>")

_CATEGORY_CAPS = {
    "identity": 35,
    "collection": 25,
    "exfiltration": 35,
    "technical": 20,
    "generic": 10,
}

_LOW_SIGNALS_THAT_CANNOT_PHISH = {
    "suspicious_keyword",
    "long_hostname",
    "many_labels",
}

_FALLBACK_EXTERNAL_REPUTATION = None


@dataclass
class SignalHit:
    id: str
    category: str
    severity: str
    score: int
    reason: str


@dataclass
class ReputationHit:
    source: str
    verdict: str
    ttl_seconds: int


@dataclass
class ThreatAssessment:
    score: int
    verdict: str
    action: str = "allow"
    confidence: float = 0.0
    reasons: list[str] = field(default_factory=list)
    signals: list[SignalHit] = field(default_factory=list)
    phase: str = "url"
    matched_brand: Optional[str] = None
    trusted_host: bool = False
    external_verdict: Optional[str] = None
    external_source: Optional[str] = None


@dataclass
class ReputationData:
    blocked_domains: set[str] = field(default_factory=set)
    blocked_url_prefixes: list[str] = field(default_factory=list)
    protected_brands: list[dict[str, Any]] = field(default_factory=list)
    suspicious_keywords: set[str] = field(default_factory=set)
    trusted_hosts: set[str] = field(default_factory=set)
    external_reputation: Optional[dict] = None

    def is_host_trusted(self, host: str) -> bool:
        host_lower = host.lower()
        if host_lower in self.trusted_hosts:
            return True
        for th in self.trusted_hosts:
            if host_lower.endswith("." + th):
                return True
        return False

    def is_host_trusted_for_brand(self, host: str, brand_name: str) -> bool:
        host_lower = host.lower()
        if self.is_host_trusted(host_lower):
            return True
        for brand in self.protected_brands:
            if brand.get("name", "").lower() != brand_name.lower():
                continue
            for domain in brand.get("domains", []):
                d = domain.lower()
                if host_lower == d or host_lower.endswith("." + d):
                    return True
            for suffix in brand.get("trusted_host_suffixes", []):
                s = suffix.lower()
                if host_lower.endswith("." + s):
                    return True
        return False

    def find_matching_brand(self, token: str) -> Optional[str]:
        token_lower = token.lower()
        norm = _normalize_confusable(token_lower)
        for brand in self.protected_brands:
            name = brand.get("name", "").lower()
            if norm == _normalize_confusable(name) or norm == name:
                return brand.get("name")
            for domain in brand.get("domains", []):
                if norm == _normalize_confusable(domain.lower().split(".")[0]):
                    return brand.get("name")
            for rd in brand.get("related_domains", []):
                if norm == _normalize_confusable(rd.lower().split(".")[0]):
                    return brand.get("name")
        return None

    def trusted_hosts_for_token(self, token: str) -> set[str]:
        result = set()
        for brand in self.protected_brands:
            name = brand.get("name", "").lower()
            domains = [d.lower() for d in brand.get("domains", [])]
            norm = _normalize_confusable(token.lower())
            if norm == _normalize_confusable(name) or norm in {
                _normalize_confusable(d.split(".")[0]) for d in domains if d
            }:
                for domain in domains:
                    result.add(domain)
                    parts = domain.split(".")
                    for i in range(1, len(parts)):
                        suffix = ".".join(parts[i:])
                        if "." in suffix:
                            result.add(suffix)
                for suffix in brand.get("trusted_host_suffixes", []):
                    result.add(suffix.lower())
        for th in self.trusted_hosts:
            result.add(th.lower())
        return result

    def all_brand_names_lower(self) -> set[str]:
        return {
            brand.get("name", "").lower()
            for brand in self.protected_brands
            if brand.get("name")
        }


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
            {
                "name": str(b.get("name", "")),
                "domains": [str(d) for d in b.get("domains", [])],
                "trusted_host_suffixes": [str(s) for s in b.get("trusted_host_suffixes", [])],
                "related_domains": [str(r) for r in b.get("related_domains", [])],
            }
            for b in data.get("protected_brands", []) if isinstance(b, dict) and b.get("name")
        ],
        suspicious_keywords=set(str(k) for k in data.get("suspicious_keywords", []) if isinstance(k, str)),
        trusted_hosts=set(str(h) for h in data.get("trusted_hosts", []) if isinstance(h, str)),
        external_reputation=data.get("external_reputation") if isinstance(data.get("external_reputation"), dict) else None,
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
                trusted_hosts=builtin.trusted_hosts | user.trusted_hosts,
                external_reputation=user.external_reputation or builtin.external_reputation,
            )
            return merged

    if user_rules_path is not None and not user_rules_path.exists():
        try:
            user_rules_path.parent.mkdir(parents=True, exist_ok=True)
            with open(user_rules_path, "w", encoding="utf-8") as f:
                json.dump({
                    "blocked_domains": [],
                    "blocked_url_prefixes": [],
                    "protected_brands": [],
                    "suspicious_keywords": [],
                    "trusted_hosts": [],
                }, f, indent=2)
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


def _strip_tags(text: str) -> str:
    return _HTML_TAG_RE.sub(" ", text)


def _extract_dom_focused_text(html: str) -> dict:
    title_text = ""
    title_m = _TITLE_RE.search(html)
    if title_m:
        title_text = _strip_tags(title_m.group(1)).strip()

    heading_texts = []
    for m in _HEADING_RE.finditer(html):
        heading_texts.append(_strip_tags(m.group(2)).strip())

    form_labels = set()
    form_inputs = set()
    form_button_texts = set()
    form_body = ""

    form_count = len(_FORM_TAG_RE.findall(html))
    if form_count == 0:
        pass
    elif form_count == 1:
        fb = _FORM_BODY_RE.search(html)
        if fb:
            form_body = fb.group(1)
    else:
        forms = _FORM_BODY_RE.findall(html)
        for fb in forms:
            form_body += fb

    if form_body:
        for m in _LABEL_RE.finditer(form_body):
            form_labels.add(_strip_tags(m.group(1)).strip())

        for m in _INPUT_ATTRS_RE.finditer(form_body):
            form_inputs.add(m.group(1).strip())

        for m in _SUBMIT_TEXT_RE.finditer(form_body):
            text = (m.group(1) or m.group(2) or "").strip()
            if text:
                form_button_texts.add(text)

    return {
        "title": title_text,
        "headings": heading_texts,
        "form_labels": form_labels,
        "form_inputs": form_inputs,
        "form_button_texts": form_button_texts,
        "form_body": form_body,
    }


def _check_brand_in_focused_text(focused: dict, brand_names: set[str]) -> dict:
    title_lower = focused["title"].lower()
    headings_text = " ".join(focused["headings"]).lower()
    labels_text = " ".join(focused["form_labels"]).lower()
    inputs_text = " ".join(focused["form_inputs"]).lower()
    buttons_text = " ".join(focused["form_button_texts"]).lower()
    form_text = labels_text + " " + inputs_text + " " + buttons_text

    in_form = set()
    all_hits = set()

    for brand in brand_names:
        brand_lower = brand.lower()
        if brand_lower in title_lower:
            all_hits.add(brand)
            if brand_lower in form_text:
                in_form.add(brand)
        if brand_lower in headings_text:
            all_hits.add(brand)
            if brand_lower in form_text:
                in_form.add(brand)
        if brand_lower in form_text:
            all_hits.add(brand)
            in_form.add(brand)

    return {"all_brands": all_hits, "form_brands": in_form}


def _check_credential_collection_in_form(form_body: str) -> list[str]:
    hits = []
    if _CREDENTIAL_INPUT_RE.search(form_body):
        hits.append("credential/seed collection input detected in form")
    return hits


def _check_passwords_in_html(html: str) -> bool:
    return bool(re.search(
        r"<input[^>]*type\s*=\s*[\"']password[\"']",
        html,
        re.IGNORECASE,
    ))


def _check_credit_card_keywords_in_form(form_body: str) -> bool:
    return bool(re.search(
        r"(?:credit\s*card|card\s*number|cvv|cvc|csc|expir)",
        form_body,
        re.IGNORECASE,
    ))


def _check_otp_seed_in_form(form_body: str) -> bool:
    return bool(re.search(
        r"(?:otp|one.time.pass|seed\s*phrase|recovery\s*phrase|"
        r"wallet\s*(?:address|phrase|password)|private\s*key|mnemonic|passphrase)",
        form_body,
        re.IGNORECASE,
    ))


def _brand_token_matches_hostname(hostname: str, reputation: ReputationData) -> list[str]:
    reasons = []
    normalized_hostname = hostname.lower()
    labels = normalized_hostname.split(".")
    for label in labels:
        if not label:
            continue
        norm_label = _normalize_confusable(label)
        for brand in reputation.protected_brands:
            name = brand.get("name", "")
            if not name:
                continue
            if norm_label == _normalize_confusable(name.lower()):
                trusted_hosts = reputation.trusted_hosts_for_token(name.lower())
                is_trusted = any(
                    normalized_hostname == th or normalized_hostname.endswith("." + th)
                    for th in trusted_hosts
                )
                if not is_trusted:
                    reasons.append(
                        f"hostname label '{label}' matches protected brand '{name}' "
                        f"but host is not trusted"
                    )
                continue
            for domain in brand.get("domains", []):
                primary = domain.lower().split(".")[0]
                if norm_label == _normalize_confusable(primary):
                    trusted_hosts = reputation.trusted_hosts_for_token(primary)
                    is_trusted = any(
                        normalized_hostname == th or normalized_hostname.endswith("." + th)
                        for th in trusted_hosts
                    )
                    if not is_trusted:
                        reasons.append(
                            f"hostname label '{label}' matches protected brand '{name}' "
                            f"but host is not trusted"
                        )
                    break
    return reasons


def _compute_assessment(signals: list[SignalHit], matched_brand: Optional[str],
                        trusted_host: bool, phase: str,
                        has_critical: bool = False,
                        external_verdict: Optional[str] = None,
                        external_source: Optional[str] = None) -> ThreatAssessment:
    categories = {"identity": 0, "collection": 0, "exfiltration": 0, "technical": 0, "generic": 0}
    category_names = set()

    for s in signals:
        cap = _CATEGORY_CAPS.get(s.category, 999)
        categories[s.category] = min(cap, categories[s.category] + s.score)
        if s.category != "generic":
            category_names.add(s.category)

    total_score = sum(categories.values())

    non_generic_cats = category_names - {"generic"}
    only_low_signals = all(s.id in _LOW_SIGNALS_THAT_CANNOT_PHISH for s in signals) if signals else False

    is_phishing = False
    is_suspicious = False

    if has_critical:
        is_phishing = True
    elif categories["identity"] >= 20 and categories["collection"] >= 20:
        is_phishing = True
    elif categories["collection"] >= 20 and categories["exfiltration"] >= 35:
        is_phishing = True
    elif total_score >= 60 and len(non_generic_cats) >= 2 and not only_low_signals:
        is_phishing = True

    if not is_phishing:
        has_medium_high = any(s.severity in ("high", "medium") for s in signals)
        if total_score >= 25:
            is_suspicious = True
        elif has_medium_high and len(signals) <= 1:
            is_suspicious = True

    if is_phishing:
        verdict = "phishing"
        action = "block"
        confidence = min(0.95, total_score / 100.0)
    elif is_suspicious:
        verdict = "suspicious"
        action = "warn"
        confidence = min(0.80, total_score / 100.0)
    else:
        verdict = "safe"
        action = "allow"
        confidence = max(0.90, 1.0 - total_score / 100.0)

    grouped_reasons = [s.reason for s in signals]

    return ThreatAssessment(
        score=total_score,
        verdict=verdict,
        action=action,
        confidence=round(confidence, 3),
        reasons=grouped_reasons,
        signals=signals,
        phase=phase,
        matched_brand=matched_brand,
        trusted_host=trusted_host,
        external_verdict=external_verdict,
        external_source=external_source,
    )


def assess_url(url: str, reputation: ReputationData) -> ThreatAssessment:
    signals: list[SignalHit] = []
    matched_brand: Optional[str] = None
    trusted_host = False
    has_critical = False

    parsed = urlparse(url)
    host = parsed.hostname or ""
    scheme = parsed.scheme
    host_lower = host.lower()

    if host_lower in reputation.blocked_domains:
        signals.append(SignalHit(
            id="blocklist_hit", category="identity", severity="critical",
            score=100, reason=f"blocked domain: {host}",
        ))
        return _compute_assessment(signals, matched_brand, trusted_host, "url", has_critical=True)

    normalized_url = url.lower()
    for prefix in reputation.blocked_url_prefixes:
        if normalized_url.startswith(prefix.lower()):
            signals.append(SignalHit(
                id="blocklist_hit", category="identity", severity="critical",
                score=100, reason=f"blocked URL prefix: {prefix}",
            ))
            return _compute_assessment(signals, matched_brand, trusted_host, "url", has_critical=True)

    external_verdict: Optional[str] = None
    external_source: Optional[str] = None

    if reputation.external_reputation is not None:
        ext = _check_external_reputation(url, host, reputation.external_reputation)
        if ext is not None:
            if ext.verdict == "malicious":
                signals.append(SignalHit(
                    id="external_malicious", category="identity", severity="critical",
                    score=100, reason=f"external reputation provider '{ext.source}' flagged as malicious",
                ))
                return _compute_assessment(signals, matched_brand, trusted_host, "url", has_critical=True,
                                           external_verdict="malicious", external_source=ext.source)
            if ext.verdict == "safe":
                return _compute_assessment([], matched_brand, trusted_host, "url", has_critical=False,
                                           external_verdict="safe", external_source=ext.source)

    if _is_ipv4(host):
        signals.append(SignalHit(
            id="ipv4_host", category="technical", severity="medium",
            score=12, reason="host is an IPv4 address",
        ))

    if scheme == "http":
        signals.append(SignalHit(
            id="http_scheme", category="technical", severity="low",
            score=8, reason="scheme is http, not https",
        ))

    path_and_query = (parsed.path + ("?" + parsed.query if parsed.query else "")).lower()
    for keyword in reputation.suspicious_keywords:
        if keyword in path_and_query or keyword in host_lower:
            signals.append(SignalHit(
                id="suspicious_keyword", category="generic", severity="low",
                score=5, reason=f"contains suspicious keyword: '{keyword}'",
            ))
            break

    if len(host) > 35:
        signals.append(SignalHit(
            id="long_hostname", category="generic", severity="low",
            score=4, reason="hostname length > 35",
        ))

    if len(host.split(".")) >= 4:
        signals.append(SignalHit(
            id="many_labels", category="generic", severity="low",
            score=4, reason="hostname has 4+ labels",
        ))

    for label in host.split("."):
        if label and _XN_PREFIX.match(label):
            signals.append(SignalHit(
                id="punycode", category="technical", severity="medium",
                score=15, reason=f"punycode label detected: {label}",
            ))
            break

    brand_reasons = _brand_token_matches_hostname(host, reputation)
    if brand_reasons:
        for br in brand_reasons:
            signals.append(SignalHit(
                id="brand_spoof_hostname", category="identity", severity="high",
                score=35, reason=br,
            ))
        for brand in reputation.protected_brands:
            name = brand.get("name", "")
            if name:
                for br in brand_reasons:
                    if name in br:
                        matched_brand = name
                        trusted_host = reputation.is_host_trusted_for_brand(host, name)
                        break
                if matched_brand:
                    break

    for signal in signals:
        if signal.id == "brand_spoof_hostname" and trusted_host:
            signals.remove(signal)

    return _compute_assessment(signals, matched_brand, trusted_host, "url")


def assess_content(url: str, html: str, reputation: ReputationData) -> ThreatAssessment:
    signals: list[SignalHit] = []
    matched_brand: Optional[str] = None
    trusted_host = False

    if not html or "<html" not in html.lower() and "<body" not in html.lower():
        return _compute_assessment(signals, matched_brand, trusted_host, "dom")

    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    focused = _extract_dom_focused_text(html)
    form_body = focused["form_body"]
    has_form = bool(_FORM_TAG_RE.search(html))

    all_brand_names = reputation.all_brand_names_lower()
    brand_hits = _check_brand_in_focused_text(focused, all_brand_names)
    brands_in_focused_text = brand_hits["all_brands"]
    brands_in_form_context = brand_hits["form_brands"]

    brands_outside_form = brands_in_focused_text - brands_in_form_context
    multi_brand_suppress = len(brands_outside_form) >= 2

    host_is_trusted_global = reputation.is_host_trusted(host)

    primary_brand = None
    if brands_in_focused_text:
        for brand_name in brands_in_focused_text:
            primary_brand = brand_name
            matched_brand = brand_name
            trusted_host = reputation.is_host_trusted_for_brand(host, brand_name)
            break

    if brands_in_form_context and not multi_brand_suppress and not (trusted_host and primary_brand):
        brand_name = next(iter(brands_in_form_context))
        signals.append(SignalHit(
            id="brand_text_mismatch", category="identity", severity="medium",
            score=20,
            reason=f"page content references '{brand_name}' in form context but host '{host}' is not trusted",
        ))
    elif brands_in_focused_text and not multi_brand_suppress and not (trusted_host and primary_brand):
        brand_name = next(iter(brands_in_focused_text))
        signals.append(SignalHit(
            id="brand_text_mismatch", category="identity", severity="medium",
            score=20,
            reason=f"page content references '{brand_name}' but host '{host}' is not trusted",
        ))

    has_password = _check_passwords_in_html(html)

    if form_body and has_form:
        cred_hits = _check_credential_collection_in_form(form_body)
        if cred_hits:
            if trusted_host and primary_brand:
                if not _FORM_ACTION_CROSS_ORIGIN.search(html):
                    pass
                else:
                    signals.append(SignalHit(
                        id="credential_collection", category="collection", severity="high",
                        score=25, reason=cred_hits[0],
                    ))
            else:
                effective_score = 25
                if has_password and trusted_host:
                    has_cross_origin = bool(_FORM_ACTION_CROSS_ORIGIN.search(html))
                    if not has_cross_origin:
                        effective_score = 0
                    else:
                        pass
                if effective_score > 0:
                    signals.append(SignalHit(
                        id="credential_collection", category="collection", severity="high",
                        score=effective_score, reason=cred_hits[0],
                    ))

    has_cross_origin_form = False
    for fm in _FORM_ACTION_CROSS_ORIGIN.finditer(html):
        action_url = fm.group(1)
        action_parsed = urlparse(action_url)
        action_host = (action_parsed.hostname or "").lower()
        if action_host and action_host != host:
            has_cross_origin_form = True
            signals.append(SignalHit(
                id="cross_origin_form", category="exfiltration", severity="high",
                score=35, reason=f"form submits to different host: {action_host}",
            ))
            break

    if has_form and _IFRAME_RE.search(html):
        signals.append(SignalHit(
            id="hidden_iframe_with_form", category="technical", severity="low",
            score=8, reason="hidden or tiny iframe detected near form",
        ))
    elif _IFRAME_RE.search(html) and not has_form:
        pass

    scripts = _SCRIPT_TAG_RE.findall(html)
    for script in scripts:
        if _OBFUSCATION_PATTERNS.search(script):
            signals.append(SignalHit(
                id="obfuscated_script", category="exfiltration", severity="medium",
                score=15, reason="obfuscated script detected (eval/atob/fromCharCode/unescape)",
            ))
            break

    if not matched_brand:
        matched_brand = primary_brand

    return _compute_assessment(signals, matched_brand, trusted_host, "dom")


def merge_assessments(
    url_assessment: ThreatAssessment,
    content_assessment: ThreatAssessment,
) -> ThreatAssessment:
    all_signals = list(url_assessment.signals) + list(content_assessment.signals)

    seen_ids = set()
    deduped_signals = []
    for s in all_signals:
        if s.id not in seen_ids:
            seen_ids.add(s.id)
            deduped_signals.append(s)

    has_critical = any(
        s.severity == "critical" or s.id == "blocklist_hit"
        for s in deduped_signals
    )

    categories = {"identity": 0, "collection": 0, "exfiltration": 0, "technical": 0, "generic": 0}
    category_names = set()
    for s in deduped_signals:
        cap = _CATEGORY_CAPS.get(s.category, 999)
        categories[s.category] = min(cap, categories[s.category] + s.score)
        if s.category != "generic":
            category_names.add(s.category)

    only_low_signals = all(s.id in _LOW_SIGNALS_THAT_CANNOT_PHISH for s in deduped_signals) if deduped_signals else False

    total_score = sum(categories.values())
    non_generic_cats = category_names - {"generic"}

    is_phishing = False
    is_suspicious = False

    if has_critical:
        is_phishing = True
    elif categories["identity"] >= 20 and categories["collection"] >= 20:
        is_phishing = True
    elif categories["collection"] >= 20 and categories["exfiltration"] >= 35:
        is_phishing = True
    elif total_score >= 60 and len(non_generic_cats) >= 2 and not only_low_signals:
        is_phishing = True

    if not is_phishing:
        has_medium_high = any(s.severity in ("high", "medium") for s in deduped_signals)
        if total_score >= 25:
            is_suspicious = True
        elif has_medium_high and len(deduped_signals) <= 1:
            is_suspicious = True

    if is_phishing:
        verdict = "phishing"
        action = "block"
        confidence = min(0.95, total_score / 100.0)
    elif is_suspicious:
        verdict = "suspicious"
        action = "warn"
        confidence = min(0.80, total_score / 100.0)
    else:
        verdict = "safe"
        action = "allow"
        confidence = max(0.90, 1.0 - total_score / 100.0)

    matched_brand = url_assessment.matched_brand or content_assessment.matched_brand
    trusted_host = url_assessment.trusted_host or content_assessment.trusted_host

    return ThreatAssessment(
        score=total_score,
        verdict=verdict,
        action=action,
        confidence=round(confidence, 3),
        reasons=[s.reason for s in deduped_signals],
        signals=deduped_signals,
        phase="merged",
        matched_brand=matched_brand,
        trusted_host=trusted_host,
        external_verdict=url_assessment.external_verdict,
        external_source=url_assessment.external_source,
    )


def should_run_local_content_analysis(url_assessment: Optional[ThreatAssessment]) -> bool:
    if url_assessment is None:
        return True
    return url_assessment.external_verdict != "safe"


_EXTERNAL_REPUTATION_CACHE: dict[str, tuple[float, Optional[ReputationHit]]] = {}


def _check_external_reputation(url: str, host: str,
                               config: dict) -> Optional[ReputationHit]:
    global _EXTERNAL_REPUTATION_CACHE, _FALLBACK_EXTERNAL_REPUTATION

    if not config.get("enabled", False):
        return None

    ttl = config.get("ttl_seconds", 3600)
    prefix = host[:30] + urlparse(url).path[:50] if urlparse(url).path else host
    now = time.time()

    if prefix in _EXTERNAL_REPUTATION_CACHE:
        timestamp, cached = _EXTERNAL_REPUTATION_CACHE[prefix]
        if now - timestamp < ttl:
            return cached
        del _EXTERNAL_REPUTATION_CACHE[prefix]

    lookup_fn = _FALLBACK_EXTERNAL_REPUTATION
    if lookup_fn is None:
        return None

    timeout = config.get("timeout_ms", 500) / 1000.0
    try:
        result = lookup_fn(url, host)
        if result is None or not isinstance(result, ReputationHit):
            _EXTERNAL_REPUTATION_CACHE[prefix] = (now, None)
            return None
        if result.ttl_seconds <= 0:
            result.ttl_seconds = ttl
        _EXTERNAL_REPUTATION_CACHE[prefix] = (now, result)
        return result
    except Exception:
        _EXTERNAL_REPUTATION_CACHE[prefix] = (now, None)
        return None


def set_external_reputation_lookup(lookup_fn: Optional[Callable[[str, str], Optional[ReputationHit]]]) -> None:
    global _FALLBACK_EXTERNAL_REPUTATION
    _FALLBACK_EXTERNAL_REPUTATION = lookup_fn


def get_top_reasons(assessment: ThreatAssessment, count: int = 3) -> list[str]:
    scored = [(s.score, s.reason) for s in assessment.signals]
    scored.sort(key=lambda x: x[0], reverse=True)
    return [reason for _, reason in scored[:count]]
