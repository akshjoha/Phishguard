import requests
import base64
import unicodedata
import re
from urllib.parse import urlparse

# ========================
# CONFIG
# ========================
VIRUSTOTAL_API_KEY = "Your_VirusTotal_API_Key_Here"

# ========================
# HOMOGLYPH MAP (suspicious characters only)
# ========================
ASCII_HOMOGLYPH_PATTERNS = [
    "@", "4", "0", "1", "!", "$", "|", "rn", "vv", "cl", "ci"
]

UNICODE_HOMOGLYPHS = {
    'a': ['α', 'а', 'ɑ'],
    'b': ['ß', 'Ь'],
    'c': ['¢', 'ϲ', 'с'],
    'd': ['ԁ', 'ɗ'],
    'e': ['е', 'ɛ', '℮'],
    'f': ['ƒ'],
    'g': ['ɡ', 'Ԍ'],
    'h': ['һ', 'ḥ'],
    'i': ['ı'],
    'j': ['ј'],
    'k': ['κ', 'ḳ'],
    'l': ['ⅼ'],
    'm': ['ṃ'],
    'n': ['ń', 'п'],
    'o': ['ο', 'о', 'ɔ'],
    'p': ['ρ', 'р'],
    'q': ['ԛ'],
    'r': ['ɾ', 'г'],
    's': ['ѕ', 'ś'],
    't': ['ţ'],
    'u': ['υ', 'ս'],
    'v': ['ⅴ'],
    'w': ['ѡ', 'ɯ'],
    'x': ['х', '×'],
    'y': ['ү', 'у'],
    'z': ['ƶ', 'ž'],
}

# ========================
# VIRUSTOTAL CHECK
# ========================
def virustotal_check(url):
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    flagged_engines = []

    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        response = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers,
            timeout=6
        )

        if response.status_code == 200:
            attributes = response.json()["data"]["attributes"]
            results = attributes.get("last_analysis_results", {})

            for engine, data in results.items():
                if data.get("category") in ["malicious", "suspicious"]:
                    flagged_engines.append(engine)

            return len(flagged_engines) > 0, flagged_engines

    except Exception:
        pass

    return False, []

# ========================
# HOMOGLYPH / UNICODE DETECTION
# ========================
def normalize_domain(domain):
    try:
        return unicodedata.normalize("NFKC", domain)
    except Exception:
        return domain

def contains_invisible_chars(domain):
    for char in domain:
        if unicodedata.category(char) in ["Cf", "Cc"]:
            return True
    return False

def detect_mixed_scripts(domain):
    scripts = set()
    for char in domain:
        if char.isalnum():
            try:
                script = unicodedata.name(char).split()[0]
                scripts.add(script)
            except ValueError:
                continue
    return "LATIN" in scripts and len(scripts) > 1

def contains_ascii_homoglyphs(domain):
    domain = domain.lower()
    for pattern in ASCII_HOMOGLYPH_PATTERNS:
        if pattern in domain:
            return True
    return False

def contains_unicode_homoglyphs(domain):
    for legit_char, fake_chars in UNICODE_HOMOGLYPHS.items():
        for fake in fake_chars:
            if fake in domain:
                return True
    return False

def is_punycode(domain):
    return "xn--" in domain

def detect_homograph_attack(url):
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    reasons = []

    # Only check ASCII homoglyphs for purely ASCII domains
    if all(ord(c) < 128 for c in domain):
        if contains_ascii_homoglyphs(domain):
            reasons.append("Look-alike characters detected in domain")
        return len(reasons) > 0, reasons

    # For non-ASCII domains
    normalized = normalize_domain(domain)
    if domain != normalized:
        reasons.append("Unicode normalization mismatch (possible homograph attack)")

    if is_punycode(domain):
        reasons.append("Punycode domain detected (IDN homograph risk)")

    if detect_mixed_scripts(domain):
        reasons.append("Mixed Unicode scripts detected in domain")

    if contains_ascii_homoglyphs(domain) or contains_unicode_homoglyphs(domain):
        reasons.append("Look-alike characters detected in domain")

    if contains_invisible_chars(domain):
        reasons.append("Invisible or zero-width Unicode characters detected")

    return len(reasons) > 0, reasons

# ========================
# FINAL ANALYSIS FUNCTION
# ========================
def analyze_url(url):
    vt_flagged, engines = virustotal_check(url)
    homoglyph_detected, homoglyph_reasons = detect_homograph_attack(url)

    reasons = []
    reasons.extend(homoglyph_reasons)

    # Final verdict prioritizes VirusTotal results
    if vt_flagged:
        verdict = "Likely Phishing"
    elif homoglyph_detected:
        verdict = "Suspicious"
    else:
        verdict = "Legitimate"

    return verdict, engines, reasons
