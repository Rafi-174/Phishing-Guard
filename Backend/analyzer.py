from urllib.parse import urlsplit, unquote
import ipaddress
import re
import math
from collections import Counter

from rdap_analyzer import analyze_domain


# ==========================================
# PHISHGUARD - ADVANCED URL ANALYZER
# Rule-Based + RDAP Detection
# ==========================================

SUSPICIOUS_WORDS = [
    "login", "verify", "update", "account",
    "password", "signin", "confirm", "secure",
    "banking", "wallet", "recover",
    "authentication", "credential", "payment",
    "verification"
]


# ==========================================
# 1. ENTROPY CALCULATION
# ==========================================

def calculate_entropy(text):

    if not text:
        return 0.0

    counts = Counter(text)
    length = len(text)

    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )


# ==========================================
# 2. HOSTNAME VALIDATION
# ==========================================

def validate_hostname(hostname):

    if not hostname:
        raise ValueError("URL must contain a valid hostname.")

    if len(hostname) > 253:
        raise ValueError("Hostname is too long.")

    try:
        ipaddress.ip_address(hostname)
        return hostname
    except ValueError:
        pass

    try:
        ascii_hostname = hostname.encode("idna").decode("ascii")
    except UnicodeError:
        raise ValueError("Invalid hostname encoding.")

    if len(ascii_hostname) > 253:
        raise ValueError("Hostname is too long.")

    labels = ascii_hostname.rstrip(".").split(".")

    for label in labels:

        if not label or len(label) > 63:
            raise ValueError("Invalid hostname structure.")

        if label.startswith("-") or label.endswith("-"):
            raise ValueError("Invalid hostname structure.")

        if not re.fullmatch(r"[a-zA-Z0-9-]+", label):
            raise ValueError("Invalid hostname structure.")

    return ascii_hostname.lower()


# ==========================================
# 3. RISK CLASSIFICATION
# ==========================================

def classify_risk(score):

    if score <= 30:
        return "Low Risk"

    elif score <= 60:
        return "Suspicious"

    else:
        return "High Risk"


# ==========================================
# 4. MAIN URL ANALYSIS
# ==========================================

def analyze_url(raw_url):

    if not isinstance(raw_url, str):
        raise ValueError("URL must be text.")

    raw_url = raw_url.strip()

    if not raw_url:
        raise ValueError("Please enter a URL.")

    if len(raw_url) > 2048:
        raise ValueError("URL is too long.")

    if any(char.isspace() for char in raw_url):
        raise ValueError("URL must not contain spaces.")

    try:

        parsed = urlsplit(raw_url)

        if parsed.scheme.lower() not in ["http", "https"]:
            raise ValueError("Only HTTP and HTTPS URLs are allowed.")

        if not parsed.hostname:
            raise ValueError("URL must contain a valid hostname.")

        original_hostname = parsed.hostname.lower()

        try:
            port = parsed.port
        except ValueError:
            raise ValueError("Invalid port in URL.")

        if parsed.username is not None or parsed.password is not None:
            raise ValueError(
                "URLs containing embedded credentials are not accepted."
            )

        hostname = validate_hostname(original_hostname)

    except ValueError as error:
        raise ValueError(str(error))

    # INITIAL VALUES

    score = 0
    indicators = []

    domain_age_days = None
    days_to_expiry = None
    rdap_status = "unknown"

    full_url = raw_url.lower()
    scheme = parsed.scheme.lower()

    def add_risk(points, reason):

        nonlocal score

        score += points
        indicators.append(reason)

    # ======================================
    # 5. IP ADDRESS DETECTION
    # ======================================

    is_ip_address = False

    try:

        ipaddress.ip_address(hostname)
        is_ip_address = True

        add_risk(25, "IP address used instead of a domain name")

    except ValueError:
        pass

    # ======================================
    # 6. SUSPICIOUS KEYWORDS
    # ======================================

    found_words = [
        word for word in SUSPICIOUS_WORDS
        if word in full_url
    ]

    if found_words:

        add_risk(
            10,
            "Suspicious keywords detected: " + ", ".join(found_words)
        )

    # ======================================
    # 7. DOMAIN LENGTH
    # ======================================

    if len(hostname) > 20 and not is_ip_address:
        add_risk(4, "Unusually long domain name")

    # ======================================
    # 8. DOMAIN DOT COUNT
    # ======================================

    dot_count = hostname.count(".")
    hostname_parts = hostname.split(".")

    if (
        dot_count >= 3
        and len(hostname_parts) > 3
        and not is_ip_address
    ):
        add_risk(3, "Multiple dots in hostname")

    # ======================================
    # 9. SUBDOMAIN ANALYSIS
    # ======================================

    if len(hostname_parts) > 3 and not is_ip_address:
        add_risk(15, "Excessive subdomains detected")

    # ======================================
    # 10. HYPHEN ANALYSIS
    # ======================================

    hyphen_count = hostname.count("-")

    if hyphen_count >= 1 and not is_ip_address:
        add_risk(3, "Hyphen detected in hostname")

    if hyphen_count >= 2 and not is_ip_address:
        add_risk(5, "Multiple hyphens in hostname")

    # ======================================
    # 11. PUNYCODE
    # ======================================

    if any(label.startswith("xn--") for label in hostname_parts):
        add_risk(15, "Punycode encoded hostname detected")

    # ======================================
    # 12. URL LENGTH
    # ======================================

    if len(raw_url) > 120:
        add_risk(10, "Unusually long URL")

    # ======================================
    # 13. SPECIAL CHARACTERS
    # ======================================

    special_count = len(re.findall(r"[@%!$]", raw_url))

    if special_count >= 2:
        add_risk(10, "Multiple unusual special characters detected")

    if "@" in parsed.path or "@" in parsed.query:
        add_risk(5, "At-sign character detected in URL path or query")

    # ======================================
    # 14. URL ENCODING
    # ======================================

    encoded_count = len(
        re.findall(r"%[0-9a-fA-F]{2}", raw_url)
    )

    if encoded_count >= 4:
        add_risk(10, "Excessive URL encoding detected")

    # ======================================
    # 15. DOMAIN ENTROPY
    # ======================================

    domain_entropy = calculate_entropy(hostname)

    if (
        len(hostname) >= 12
        and domain_entropy > 3.8
        and not is_ip_address
    ):
        add_risk(10, "Unusually complex hostname pattern")

    # ======================================
    # 16. FULL URL ENTROPY
    # ======================================

    url_entropy = calculate_entropy(full_url)

    if url_entropy > 4.0:
        add_risk(5, "High URL character entropy detected")

    # ======================================
    # 17. PATH TRAVERSAL DETECTION
    # ======================================

    decoded_path = parsed.path

    # Decode repeatedly to detect encoded traversal patterns
    for _ in range(3):
        decoded_path = unquote(decoded_path)

    normalized_path = decoded_path.replace("\\", "/")

    path_segments = normalized_path.split("/")

    if any(segment == ".." for segment in path_segments):
        add_risk(15, "Path traversal pattern detected")

    # ======================================
    # 18. PATH ANALYSIS
    # ======================================

    path_parts = [
        part for part in parsed.path.split("/") if part
    ]

    if len(path_parts) >= 6:
        add_risk(8, "Unusually deep URL path")

    # ======================================
    # 19. QUERY PARAMETERS
    # ======================================

    query_count = len([
        item for item in parsed.query.split("&") if item
    ])

    if query_count >= 8:
        add_risk(8, "Excessive URL query parameters")

    # ======================================
    # 20. HTTP PROTOCOL
    # ======================================

    if scheme == "http":
        add_risk(5, "Connection does not use HTTPS")

    # ======================================
    # 21. UNUSUAL PORT
    # ======================================

    if port is not None:

        default_port = 80 if scheme == "http" else 443

        if port != default_port:
            add_risk(5, "Non-standard port detected")

    # ======================================
    # 22. ENCODED CONTENT
    # ======================================

    decoded_url = unquote(raw_url)

    if (
        decoded_url != raw_url
        and re.search(
            r"javascript:|data:|<script|<iframe",
            decoded_url,
            re.IGNORECASE
        )
    ):
        add_risk(20, "Potentially suspicious encoded URL content")

    # ======================================
    # 23. NUMERIC DOMAIN ANALYSIS
    # ======================================

    domain_without_dots = hostname.replace(".", "")

    digit_count = sum(
        char.isdigit() for char in domain_without_dots
    )

    if digit_count >= 1 and not is_ip_address:
        add_risk(2, "Digits detected in hostname")

    if (
        len(domain_without_dots) >= 10
        and digit_count / len(domain_without_dots) > 0.5
        and not is_ip_address
    ):
        add_risk(8, "Unusually high number of digits in hostname")

    # ======================================
    # 24. RDAP DOMAIN ANALYSIS
    # ======================================

    if not is_ip_address:

        try:

            rdap_result = analyze_domain(hostname)

            rdap_status = rdap_result.get(
                "rdap_status", "unknown"
            )

            domain_age_days = rdap_result.get(
                "domain_age_days"
            )

            days_to_expiry = rdap_result.get(
                "days_to_expiry"
            )

            for reason in rdap_result.get("indicators", []):

                indicators.append("RDAP: " + reason)

            if rdap_status == "success":

                rdap_score = rdap_result.get(
                    "rdap_risk_score", 0
                )

                score += max(0, int(rdap_score))

        except Exception:

            rdap_status = "unknown"

            indicators.append(
                "RDAP: Domain registration check unavailable"
            )

    # ======================================
    # 25. FINAL RISK SCORE
    # ======================================

    score = min(score, 100)

    # ======================================
    # 26. RISK CLASSIFICATION
    # ======================================

    risk_level = classify_risk(score)

    # ======================================
    # 27. FINAL RESULT
    # ======================================

    return {
        "url": raw_url,
        "risk_score": score,
        "risk_level": risk_level,
        "indicators": indicators,
        "domain_age_days": domain_age_days,
        "days_to_expiry": days_to_expiry,
        "rdap_status": rdap_status
    }


# ==========================================
# END OF PHISHGUARD ANALYZER
# ==========================================