from urllib.parse import urlsplit, unquote
import ipaddress
import re
import math
from collections import Counter


# ==========================================
# PHISHGUARD - ADVANCED URL ANALYZER
# ==========================================

SUSPICIOUS_WORDS = [
    "login",
    "verify",
    "update",
    "account",
    "password",
    "signin",
    "confirm",
    "secure",
    "banking",
    "wallet",
    "recover",
    "authentication",
    "credential",
    "payment",
    "verification"
]


# ==========================================
# 1. ENTROPY CALCULATION
# ==========================================

def calculate_entropy(text):

    if not text:
        return 0

    counts = Counter(text)
    length = len(text)

    entropy = -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )

    return entropy


# ==========================================
# 2. URL ANALYSIS
# ==========================================

def analyze_url(raw_url):

    # BASIC VALIDATION

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
            raise ValueError(
                "Only HTTP and HTTPS URLs are allowed."
            )

        if not parsed.hostname:
            raise ValueError(
                "URL must contain a valid hostname."
            )

        hostname = parsed.hostname.lower()

        # PORT VALIDATION

        try:
            parsed.port
        except ValueError:
            raise ValueError("Invalid port in URL.")

        # CREDENTIAL VALIDATION

        if (
            parsed.username is not None
            or parsed.password is not None
        ):
            raise ValueError(
                "URLs containing embedded credentials "
                "are not accepted."
            )

        # HOSTNAME VALIDATION

        if len(hostname) > 253:
            raise ValueError("Hostname is too long.")

        try:
            hostname.encode("idna")
        except UnicodeError:
            raise ValueError("Invalid hostname encoding.")

    except ValueError as error:
        raise ValueError(str(error))

    # INITIAL VALUES

    score = 0
    indicators = []

    full_url = raw_url.lower()

    # RISK ADDING FUNCTION

    def add_risk(points, reason):

        nonlocal score

        score += points
        indicators.append(reason)

    # ==========================================
    # 3. IP ADDRESS DETECTION
    # ==========================================

    try:

        ipaddress.ip_address(hostname)

        add_risk(
            25,
            "IP address used instead of a domain name"
        )

    except ValueError:
        pass

    # ==========================================
    # 4. SUSPICIOUS KEYWORD DETECTION
    # ==========================================

    found_words = [
        word for word in SUSPICIOUS_WORDS
        if word in full_url
    ]

    if found_words:

        add_risk(
            10,
            "Suspicious keywords detected: "
            + ", ".join(found_words)
        )

    # ==========================================
    # 5. SUBDOMAIN ANALYSIS
    # ==========================================

    hostname_parts = hostname.split(".")

    if len(hostname_parts) > 3:

        add_risk(
            15,
            "Excessive subdomains detected"
        )

    # ==========================================
    # 6. HYPHEN ANALYSIS
    # ==========================================

    hyphen_count = hostname.count("-")

    if hyphen_count >= 2:

        add_risk(
            8,
            "Multiple hyphens in hostname"
        )

    # ==========================================
    # 7. PUNYCODE DETECTION
    # ==========================================

    if any(
        label.startswith("xn--")
        for label in hostname_parts
    ):

        add_risk(
            15,
            "Punycode encoded hostname detected"
        )

    # ==========================================
    # 8. URL LENGTH ANALYSIS
    # ==========================================

    if len(raw_url) > 120:

        add_risk(
            10,
            "Unusually long URL"
        )

    # ==========================================
    # 9. SPECIAL CHARACTER ANALYSIS
    # ==========================================

    special_count = len(
        re.findall(r"[@%!$]", raw_url)
    )

    if special_count >= 2:

        add_risk(
            10,
            "Multiple unusual special characters detected"
        )

    # ==========================================
    # 10. URL ENCODING ANALYSIS
    # ==========================================

    encoded_count = len(
        re.findall(
            r"%[0-9a-fA-F]{2}",
            raw_url
        )
    )

    if encoded_count >= 4:

        add_risk(
            10,
            "Excessive URL encoding detected"
        )

    # ==========================================
    # 11. DOMAIN ENTROPY ANALYSIS
    # ==========================================

    domain_entropy = calculate_entropy(hostname)

    if (
        len(hostname) >= 12
        and domain_entropy > 3.8
    ):

        add_risk(
            10,
            "Unusually complex hostname pattern"
        )

    # ==========================================
    # 12. URL PATH ANALYSIS
    # ==========================================

    path_parts = [
        part
        for part in parsed.path.split("/")
        if part
    ]

    if len(path_parts) >= 6:

        add_risk(
            8,
            "Unusually deep URL path"
        )

    # ==========================================
    # 13. QUERY PARAMETER ANALYSIS
    # ==========================================

    query_count = len([
        item
        for item in parsed.query.split("&")
        if item
    ])

    if query_count >= 8:

        add_risk(
            8,
            "Excessive URL query parameters"
        )

    # ==========================================
    # 14. HTTP PROTOCOL ANALYSIS
    # ==========================================

    if parsed.scheme.lower() == "http":

        add_risk(
            5,
            "Connection does not use HTTPS"
        )

    # ==========================================
    # 15. ENCODED CONTENT ANALYSIS
    # ==========================================

    decoded_url = unquote(raw_url)

    if (
        decoded_url != raw_url
        and re.search(
            r"javascript:|data:|<script|<iframe",
            decoded_url,
            re.IGNORECASE
        )
    ):

        add_risk(
            20,
            "Potentially suspicious encoded URL content"
        )

    # ==========================================
    # 16. NUMERIC DOMAIN ANALYSIS
    # ==========================================

    domain_without_dots = hostname.replace(".", "")

    digit_count = sum(
        char.isdigit()
        for char in domain_without_dots
    )

    if (
        len(domain_without_dots) >= 10
        and digit_count / len(domain_without_dots) > 0.5
    ):

        add_risk(
            8,
            "Unusually high number of digits in hostname"
        )

    # ==========================================
    # 17. FINAL RISK SCORE
    # ==========================================

    score = min(score, 100)

    # ==========================================
    # 18. RISK CLASSIFICATION
    # ==========================================

    if score <= 30:

        risk_level = "Low Risk"

    elif score <= 60:

        risk_level = "Suspicious"

    else:

        risk_level = "High Risk"

    # ==========================================
    # 19. FINAL RESULT
    # ==========================================

    return {

        "url": raw_url,

        "risk_score": score,

        "risk_level": risk_level,

        "indicators": indicators

    }


# ==========================================
# END OF PHISHGUARD ANALYZER
# ==========================================