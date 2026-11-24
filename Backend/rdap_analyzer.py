import requests
import tldextract

from datetime import datetime, timezone
from functools import lru_cache


# ==========================================
# PHISHGUARD - RDAP DOMAIN ANALYZER
# ==========================================

RDAP_BASE_URL = "https://rdap.org/domain/"

TIMEOUT = 8


# ==========================================
# 1. DOMAIN EXTRACTION
# ==========================================

def extract_registered_domain(hostname):

    extracted = tldextract.extract(hostname)

    if not extracted.domain or not extracted.suffix:
        return None

    return (
        extracted.domain + "." + extracted.suffix
    ).lower()


# ==========================================
# 2. DATE PARSER
# ==========================================

def parse_rdap_date(data, action):

    events = data.get("events", [])

    for event in events:

        if event.get("eventAction", "").lower() == action:

            date_value = event.get("eventDate")

            if not date_value:
                continue

            try:
                parsed_date = datetime.fromisoformat(
                    date_value.replace("Z", "+00:00")
                )

                if parsed_date.tzinfo is None:
                    parsed_date = parsed_date.replace(
                        tzinfo=timezone.utc
                    )

                return parsed_date

            except ValueError:
                continue

    return None


# ==========================================
# 3. RDAP LOOKUP
# ==========================================

@lru_cache(maxsize=500)
def get_rdap_data(domain):

    try:

        response = requests.get(
            RDAP_BASE_URL + domain,
            headers={
                "Accept": "application/rdap+json"
            },
            timeout=TIMEOUT
        )

        if response.status_code == 404:
            return {
                "status": "not_found"
            }

        response.raise_for_status()

        return {
            "status": "success",
            "data": response.json()
        }

    except requests.exceptions.Timeout:

        return {
            "status": "unknown",
            "message": "RDAP request timed out"
        }

    except requests.exceptions.RequestException:

        return {
            "status": "unknown",
            "message": "RDAP service unavailable"
        }

    except ValueError:

        return {
            "status": "unknown",
            "message": "Invalid RDAP response"
        }


# ==========================================
# 4. MAIN DOMAIN ANALYSIS
# ==========================================

def analyze_domain(hostname):

    result = {
        "domain": None,
        "rdap_status": "unknown",
        "domain_age_days": None,
        "days_to_expiry": None,
        "rdap_risk_score": 0,
        "indicators": []
    }

    registered_domain = extract_registered_domain(
        hostname
    )

    if not registered_domain:

        result["indicators"].append(
            "Registered domain could not be identified"
        )

        return result

    result["domain"] = registered_domain

    # RDAP lookup
    rdap_result = get_rdap_data(registered_domain)

    result["rdap_status"] = rdap_result["status"]

    if rdap_result["status"] != "success":

        result["indicators"].append(
            "RDAP registration information unavailable"
        )

        result["rdap_risk_score"] += 1

        return result

    data = rdap_result["data"]

    now = datetime.now(timezone.utc)

    # Registration date
    registration_date = parse_rdap_date(
        data,
        "registration"
    )

    # Expiration date
    expiration_date = parse_rdap_date(
        data,
        "expiration"
    )

    # ======================================
    # DOMAIN AGE
    # ======================================

    if registration_date:

        age_days = (
            now - registration_date
        ).days

        result["domain_age_days"] = age_days

        if age_days < 0:

            result["indicators"].append(
                "Invalid future registration date"
            )

        elif age_days < 365:

            result["indicators"].append(
                "Domain registered less than 365 days ago"
            )

            result["rdap_risk_score"] += 1

    else:

        result["indicators"].append(
            "Domain registration date unavailable"
        )

    # ======================================
    # EXPIRATION DATE
    # ======================================

    if expiration_date:

        days_to_expiry = (
            expiration_date - now
        ).days

        result["days_to_expiry"] = days_to_expiry

    else:

        result["indicators"].append(
            "Domain expiration date unavailable"
        )

    # ======================================
    # COMBINED RDAP RULE
    # ======================================

    if (
        registration_date
        and expiration_date
    ):

        age_days = result["domain_age_days"]
        expiry_days = result["days_to_expiry"]

        if (
            0 <= age_days < 365
            and 0 <= expiry_days < 180
        ):

            result["indicators"].append(
                "New domain with less than 180 days "
                "remaining before expiration"
            )

            result["rdap_risk_score"] += 1

    return result


# ==========================================
# END OF RDAP ANALYZER
# ==========================================