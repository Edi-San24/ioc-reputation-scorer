# feeds/whois_client.py
# WHOIS enrichment client using WhoisXML API.
# Provides domain registration data to improve scoring context.

import logging
import requests
from datetime import datetime, timezone
from config import (
    WHOIS_API_KEY,
    REQUEST_TIMEOUT,
    REQUEST_RETRIES,
    RETRY_BACKOFF,
)

logger = logging.getLogger(__name__)

WHOIS_BASE_URL = "https://www.whoisxmlapi.com/whoisserver/WhoisService"


class WHOISClient:
    """
    Client for querying WHOIS registration data via WhoisXML API.
    Only queries domains — IPs, hashes, and URLs are skipped.
    """

    def __init__(self):
        self.api_key  = WHOIS_API_KEY
        self.base_url = WHOIS_BASE_URL

    def query_domain(self, domain):
        """
        Queries WHOIS data for a domain.
        Returns normalized registration data or None if unavailable.
        """
        logger.info(f"Querying WHOIS for domain: {domain}")

        params = {
            "apiKey":       self.api_key,
            "domainName":   domain,
            "outputFormat": "JSON",
            "da":           "2",
        }

        for attempt in range(1, REQUEST_RETRIES + 1):
            try:
                response = requests.get(
                    self.base_url,
                    params=params,
                    timeout=REQUEST_TIMEOUT,
                )
                response.raise_for_status()
                data = response.json()
                return self._parse_response(data, domain)

            except requests.exceptions.HTTPError as e:
                logger.error(f"WHOIS HTTP error on attempt {attempt}: {e}")
            except requests.exceptions.ConnectionError as e:
                logger.error(f"WHOIS connection error on attempt {attempt}: {e}")
            except requests.exceptions.Timeout:
                logger.error(f"WHOIS timeout on attempt {attempt}")

            import time
            time.sleep(RETRY_BACKOFF * attempt)

        logger.error(f"WHOIS lookup failed for: {domain}")
        return None

    def _parse_response(self, data, domain):
        """
        Extracts relevant WHOIS fields from the API response.
        """
        record = data.get("WhoisRecord", {})

        # Registration dates
        created_date = record.get("createdDate", None)
        updated_date = record.get("updatedDate", None)
        expires_date = record.get("expiresDate", None)

        # Registrar info
        registrar = record.get("registrarName", None)

        # Registrant info
        registrant         = record.get("registrant", {})
        registrant_org     = registrant.get("organization", None)
        registrant_country = registrant.get("country", None)

        # Domain age in days
        domain_age_days = None
        if created_date:
            try:
                created = datetime.fromisoformat(created_date.replace("Z", "+00:00"))
                now     = datetime.now(timezone.utc)
                domain_age_days = (now - created).days
            except (ValueError, TypeError):
                pass

        # Privacy protected check
        privacy_protected = any(
            term in str(registrant).lower()
            for term in ["privacy", "proxy", "whoisguard", "redacted", "protected"]
        )

        return {
            "ioc":               domain,
            "ioc_type":          "domain",
            "source":            "whois",
            "created_date":      created_date,
            "updated_date":      updated_date,
            "expires_date":      expires_date,
            "registrar":         registrar,
            "registrant_org":    registrant_org,
            "registrant_country": registrant_country,
            "domain_age_days":   domain_age_days,
            "privacy_protected": privacy_protected,
            "raw_data":          data,
        }  

