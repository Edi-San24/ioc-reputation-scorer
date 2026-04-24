# feeds/abusech_client.py
# Handles all communication with abuse.ch threat feeds.
# Covers MalwareBazaar (hashes), URLhaus (URLs/domains), Feodo Tracker (IPs)

import logging
import requests
import csv
import io
from config import (
    ABUSECH_FEEDS,
    ABUSECH_API_KEY,
    REQUEST_TIMEOUT,
    REQUEST_RETRIES,
    RETRY_BACKOFF,
)

logger = logging.getLogger(__name__)

class AbuseCHClient:
    """
    Client for querying abuse.ch threat intelligence feeds.
    Covers MalwareBazaar, URLhaus, and Feodo Tracker.
    Requires an abuse.ch Auth-Key for authentication.
    """

    def __init__(self):
        self.feeds = ABUSECH_FEEDS
        self.headers = {"Auth-Key": ABUSECH_API_KEY}

    def _make_request(self, url, as_text=False):
        """
        Makes an HTTP GET request with retry logic.
        as_text=True returns raw text (for CSV).
        as_text=False returns parsed JSON.
        """
        for attempt in range(1, REQUEST_RETRIES + 1):
            try:
                response = requests.get(url, headers = self.headers, timeout=REQUEST_TIMEOUT)
                response.raise_for_status()

                if as_text:
                    return response.text
                return response.json()

            except requests.exceptions.HTTPError as e:
                logger.error(f"HTTP error on attempt {attempt}: {e}")
            except requests.exceptions.ConnectionError as e:
                logger.error(f"Connection error on attempt {attempt}: {e}")
            except requests.exceptions.Timeout:
                logger.error(f"Timeout on attempt {attempt}")

            if attempt < REQUEST_RETRIES:
                wait = RETRY_BACKOFF * attempt
                logger.info(f"Retrying in {wait} seconds...")
                import time
                time.sleep(wait)

        logger.error(f"All {REQUEST_RETRIES} attempts failed for: {url}")
        return None

    def query_hash(self, file_hash):
        """
        Looks up a file hash in MalwareBazaar.
        Returns normalized IOC data or None if not found.
        """
        logger.info(f"Querying MalwareBazaar for hash: {file_hash}")

        url = self.feeds["malwarebazaar"]
        payload = {
            "query": "get_info",
            "hash": file_hash,
        }

        try:
            response = requests.post(url, data=payload, headers = self.headers, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            data = response.json()
        except Exception as e:
            logger.error(f"MalwareBazaar request failed: {e}")
            return None

        if data.get("query_status") != "ok":
            logger.info(f"Hash not found in MalwareBazaar: {file_hash}")
            return None

        sample = data.get("data", [{}])[0]

        return {
            "ioc":              file_hash,
            "ioc_type":         "hash",
            "source":           "malwarebazaar",
            "malware_families": [sample.get("signature", "unknown")],
            "tags":             sample.get("tags", []) or [],
            "file_type":        sample.get("file_type", None),
            "first_seen":       sample.get("first_seen", None),
            "last_seen":        sample.get("last_seen", None),
            "reporter":         sample.get("reporter", None),
            "country":          None,
            "asn":              None,
            "pulse_count":      0,
            "threat_actors":    [],
            "raw_data":         data,
        }

    # URLhaus lookup
    def query_url(self, url_or_domain):
        """
        Looks up a URL or domain in URLhaus.
        Returns normalized IOC data or None if not found.
        """
        logger.info(f"Querying URLhaus for: {url_or_domain}")

        api_url = "https://urlhaus-api.abuse.ch/v1/url/"
        payload = {"url": url_or_domain}

        try:
            response = requests.post(api_url, data=payload, headers=self.headers, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            data = response.json()
        except Exception as e:
            logger.error(f"URLhaus request failed: {e}")
            return None

        if data.get("query_status") != "is_listed":
            logger.info(f"URL not found in URLhaus: {url_or_domain}")
            return None

        ioc_type = "domain" if "http" not in url_or_domain else "url"

        return {
            "ioc":              url_or_domain,
            "ioc_type":         ioc_type,
            "source":           "urlhaus",
            "malware_families": [data.get("threat", "unknown")],
            "tags":             data.get("tags", []) or [],
            "file_type":        None,
            "first_seen":       data.get("date_added", None),
            "last_seen":        data.get("last_online", None),
            "reporter":         data.get("reporter", None),
            "url_status":       data.get("url_status", None),
            "country":          None,
            "asn":              None,
            "pulse_count":      0,
            "threat_actors":    [],
            "raw_data":         data,
        }

    def query_ip(self, ip_address):
        """
        Looks up an IP address in the Feodo Tracker botnet C2 blocklist.
        Returns normalized IOC data or None if not found.
        """
        logger.info(f"Querying Feodo Tracker for IP: {ip_address}")

        data = self._make_request(self.feeds["feodo"])
        if not data:
            return None

        match = next(
            (entry for entry in data if entry.get("ip_address") == ip_address),
            None
        )

        if match is None:
            logger.info(f"IP not found in Feodo Tracker: {ip_address}")
            return None

        return {
            "ioc":              ip_address,
            "ioc_type":         "ip",
            "source":           "feodo",
            "malware_families": [match.get("malware", "unknown")],
            "tags":             [match.get("malware", "")],
            "file_type":        None,
            "first_seen":       match.get("first_seen", None),
            "last_seen":        match.get("last_online", None),
            "reporter":         None,
            "url_status":       None,
            "country":          match.get("country", None),
            "asn":              match.get("as_number", None),
            "pulse_count":      0,
            "threat_actors":    [],
            "raw_data":         match,
        }


        

