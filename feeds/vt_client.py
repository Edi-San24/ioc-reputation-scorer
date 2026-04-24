# feeds/vt_client.py
# Handles all communication with the VirusTotal API
# Covers: IP, Domain, Hash, and URL queries

import time
import logging
import requests
from config import (
    VT_API_KEY,
    VT_BASE_URL,
    VT_ENDPOINTS,
    VT_RATE_LIMIT_DELAY,
    REQUEST_TIMEOUT,
    REQUEST_RETRIES,
    RETRY_BACKOFF,
)
logger = logging.getLogger(__name__)

class VirusTotalClient:
    """
    Client for querying the VirusTotal API v3
    Handles authentication, rate limiting, and response parsing
    """

    def __init__(self):
        self.api_key = VT_API_KEY
        self.base_url = VT_BASE_URL
        self.headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json",
        }

    def _make_request(self, url):
        """
        Makes an HTTP GET request with rety logic & rate limit delay
        Returns a parsed JSON on success, None on failure.
        """

        for attempt in range(1, REQUEST_RETRIES + 1):
            try:
                response = requests.get(
                    url,
                    headers=self.headers,
                    timeout=REQUEST_TIMEOUT,
                )
                response.raise_for_status()
                time.sleep(VT_RATE_LIMIT_DELAY)  # Rate limit delay
                return response.json()
            
            except requests.exceptions.HTTPError as e:
                if response.status_code == 429:  # Too Many Requests
                    logger.warning("VirusTotal rate limit hit! Waiting 60 seconds...")
                    time.sleep(60)  # Wait longer if rate limited
                else:
                    logger.error(f"HTTP error on attempt {attempt} : {e}")
                
            except requests.exceptions.ConnectionError as e:
                logger.error(f"Connection error on attempt {attempt} : {e}")
            except requests.exceptions.Timeout:
                logger.error(f"Timeout on attempt {attempt}")

            if attempt < REQUEST_RETRIES:
                wait = RETRY_BACKOFF * attempt
                logger.info(f"Retrying in {wait} seconds...")
                time.sleep(wait)

        logger.error(f"All {REQUEST_RETRIES} attempts failed for URL: {url}")
        return None
    
    def query_ioc(self, ioc, ioc_type):
        """
        Queries VirusTotal for a single IOC
        Returns a normalized dictionary of threat intelligence data.
        """
        if ioc_type not in VT_ENDPOINTS:
            logger.error(f"Unsupported IOC type: {ioc_type}")
            return None
        
        endpoint = VT_ENDPOINTS[ioc_type].format(ioc=ioc)
        url = f"{self.base_url}{endpoint}"
        logger.info(f"Querying VirusTotal for {ioc_type}: {ioc}")

        data = self._make_request(url)
        if not data:
            return None
        
        return self._parse_response(data, ioc, ioc_type)
    


    def _parse_response(self, data, ioc, ioc_type):
        """
        Extracts relevant fields from the raw VT API response.
        Returns a normalized dictionary matching the unified IOC schema.
        """

        attributes = data.get("data", {}).get("attributes", {})

        #Detecting stats 
        stats = attributes.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total_engines = sum(stats.values()) if stats else 0
        detection_ratio = round(malicious / total_engines,3) if total_engines > 0 else 0.0

        # Malware families from AV engine results
        av_results = attributes.get("last_analysis_results", {})
        malware_families = list({
            result.get("result") 
            for result in av_results.values()
            if result.get("category") == "malicious" and result.get("result")
        })

        #Tags & threat categories 
        tags = attributes.get("tags", []) or []
        categories = list(attributes.get("categories", {}).values())

        #Dates 
        first_seen = attributes.get("first_submission_date", None)
        last_seen = attributes.get("last_submission_date", None)

        #Convert VT timestamps to ISO format
        if isinstance(first_seen, int):
            from datetime import datetime, timezone
            first_seen = datetime.fromtimestamp(first_seen, tz=timezone.utc).isoformat()

        if isinstance(last_seen, int):
            from datetime import datetime, timezone
            last_seen = datetime.fromtimestamp(last_seen, tz=timezone.utc).isoformat()

        return {
            "ioc": ioc,
            "ioc_type": ioc_type,
            "source": "virustotal",
            "pulse_count": malicious,
            "threat_actors": [], #VT doesn't provide this directly
            "malware_families": malware_families,
            "tags": tags + categories,
            "country": attributes.get("country", None),
            "asn": attributes.get("asn", ""),
            "first_seen": first_seen,
            "last_seen": last_seen,
            "detection_ratio": detection_ratio,
            "total_engines": total_engines,
            "raw_data": data, #Keep the full response for future feature extraction
        }
    
