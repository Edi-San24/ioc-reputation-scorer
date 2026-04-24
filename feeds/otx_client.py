# feeds / otx_client.py
# This will handle all communication with the OTX API. 

#Libraries
import time
import logging 
import requests 
from config import(
    OTX_API_KEY,
    OTX_BASE_URL,
    OTX_ENDPOINTS,
    REQUEST_TIMEOUT,
    REQUEST_RETRIES,
    RETRY_BACKOFF,
)

logger = logging.getLogger(__name__)


#OTX Client Class
class OTXClient:
    """
    Client for interacting with the OTX API.
    Handles the following: Authentication, Retries, and Response Parsing.
    """

    def __init__(self):
        self.api_key = OTX_API_KEY
        self.base_url = OTX_BASE_URL
        self.headers = {
            "X-OTX-API-KEY": self.api_key,
            "Content-Type": "application/json",
        }
    
    def _make_request(self, url):
        """
        Makes an HTTP GET Request with retry logic.
        Returns parsed JSON response or None on failure.
        """
        for attempt in range(1, REQUEST_RETRIES + 1):
            try:
                response = requests.get(
                    url,
                    headers=self.headers,
                    timeout=REQUEST_TIMEOUT
                )
                response.raise_for_status()
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
                time.sleep(wait)
            
        logger.error(f"All {REQUEST_RETRIES} attempts failed for URL: {url}")
        return None

    def query_ioc(self, ioc, ioc_type):
        """
        Queries the OTX for a single IOC
        Returns a normalized directory of threat intelligence data. 
        """

        if ioc_type not in OTX_ENDPOINTS:
            logger.error(f"Unsupported IOC type: {ioc_type}")
            return None
        
        endpoint = OTX_ENDPOINTS[ioc_type].format(ioc=ioc)
        url = f"{self.base_url}{endpoint}"
        logger.info(f"Querying OTX for {ioc_type}: {ioc}")

        data = self._make_request(url)
        if data is None:
            return None
        
        return self._parse_response(data, ioc, ioc_type)
    
    def _parse_response(self, data, ioc, ioc_type):
        """
        Extracts relevant fields from the raw OTX API response.
        Returns a normalized dictionary ready for the scoring engine.
        """
        pulse_info = data.get("pulse_info", {})
        pulses     = pulse_info.get("pulses", [])

        #Extracting unique threat actor tags across all pulses 
        threat_actors = list({
            tag
            for pulse in pulses
            for tag in pulse.get("tags", [])
            if "apt" in tag.lower() or "actor" in tag.lower()
        })

        #Extract unique malware family names 
        malware_families = list({
            ref
            for pulse in pulses
            for ref in pulse.get("references", [])
            if isinstance(ref,str) and ref 
        })

        #Extracting first and last seen dates 
        first_seen = data.get("first_seen", None)
        last_seen  = data.get("last_seen", None)

        return {
            "ioc": ioc,
            "ioc_type": ioc_type,
            "source": "otx",
            "pulse_count": pulse_info.get("count", 0),
            "threat_actors": threat_actors,
            "malware_families": malware_families,
            "tags": [tag for pulse in pulses for tag in pulse.get("tags", [])],
            "country": data.get("country_code", None),
            "asn": data.get("asn", None),
            "first_seen": first_seen,
            "last_seen": last_seen,
            "raw_data": data,
        }
    