import requests, os
from cryptography import x509
import os
import logging
CACHE_DIR = "crl_cache"

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


def check_crl(cert, url):
    logger.debug(f"check_crl called with url: {url}")
    
    if not os.path.exists(CACHE_DIR):
        os.makedirs(CACHE_DIR)
        logger.debug(f"Created cache directory: {CACHE_DIR}")
    
    if not url:
        logger.debug("No CRL URL provided")
        return None
    
    cache_filename = f"crl_{cert.serial_number}.der"
    cache_path = os.path.join(CACHE_DIR, cache_filename)
    logger.debug(f"CRL cache path: {cache_path}")
    
    crl = None
    
    if os.path.exists(cache_path):
        logger.debug("Loading CRL from cache...")
        try:
            with open(cache_path, "rb") as f:
                crl = x509.load_der_x509_crl(f.read())
            logger.debug("CRL loaded from cache successfully")
        except Exception as e:
            logger.warning(f"Error loading cached CRL: {e}")
            os.remove(cache_path)
            logger.debug("Removed corrupted cache file")
            crl = None
    
    if crl is None:
        logger.debug(f"Downloading CRL from {url}")
        try:
            resp = requests.get(url, timeout=10)
            logger.debug(f"CRL download status code: {resp.status_code}")
            
            if resp.status_code == 200:
                logger.debug(f"Writing CRL to cache: {cache_path}")
                with open(cache_path, "wb") as f:
                    f.write(resp.content)
                    
                with open(cache_path, "rb") as f:
                    crl = x509.load_der_x509_crl(f.read())
                logger.debug("CRL downloaded and parsed successfully")
            else:
                logger.warning(f"Failed to download CRL: HTTP {resp.status_code}")
                return None
                
        except Exception as e:
            logger.error(f"Error downloading CRL: {type(e).__name__}: {e}")
            return None
    
    # Vérifier si le certificat est révoqué
    logger.debug(f"Checking if certificate {cert.serial_number} is revoked...")
    for revoked in crl:
        if revoked.serial_number == cert.serial_number:
            logger.warning(f"Certificate {cert.serial_number} is REVOKED")
            return {"status": "REVOKED"}
    
    logger.debug(f"Certificate {cert.serial_number} is not revoked")
    return {"status": "GOOD"}