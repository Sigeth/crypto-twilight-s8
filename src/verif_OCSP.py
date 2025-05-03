import sys, requests, os
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.ocsp import OCSPRequestBuilder, load_der_ocsp_response
from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID
from src.logger import *
import logging


logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)
CACHE_DIR = "crl_cache"


def check_ocsp(cert, issuer, url):
    logger.debug(f"check_ocsp called with url: {url}")
    
    if url and issuer:
        try:
            logger.debug("Creating OCSP request...")
            req = OCSPRequestBuilder().add_certificate(cert, issuer, hashes.SHA1()).build()
            
            logger.debug(f"Sending OCSP request to {url}")
            resp = requests.post(
                url, 
                data=req.public_bytes(serialization.Encoding.DER),
                headers={'Content-Type': 'application/ocsp-request'},
                timeout=10
            )
            
            logger.debug(f"OCSP response status code: {resp.status_code}")
            
            if resp.status_code == 200:
                ocsp_resp = load_der_ocsp_response(resp.content)
                status = ocsp_resp.certificate_status.name
                logger.debug(f"OCSP certificate status: {status}")
                return {"status": status}
            else:
                logger.warning(f"OCSP request failed with status code: {resp.status_code}")
                
        except Exception as e:
            logger.error(f"Error in check_ocsp: {type(e).__name__}: {e}")
    else:
        logger.debug(f"check_ocsp skipped - url: {url is not None}, issuer: {issuer is not None}")
    
    return None

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