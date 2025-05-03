import sys, requests, os
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.x509.ocsp import OCSPRequestBuilder, load_der_ocsp_response
from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID
import os
import logging


logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)
def load_cert(path, fmt):
    with open(path, 'rb') as f:
        data = f.read()
    return x509.load_pem_x509_certificate(data, default_backend()) if fmt.lower() == 'pem' else x509.load_der_x509_certificate(data, default_backend())



def get_url(cert, extension_oid, access_method_oid=None):
    """
    Extract URL from certificate extensions.
    
    Args:
        cert: The certificate object
        extension_oid: The OID of the extension to look for
        access_method_oid: Optional access method OID for AIA extension
    
    Returns:
        str: The URL if found, None otherwise
    """
    try:
        if extension_oid == ExtensionOID.CRL_DISTRIBUTION_POINTS:
            logger.debug("Looking for CRL distribution points")
            try:
                ext = cert.extensions.get_extension_for_oid(extension_oid)
                for dp in ext.value:
                    if dp.full_name:
                        for name in dp.full_name:
                            if isinstance(name, x509.UniformResourceIdentifier):
                                logger.debug(f"Found CRL URL: {name.value}")
                                return name.value
            except x509.ExtensionNotFound:
                logger.debug("No CRL distribution points extension found")
                
        elif extension_oid == ExtensionOID.AUTHORITY_INFORMATION_ACCESS:
            logger.debug("Looking for AIA extension")
            try:
                ext = cert.extensions.get_extension_for_oid(extension_oid)
                for access in ext.value:
                    if access.access_method == access_method_oid:
                        if isinstance(access.access_location, x509.UniformResourceIdentifier):
                            logger.debug(f"Found OCSP URL: {access.access_location.value}")
                            return access.access_location.value
            except x509.ExtensionNotFound:
                logger.debug("No AIA extension found")
                
    except Exception as e:
        logger.error(f"Error in get_url: {e}")
    
    return None


