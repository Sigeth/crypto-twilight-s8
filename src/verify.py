"""
Certificate verification module.

This module provides functions to verify X.509 certificates without relying on
external cryptographic libraries like pycryptodome. It implements the necessary
cryptographic functions in pure Python.
"""

from src.verify_extensions import *
from src.verify_sig import *
from src.logger import *

from datetime import datetime as dt
from datetime import timezone

from cryptography import x509

from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID
import os
from src.verif_CRL import check_crl
from src.verif_OCSP import check_ocsp
from src.verify_utils import *  

logger = get_logger()


def load_cert(file_format, file_name):
    """
    Load an X.509 certificate from a file.

    Args:
        file_format (str): Format of the certificate ('pem' or 'der')
        file_name (str): Path to the certificate file

    Returns:
        x509.Certificate: Loaded certificate object or None if loading fails
    """
    with open(file_name, "rb") as f:
        file_data = f.read()

    if file_data is None:
        print("File not found or empty.")
        return None

    if file_format.lower() == "pem":
        return x509.load_pem_x509_certificate(file_data)
    else:
        return x509.load_der_x509_certificate(file_data)


def verify_certificate(cert, ca_cert=None):
    """
    Verify a certificate's validity.

    Args:
        cert (x509.Certificate): Certificate to verify
        ca_cert (x509.Certificate, optional): CA certificate that issued 'cert'

    Returns:
        bool: True if the certificate is valid, False otherwise
    """
    # Check key usage
    if not verify_key_usage(cert, ca_cert):
        logger.info("Key Usage verification failed")
        return False

    # Check basic constraints
    if not verify_basic_constraints(cert, ca_cert):
        logger.info("Basic Constraints verification failed")
        return False

    # Check validity period
    current_time = dt.now(timezone.utc)
    if current_time < cert.not_valid_before_utc or current_time > cert.not_valid_after_utc:
        logger.info("Certificate expired")
        return False
    

    if(verifyCRLOCSP(cert) == False and cert.issuer != cert.subject):
        logger.info("problème dans la vérification du CRL/OCSP")
        return False
    # Check signature algorithm
    algo_cert = cert.signature_algorithm_oid
    supported_algorithms = [
        "1.2.840.113549.1.1.11",  # RSA with SHA-256
        "1.2.840.10045.4.3.3",  # ECDSA with SHA-384
        "1.2.840.10045.4.3.2"  # ECDSA with SHA-256
    ]

    if algo_cert.dotted_string in supported_algorithms:
        # Determine which public key to use for verification
        if ca_cert is None:
            pub_key = cert.public_key()
        else:
            pub_key = ca_cert.public_key()
      
        signature = cert.signature

        if algo_cert.dotted_string == "1.2.840.113549.1.1.11":  # RSA
            return verify_cert_signature(
                "RSA",
                pub_key,
                cert.tbs_certificate_bytes,
                signature,
                cert.signature_hash_algorithm
            )
        else:  # ECDSA
            return verify_cert_signature(
                "ECDSA",
                pub_key,
                cert.tbs_certificate_bytes,
                signature,
                cert.signature_hash_algorithm
            )
    else:
        logger.info("Unsupported Algorithm")
        logger.debug(f'Algorithm OID: {cert.signature_algorithm_oid}')
        return False
    
def verifyCRLOCSP(cert, ca_cert=None):
    """
    Verify certificate revocation status using OCSP and CRL.
    
    Args:
        cert: The certificate to check
        ca_cert: The issuer's certificate (optional)
    
    Returns:
        bool: True if certificate is valid, False if revoked or check fails
    """
    try:
 
        
        # Check if this is a root certificate
        is_root = cert.issuer == cert.subject
        
        
        # Root certificates often don't have CRL/OCSP
        if is_root:
            return True
        
        # Get OCSP URL
        ocsp_url = get_url(cert, ExtensionOID.AUTHORITY_INFORMATION_ACCESS, AuthorityInformationAccessOID.OCSP)
        
        # Get CRL URL
        crl_url = get_url(cert, ExtensionOID.CRL_DISTRIBUTION_POINTS)
        
        # Use ca_cert as issuer certificate
        issuer_cert = ca_cert
        
        # Try OCSP first
        if issuer_cert and ocsp_url:

            
            ocsp_result = check_ocsp(cert, issuer_cert, ocsp_url)

            
            if ocsp_result:
                if ocsp_result['status'] == "GOOD":
                    logger.info("✓ OCSP check PASSED - Certificate is valid")
                    return True
                else:
                    return False
            else:
                logger.warning("OCSP check returned None - falling back to CRL")
        else:
            logger.info(f"OCSP check skipped - issuer_cert: {issuer_cert is not None}, ocsp_url: {ocsp_url is not None}")
        
        # If OCSP fails or is not available, try CRL
        if crl_url:

            
            crl_result = check_crl(cert, crl_url)
            
            if crl_result:
                if crl_result['status'] == "GOOD":
                    logger.info("✓ CRL check PASSED - Certificate is valid")
                    return True
                else:
                    logger.warning(f"✗ CRL check FAILED - Status: {crl_result['status']}")
                    return False
            else:
                logger.warning("CRL check returned None")
        else:
            logger.warning("No CRL URL available")
        
        # If neither OCSP nor CRL is available, decide based on certificate type
        if not ocsp_url and not crl_url:
            logger.warning("Neither OCSP nor CRL URLs available")
            
            # For non-root certificates without revocation info, this might be a problem
            # For root certificates, it's usually normal
            if is_root:
                logger.info("Root certificate without revocation info - considering valid")
                return True
            else:
                logger.warning("Non-root certificate without revocation info - considering invalid")
                return False
        
        logger.warning("✗ Neither OCSP nor CRL check could be performed successfully")
        return False
        
    except Exception as e:
        logger.error(f"✗ Error in verifyCRLOCSP: {type(e).__name__}: {e}")
        logger.exception("Full traceback:")
        return False

def verify_certificate_chain(file_format: str, certs):
    """
    Verify a certificate chain.

    Args:
        file_format (str): Format of the certificates ('pem' or 'der')
        certs (list): List of certificate file paths, ordered from root CA to end entity

    Returns:
        bool: True if the certificate chain is valid, False otherwise
    """
    cert = load_cert(file_format, certs[-1])
    if cert is None:
        return False

    if cert.issuer == cert.subject:
        cert.verify_directly_issued_by(cert)
        return verify_certificate(cert)
    else:
        if len(certs[:-1]) == 0:
            logger.info("Missing CA certificate")
            return False
        ca_cert = load_cert(file_format, certs[-2])
        if ca_cert is None:
            logger.info("CA Certificate not found")
            return False
        # Recursively verify the rest of the chain
        if verify_certificate_chain(file_format, certs[:-1]):
            cert.verify_directly_issued_by(ca_cert)
            return verify_certificate(cert, ca_cert)
        else:
            return False