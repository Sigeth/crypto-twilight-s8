"""
Certificate verification module.

This module provides functions to verify X.509 certificates without relying on
external cryptographic libraries like pycryptodome. It implements the necessary
cryptographic functions in pure Python.
"""

from src.verify_extensions import verify_key_usage, verify_basic_constraints
from src.verify_sig import verify_cert_signature

from datetime import datetime as dt
from datetime import timezone

from cryptography import x509


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
        print("Invalid Key Usage")
        return False

    # Check basic constraints
    if not verify_basic_constraints(cert, ca_cert):
        print("Invalid Basic Constraints")
        return False

    # Check validity period
    current_time = dt.now(timezone.utc)
    if current_time < cert.not_valid_before_utc or current_time > cert.not_valid_after_utc:
        print("Certificate expired")
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

        # Verify signature based on algorithm type
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
        print("Unsupported Algorithm")
        print(cert.signature_algorithm_oid)
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
    # Load the certificate to verify (last in the chain)
    cert = load_cert(file_format, certs[-1])
    if cert is None:
        return False

    # Check if it's a self-signed certificate
    if cert.issuer == cert.subject:
        cert.verify_directly_issued_by(cert)
        return verify_certificate(cert)
    else:
        # Load the issuing CA certificate
        ca_cert = load_cert(file_format, certs[-2])
        if ca_cert is None:
            print("CA Certificate not found")
            return False

        # Recursively verify the rest of the chain
        if verify_certificate_chain(file_format, certs[:-1]):
            cert.verify_directly_issued_by(ca_cert)
            return verify_certificate(cert, ca_cert)
        else:
            return False