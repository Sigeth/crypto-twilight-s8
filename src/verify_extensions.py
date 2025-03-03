"""
X.509 Certificate Validation Module

This module provides utility functions for validating X.509 certificates according
to standard PKI requirements. It focuses specifically on verifying certificate
extensions that control how certificates can be used within a PKI hierarchy.

Functions:
    verify_key_usage(cert, ca_cert=None):
        Verifies that a certificate has the appropriate key usage extensions set.

    verify_basic_constraints(cert, ca_cert=None):
        Verifies that a certificate has the appropriate basic constraints extension set.

Usage:
    For CA certificates: Pass only the CA certificate to either function.
    For end-entity certificates: Pass both the end-entity certificate and its issuing CA.
"""

from cryptography import x509


def verify_key_usage(cert, ca_cert=None):
    """
    Verify the key usage extension of a certificate.

    Args:
        cert (x509.Certificate): Certificate to verify
        ca_cert (x509.Certificate, optional): CA certificate that issued 'cert'

    Returns:
        bool: True if key usage is valid, False otherwise
    """
    key_usage_extension = cert.extensions.get_extension_for_class(x509.extensions.KeyUsage)

    if ca_cert is None:
        # For CA certificates, check if they can sign certificates and CRLs
        return key_usage_extension.value.key_cert_sign and key_usage_extension.value.crl_sign
    else:
        # For end-entity certificates, check if the CA can sign and the cert has digital signature
        ca_key_usage_extension = ca_cert.extensions.get_extension_for_class(x509.extensions.KeyUsage)
        if not ca_key_usage_extension.value.key_cert_sign or not ca_key_usage_extension.value.crl_sign:
            return False
        return key_usage_extension.value.digital_signature


def verify_basic_constraints(cert, ca_cert=None):
    """
    Verify the basic constraints extension of a certificate.

    Args:
        cert (x509.Certificate): Certificate to verify
        ca_cert (x509.Certificate, optional): CA certificate that issued 'cert'

    Returns:
        bool: True if basic constraints are valid, False otherwise
    """
    if ca_cert is None:
        # For CA certificates, check if the CA flag is set
        basic_constraints_extension = cert.extensions.get_extension_for_class(
            x509.extensions.BasicConstraints
        )
        return basic_constraints_extension.value.ca
    else:
        # For CA certificates that issued 'cert', verify the CA flag is set
        ca_basic_constraints_extension = ca_cert.extensions.get_extension_for_class(
            x509.extensions.BasicConstraints
        )
        return ca_basic_constraints_extension.value.ca
