"""
Certificate verification module.

This module provides functions to verify X.509 certificates without relying on
external cryptographic libraries like pycryptodome. It implements the necessary
cryptographic functions in pure Python.
"""

from datetime import datetime as dt
from datetime import timezone

from cryptography import x509
from cryptography.hazmat.primitives.hashes import Hash

from ecpy.curves import Curve, Point


def bytes_to_long(byte_array):
    """
    Convert a byte string to an integer.

    Args:
        byte_array (bytes): Bytes to convert

    Returns:
        int: Integer representation of the byte array (big-endian)
    """
    return int.from_bytes(byte_array, byteorder='big')


def long_to_bytes(n, blocksize=0):
    """
    Convert an integer to a byte string.

    Args:
        n (int): Integer to convert
        blocksize (int, optional): Minimum size of the resulting byte string

    Returns:
        bytes: Byte representation of the integer (big-endian)
    """
    # Calculate minimum bytes needed to represent the number
    byte_length = (n.bit_length() + 7) // 8

    # Use blocksize if it's specified and larger than the calculated length
    if blocksize > 0 and byte_length < blocksize:
        byte_length = blocksize

    return n.to_bytes(byte_length, byteorder='big')


def inverse(a, m):
    """
    Calculate the modular multiplicative inverse of 'a' modulo 'm'.

    Args:
        a (int): Number to find the inverse for
        m (int): Modulus

    Returns:
        int: Modular multiplicative inverse of 'a'

    Raises:
        ValueError: If the modular inverse doesn't exist
    """
    if m == 1:
        return 0

    # Extended Euclidean Algorithm to find modular inverse
    def extended_gcd(a, b):
        """
        Extended Euclidean Algorithm to find GCD and coefficients.

        Returns (gcd, x, y) such that a*x + b*y = gcd
        """
        if a == 0:
            return b, 0, 1
        else:
            gcd, x, y = extended_gcd(b % a, a)
            return gcd, y - (b // a) * x, x

    # Ensure a is positive and less than m
    a = a % m

    gcd, x, y = extended_gcd(a, m)

    if gcd != 1:
        raise ValueError("Modular inverse does not exist")
    else:
        return x % m


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


def decode_der_signature(sequence):
    """
    Decode a DER-encoded ECDSA signature.

    Args:
        sequence (bytes): DER-encoded signature

    Returns:
        tuple: (r, s) components of the signature or None if invalid
    """
    # Verify this is a sequence
    if sequence[0] != 0x30:
        return None

    sequence_length = sequence[1]

    # Parse the r component
    r_sequence = sequence[2:]
    if r_sequence[0] != 0x02:  # r should be an integer
        return None

    r_integer_length = r_sequence[1]
    r = bytes_to_long(r_sequence[2:r_integer_length + 2])

    # Parse the s component
    s_sequence = r_sequence[r_integer_length + 2:]
    if s_sequence[0] != 0x02:  # s should be an integer
        return None

    s_integer_length = s_sequence[1]
    s = bytes_to_long(s_sequence[2:s_integer_length + 2])

    return r, s


def verify_cert_signature(mode, public_key, message, signature, hash_algorithm):
    """
    Verify a certificate signature.

    Args:
        mode (str): Signature algorithm type ('RSA' or 'ECDSA')
        public_key: Public key object from the cryptography library
        message (bytes): The message that was signed (TBS certificate bytes)
        signature (bytes): The signature to verify
        hash_algorithm: Hash algorithm used for the signature

    Returns:
        bool: True if the signature is valid, False otherwise
    """
    # Calculate the hash of the message
    hash_obj = Hash(hash_algorithm)
    hash_obj.update(message)
    message_hash = bytes_to_long(hash_obj.finalize())

    if mode == "RSA":
        # Extract RSA public key parameters
        e, n = public_key.public_numbers().e, public_key.public_numbers().n
        s = bytes_to_long(signature)

        # SHA-256 ASN.1 header used in RSA PKCS#1v1.5 signatures
        sha256_header = bytes.fromhex("3031300d060960864801650304020105000420")

        # Verify the signature using RSA
        signature_to_verify = long_to_bytes(pow(s, e, n))
        message_to_verify = long_to_bytes(message_hash % n)

        # Find the padding boundary and extract the actual signature
        start_of_signature = signature_to_verify.find(b"\x00", 1)
        signature_to_verify = signature_to_verify[start_of_signature + 1:]

        return signature_to_verify == sha256_header + message_to_verify
    else:  # ECDSA
        # Get curve parameters
        curve = Curve.get_curve(public_key.public_numbers().curve.name)
        n = curve._domain["order"]
        G = curve._domain["generator"]

        # Create a point from the public key coordinates
        Qa = Point(public_key.public_numbers().x, public_key.public_numbers().y, curve)

        # Decode the DER-encoded signature
        r, s = decode_der_signature(signature)

        # Perform ECDSA signature validation checks
        if not curve.is_on_curve(Qa):
            return False
        if not 1 < r < (n - 1):
            return False
        if not 1 < s < (n - 1):
            return False

        # Calculate signature verification values
        u = inverse(s, n)
        u1 = (message_hash * u) % n
        u2 = (r * u) % n

        # Perform the ECDSA verification calculation
        P = u1 * G + u2 * Qa
        r1 = P.x % n

        return r1 == r


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


def view_certificate(file_format: str, certs):
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
        if view_certificate(file_format, certs[:-1]):
            cert.verify_directly_issued_by(ca_cert)
            return verify_certificate(cert, ca_cert)
        else:
            return False