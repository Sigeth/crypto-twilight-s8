"""
X.509 Certificate Signature Verification

This module provides functionality for verifying digital signatures on X.509 certificates
using RSA and ECDSA algorithms. It implements the cryptographic operations required to
validate that a certificate was properly signed by its issuer.

Functions:
    verify_cert_signature(mode, public_key, message, signature, hash_algorithm):
        Verifies a digital signature on certificate data using either RSA or ECDSA.

Dependencies:
    - cryptography: For hash functions and public key interfaces
    - ecpy: For elliptic curve operations

Supported Algorithms:
    - RSA with PKCS#1 v1.5 padding
    - ECDSA on various named curves

Note:
    This implementation performs the raw mathematical operations for signature
    verification rather than relying on higher-level cryptographic libraries.
"""

from src.math_utils import long_to_bytes, bytes_to_long, inverse
from src.der import decode_der_signature

from cryptography.hazmat.primitives.hashes import Hash
from ecpy.curves import Curve, Point


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
        n = curve.order
        G = curve.generator

        # Create a point from the public key coordinates
        Qa = Point(public_key.public_numbers().x, public_key.public_numbers().y, curve)

        # Decode the DER-encoded signature
        decoded_signature = decode_der_signature(signature)
        if decoded_signature is None:
            print("Malformed signature")
            return False
        r, s = decoded_signature

        # Perform ECDSA signature validation checks
        if not curve.is_on_curve(Qa):
            print("Wrong public key")
            return False
        if not 1 < r < (n - 1):
            print("Wrong signature")
            return False
        if not 1 < s < (n - 1):
            print("Wrong signature")
            return False

        # Calculate signature verification values
        u = inverse(s, n)
        u1 = (message_hash * u) % n
        u2 = (r * u) % n

        # Perform the ECDSA verification calculation
        P = u1 * G + u2 * Qa
        r1 = P.x % n

        return r1 == r

