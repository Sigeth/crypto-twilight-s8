"""
DER-Encoded ECDSA Signature Decoder

This module provides a function to decode DER-encoded ECDSA signatures,
extracting the r and s components for cryptographic verification and processing.

Functions:
    decode_der_signature(sequence):
        Decodes a DER-encoded ECDSA signature and extracts its r and s components.

The function verifies that the given sequence follows the DER encoding format
for ECDSA signatures. It ensures proper structure and extracts the integer
values representing the r and s components.
"""

from src.math_utils import bytes_to_long


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
