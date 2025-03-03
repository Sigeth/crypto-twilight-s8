"""
Mathematical Utilities for Cryptography

This module provides pure Python implementations of essential mathematical functions
used in cryptographic operations, eliminating dependencies on external cryptographic
libraries like pycryptodome.

Functions:
    bytes_to_long(byte_array):
        Converts a byte string to an integer using big-endian byte order.

    long_to_bytes(n, blocksize=0):
        Converts an integer to a byte string using big-endian byte order.

    inverse(a, m):
        Calculates the modular multiplicative inverse using the extended Euclidean algorithm.

These functions are particularly useful for implementing cryptographic operations like
RSA, ECDSA, and other public key cryptosystems where conversions between bytes and
integers are common, as well as modular arithmetic operations.

Note:
    While these implementations are functionally equivalent to those found in
    cryptographic libraries, they are not necessarily constant-time and should be
    used with caution in security-sensitive contexts.
"""

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

