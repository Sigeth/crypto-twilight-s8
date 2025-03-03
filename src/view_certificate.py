from datetime import datetime as dt
from datetime import timezone

from cryptography import x509
from cryptography.hazmat.primitives.hashes import Hash

from Crypto.Util.number import bytes_to_long, long_to_bytes, inverse

from ecpy.curves import Curve, Point

def load_cert(file_format, file_name):
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
    key_usage_extension = cert.extensions.get_extension_for_class(x509.extensions.KeyUsage)

    if ca_cert is None:
        return key_usage_extension.value.key_cert_sign and key_usage_extension.value.crl_sign
    else:
        ca_key_usage_extension = ca_cert.extensions.get_extension_for_class(x509.extensions.KeyUsage)
        if not ca_key_usage_extension.value.key_cert_sign or not ca_key_usage_extension.value.crl_sign:
            return False
        return key_usage_extension.value.digital_signature

def verify_basic_constraints(cert, ca_cert=None):
    if ca_cert is None:
        basic_constraints_extension = cert.extensions.get_extension_for_class(x509.extensions.BasicConstraints)
        return basic_constraints_extension.value.ca
    else:
        ca_basic_constraints_extension = ca_cert.extensions.get_extension_for_class(x509.extensions.BasicConstraints)
        return ca_basic_constraints_extension.value.ca

def decode_der_signature(sequence):
    # we should have only one sequence
    if sequence[0] != 0x30:
        return None
    sequence_length = sequence[1]

    r_sequence = sequence[2:]
    # r should be an integer
    if r_sequence[0] != 0x02:
        return None

    r_integer_length = r_sequence[1]
    r = bytes_to_long(r_sequence[2:r_integer_length+2])

    s_sequence = r_sequence[r_integer_length+2:]
    # s should be an integer
    if s_sequence[0] != 0x02:
        return None

    s_integer_length = s_sequence[1]
    s = bytes_to_long(s_sequence[2:s_integer_length+2])

    return r, s

def verify_cert_signature(mode, public_key, message, signature, hash_algorithm):
    H = Hash(hash_algorithm)
    H.update(message)
    H = bytes_to_long(H.finalize())

    if mode == "RSA":
        e, n = public_key.public_numbers().e, public_key.public_numbers().n
        s = bytes_to_long(signature)
        sha256_header = bytes.fromhex("3031300d060960864801650304020105000420")

        signature_to_verify = long_to_bytes(pow(s, e, n))
        message_to_verify = long_to_bytes(H % n)
        start_of_signature = signature_to_verify.find(b"\x00", 1)
        signature_to_verify = signature_to_verify[start_of_signature+1:]
        return signature_to_verify == sha256_header + message_to_verify
    else:
        curve = Curve.get_curve(public_key.public_numbers().curve.name)
        n = curve._domain["order"]
        G = curve._domain["generator"]
        Qa = Point(public_key.public_numbers().x, public_key.public_numbers().y, curve)
        r, s = decode_der_signature(signature)

        if not curve.is_on_curve(Qa):
            return False
        if not 1 < r < (n - 1):
            return False
        if not 1 < s < (n-1):
            return False

        u = inverse(s, n)

        u1 = (H * u) % n
        u2 = (r * u) % n

        P = u1 * G + u2 * Qa
        r1 = P.x % n
        return r1 == r

def verify_certificate(cert, ca_cert=None):
    if not verify_key_usage(cert, ca_cert):
        print("Invalid Key Usage")
        return False

    if not verify_basic_constraints(cert, ca_cert):
        print("Invalid Basic Constraints")
        return False

    if dt.now(timezone.utc) < cert.not_valid_before_utc or dt.now(timezone.utc) > cert.not_valid_after_utc:
        print("Certificate expired")
        return False

    algo_cert = cert.signature_algorithm_oid

    if algo_cert.dotted_string in ["1.2.840.113549.1.1.11", "1.2.840.10045.4.3.3", "1.2.840.10045.4.3.2"]:
        if ca_cert is None:
            pub_key = cert.public_key()
        else:
            pub_key = ca_cert.public_key()
        signature = cert.signature

        if algo_cert.dotted_string == "1.2.840.113549.1.1.11": # RSA
            return verify_cert_signature("RSA", pub_key, cert.tbs_certificate_bytes, signature, cert.signature_hash_algorithm)
        else: #ECDSA
            return verify_cert_signature("ECDSA", pub_key, cert.tbs_certificate_bytes, signature, cert.signature_hash_algorithm)
    else:
        print("Unsupported Algorithm")
        print(cert.signature_algorithm_oid)
        return False

def view_certificate(file_format: str, certs):
    cert = load_cert(file_format, certs[-1])
    if cert is None:
        return False
    if cert.issuer == cert.subject:
        cert.verify_directly_issued_by(cert)
        return verify_certificate(cert)
    else:
        ca_cert = load_cert(file_format, certs[-2])
        if ca_cert is None:
            print("CA Certificate not found")
            return False
        if view_certificate(file_format, certs[:-1]):
            cert.verify_directly_issued_by(ca_cert)
            return verify_certificate(cert, ca_cert)
        else:
            return False