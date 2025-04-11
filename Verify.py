import sys, requests, os
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.x509.ocsp import OCSPRequestBuilder, load_der_ocsp_response
from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID

def load_cert(path, fmt):
    with open(path, 'rb') as f:
        data = f.read()
    return x509.load_pem_x509_certificate(data, default_backend()) if fmt.lower() == 'pem' else x509.load_der_x509_certificate(data, default_backend())

def get_url(cert, oid, access_method=None):
    for ext in cert.extensions:
        if ext.oid == oid:
            if oid == ExtensionOID.AUTHORITY_INFORMATION_ACCESS:
                for desc in ext.value:
                    if desc.access_method == access_method:
                        return desc.access_location.value
            elif oid == ExtensionOID.CRL_DISTRIBUTION_POINTS:
                for point in ext.value:
                    if point.full_name:
                        return point.full_name[0].value
    return None

def get_issuer(cert):
    url = get_url(cert, ExtensionOID.AUTHORITY_INFORMATION_ACCESS, AuthorityInformationAccessOID.CA_ISSUERS)
    if url:
        try:
            resp = requests.get(url, timeout=10)
            temp = "issuer.tmp"
            with open(temp, "wb") as f:
                f.write(resp.content)
            try:
                with open(temp, 'rb') as f:
                    return x509.load_der_x509_certificate(f.read(), default_backend())
            except:
                with open(temp, 'rb') as f:
                    return x509.load_pem_x509_certificate(f.read(), default_backend())
            finally:
                os.remove(temp)
        except:
            pass
    return None

def check_ocsp(cert, issuer):
    url = get_url(cert, ExtensionOID.AUTHORITY_INFORMATION_ACCESS, AuthorityInformationAccessOID.OCSP)
    if url and issuer:
        try:
            req = OCSPRequestBuilder().add_certificate(cert, issuer, hashes.SHA1()).build()
            resp = requests.post(url, data=req.public_bytes(default_backend()), headers={'Content-Type': 'application/ocsp-request'})
            if resp.status_code == 200:
                ocsp_resp = load_der_ocsp_response(resp.content)
                return {"status": ocsp_resp.certificate_status.name}
        except Exception as e:
            pass
    return None
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import requests

# Dossier pour stocker les CRLs téléchargées
CACHE_DIR = "crl_cache"

def check_crl(cert):
    # S'assurer que le dossier de cache existe
    if not os.path.exists(CACHE_DIR):
        os.makedirs(CACHE_DIR)
    
    url = get_url(cert, x509.ExtensionOID.CRL_DISTRIBUTION_POINTS)
    if not url:
        return None
    
    # Utiliser le numéro de série du certificat comme nom de fichier
    cache_filename = f"crl_{cert.serial_number}.der"
    cache_path = os.path.join(CACHE_DIR, cache_filename)
    
    # Vérifier si on a déjà cette CRL en cache
    crl = None
    if os.path.exists(cache_path):
        try:
            # Charger la CRL du cache
            with open(cache_path, "rb") as f:
                crl = x509.load_der_x509_crl(f.read(), default_backend())
        except Exception:
            # Si erreur lors du chargement, on considère que le cache est invalide
            os.remove(cache_path)
            crl = None
    
    # Si pas en cache, télécharger la CRL
    if crl is None:
        try:
            resp = requests.get(url, timeout=10)
            with open(cache_path, "wb") as f:
                f.write(resp.content)
            with open(cache_path, "rb") as f:
                crl = x509.load_der_x509_crl(f.read(), default_backend())
        except Exception:
            return None
    
    # Vérifier si le certificat est révoqué
    for revoked in crl:
        if revoked.serial_number == cert.serial_number:
            return {"status": "REVOKED"}
    return {"status": "GOOD"}

def main():
    if len(sys.argv) !=  3:
        print("Usage: python script.py <pem|der> <cert_path>")
        return

    try:
        cert = load_cert(sys.argv[2], sys.argv[1])
        print(f"Certificat: {cert.subject.rfc4514_string()}")
        
        # OCSP check
        issuer = get_issuer(cert)
        if issuer:
            ocsp_result = check_ocsp(cert, issuer)
            if ocsp_result:
                print(f"OCSP: {ocsp_result['status']}")
                return
        
        # CRL check
        crl_result = check_crl(cert)
        if crl_result:
            print(f"CRL: {crl_result['status']}")
            return
        
        print("Impossible de vérifier le statut")
    except Exception as e:
        print(f"Erreur: {e}")

if __name__ == "__main__":
    main()