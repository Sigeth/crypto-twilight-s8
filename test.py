import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.ocsp import OCSPRequestBuilder, load_der_ocsp_response
from cryptography.hazmat.primitives import hashes

linkCRL = "http://crl.globalsign.com/root-r3.crl" #changer par la val dans le certif
CertifNumber = 161802333825783230223370087730291711713
linkOCSP = "http://ocsp2.globalsign.com/rootr3"

def DownloadCertifs(link, nom_fichier="./certs/CRL/test.crl"):
    try:
        response = requests.get(link, timeout=10)
        response.raise_for_status()
        with open(nom_fichier, "wb") as f:
            f.write(response.content)
        print(f"✅ Certificat téléchargé et enregistré sous '{nom_fichier}'")
    except requests.exceptions.RequestException as e:
        print(f"❌ Erreur lors du téléchargement : {e}")

def showCRL(file):
    lstSerial = []
    try:
        with open(file, "rb") as f:
            crl_data = f.read()
        crl = x509.load_der_x509_crl(crl_data, default_backend())
        print(f"CRL marche le sang")
        print(f"Date : {crl.last_update}")
        print(f"CA : {crl.issuer}")
        for revoked_cert in crl:
            print(f"\nCertificat révoqué :")
            print(f"N° : {revoked_cert.serial_number}")
            lstSerial.append(revoked_cert.serial_number)
    except Exception as e:
        print(f"Erreur: {e}")
    return lstSerial

def verifCertif(listeCrl, serial_number):
    if serial_number in listeCrl:
        return True
    return False

def VerifOCSP(ocsp_url, cert_path, issuer_path):
    try:
        # Charger le certificat et l'émetteur
        with open(cert_path, 'rb') as f:
            cert_data = f.read()
            cert = x509.load_pem_x509_certificate(cert_data, default_backend())
        
        with open(issuer_path, 'rb') as f:
            issuer_data = f.read()
            issuer = x509.load_pem_x509_certificate(issuer_data, default_backend())
        
        # Créer la requête OCSP
        builder = OCSPRequestBuilder()
        builder = builder.add_certificate(cert, issuer, hashes.SHA1())
        req = builder.build()
        
        # Envoyer la requête OCSP
        headers = {'Content-Type': 'application/ocsp-request'}
        response = requests.post(ocsp_url, data=req.public_bytes(default_backend()), headers=headers)
        
        if response.status_code != 200:
            return f"Erreur HTTP: {response.status_code}"
        
        # Analyser la réponse
        ocsp_response = load_der_ocsp_response(response.content)
        return {
            "status": ocsp_response.certificate_status.name,
            "this_update": ocsp_response.this_update,
            "next_update": ocsp_response.next_update,
            "revocation_time": ocsp_response.revocation_time if ocsp_response.revocation_time else None,
            "revocation_reason": ocsp_response.revocation_reason.name if ocsp_response.revocation_reason else None
        }
        
    except Exception as e:
        return f"Erreur lors de la vérification OCSP: {str(e)}"

resultat = VerifOCSP(linkOCSP, "./.pem", "emetteur.pem")
print(resultat)