import hashlib
from cryptography.hazmat.primitives.serialization import load_der_x509_certificate
from cryptography.hazmat.primitives import hashes

def sha256_fingerprint_der(der_bytes: bytes) -> str :
    try:
        cert = load_der_x509_certificate(der_bytes)
        return cert.fingerprint(hashes.SHA256()).hex()
    except Exception:
        return hashlib.sha256(der_bytes).hexdigest()