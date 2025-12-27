# Same as Linux version, but with Windows path handling
import os
import sys
import json
import logging
from flask import Flask, request, jsonify
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
import datetime

# Windows-specific path handling
if sys.platform == "win32":
    certs_dir = os.path.join(os.getcwd(), "data", "certs")
    os.makedirs(certs_dir, exist_ok=True)

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class RootCA:
    def __init__(self):
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.certificate = self.generate_self_signed_cert()
        self.issued_certs = {}
        
        # Save certificate to Windows filesystem
        if sys.platform == "win32":
            cert_path = os.path.join(certs_dir, "root_ca.pem")
            with open(cert_path, "wb") as f:
                f.write(self.certificate.public_bytes(serialization.Encoding.PEM))
            logging.info(f"Root CA certificate saved to: {cert_path}")
    
    def generate_self_signed_cert(self):
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Michigan"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Detroit"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "V2X-SCMS"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Root CA"),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            self.private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365*10)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=2),
            critical=True
        ).sign(self.private_key, hashes.SHA256())
        
        return cert

root_ca = RootCA()

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "healthy", "platform": sys.platform, "service": "Root CA"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)