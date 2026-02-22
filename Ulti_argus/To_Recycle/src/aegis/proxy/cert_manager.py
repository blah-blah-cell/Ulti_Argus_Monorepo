import os
import datetime
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

class CertificateAuthority:
    def __init__(self, cert_dir="certs"):
        self.cert_dir = cert_dir
        self.ca_key_path = os.path.join(cert_dir, "argus_root_ca.key")
        self.ca_cert_path = os.path.join(cert_dir, "argus_root_ca.crt")
        os.makedirs(cert_dir, exist_ok=True)
        
        if not os.path.exists(self.ca_key_path):
            self._generate_root_ca()
        else:
            self._load_root_ca()

    def _generate_root_ca(self):
        print("[*] Generating new Root CA...")
        self.key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"IN"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Karnataka"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Argus AI Security"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"Argus Root CA"),
        ])
        
        self.cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            self.key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=3650)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True,
        ).sign(self.key, hashes.SHA256())
        
        # Save to disk
        with open(self.ca_key_path, "wb") as f:
            f.write(self.key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))
            
        with open(self.ca_cert_path, "wb") as f:
            f.write(self.cert.public_bytes(serialization.Encoding.PEM))
            
        print(f"[*] Root CA saved to {self.cert_dir}")

    def _load_root_ca(self):
        print("[*] Loading existing Root CA...")
        with open(self.ca_key_path, "rb") as f:
            self.key = serialization.load_pem_private_key(f.read(), password=None)
        with open(self.ca_cert_path, "rb") as f:
            self.cert = x509.load_pem_x509_certificate(f.read())
            
    def get_ca_cert_path(self):
        return self.ca_cert_path

if __name__ == "__main__":
    ca = CertificateAuthority()
