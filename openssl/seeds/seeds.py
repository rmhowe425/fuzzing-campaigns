import os
import random
from pathlib import Path
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa

OUTPUT_DIR = Path("seeds")
OUTPUT_DIR.mkdir(exist_ok=True)

TLS_VERSIONS = [b"\x03\x00", b"\x03\x01", b"\x03\x02", b"\x03\x03", b"\x03\x04"]
CIPHERS = [b"\x00\x2f", b"\x00\x35", b"\x00\x0a", b"\x00\x05"]
EVP_NAMES = [b"AES-128-CBC", b"AES-256-CBC", b"SHA256", b"SHA384", b"DES", b"RC2", b"RC4", b"NULLCipher"]

def random_bytes(length):
    return bytes(random.randint(0, 255) for _ in range(length))

def generate_tls_client_hello():
    version = random.choice(TLS_VERSIONS)
    cipher = random.choice(CIPHERS)
    session_id = random_bytes(random.randint(0, 5))
    extensions = random_bytes(random.randint(0, 8))
    return b"\x16" + version + len(cipher + session_id + extensions).to_bytes(2, 'big') + b"\x01\x00" + len(cipher).to_bytes(1, 'big') + cipher + session_id + extensions

def generate_tls_server_hello():
    version = random.choice(TLS_VERSIONS)
    cipher = random.choice(CIPHERS)
    random_bytes_len = random.randint(0, 8)
    return b"\x16" + version + random_bytes(random_bytes_len)

def generate_truncated_handshake():
    length = random.randint(1, 10)
    return random_bytes(length)

def generate_evp_string():
    return random.choice(EVP_NAMES)

def generate_der_cert(filename):
    key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"Test")])
    cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(key.public_key()) \
        .serial_number(random.randint(1, 10000)) \
        .not_valid_before(datetime.utcnow()) \
        .not_valid_after(datetime.utcnow() + timedelta(days=1)) \
        .sign(key, hashes.SHA256())
    der_bytes = cert.public_bytes(serialization.Encoding.DER)
    with open(filename, "wb") as f:
        f.write(der_bytes)

# Generate 50 seeds
for i in range(50):
    seed_file = OUTPUT_DIR / f"seed_{i:02d}.bin"
    choice = random.randint(0, 4)
    if choice == 0:
        data = generate_tls_client_hello()
    elif choice == 1:
        data = generate_tls_server_hello()
    elif choice == 2:
        data = generate_truncated_handshake()
    elif choice == 3:
        data = generate_evp_string()
    else:
        generate_der_cert(seed_file)
        continue
    with open(seed_file, "wb") as f:
        f.write(data)

print(f"Generated 50 seed files in {OUTPUT_DIR.resolve()}")
