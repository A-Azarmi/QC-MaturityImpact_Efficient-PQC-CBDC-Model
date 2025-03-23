
from flask import Flask, render_template, request, send_file, redirect, url_for, flash
import requests
import os
import json
from getpass import getpass
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag, InvalidSignature
import base64

app = Flask(__name__)
app.secret_key = 'supersecretkey'

# IPFS credentials 
KALEIDO_IPFS_URL = "https://u1wfyxxsla-u1h8msgwdl-ipfs.us1-azure.kaleido.io"
IPFS_USERNAME = "User"  
IPFS_PASSWORD = "Pass"

def upload_to_ipfs(file_path):
    # Upload a file to  IPFS and return the IPFS hash
    try:
        with open(file_path, "rb") as file:
            files = {"file": file}
            response = requests.post(
                f"{KALEIDO_IPFS_URL}/api/v0/add",
                auth=(IPFS_USERNAME, IPFS_PASSWORD),  # Basic Auth with username and password
                files=files,
            )
            response.raise_for_status()  # Raise an error for bad status codes
            ipfs_data = response.json()
            return ipfs_data["Hash"]
    except Exception as e:
        print(f"Error uploading to IPFS: {e}")
        raise

def save_ipfs_metadata(ipfs_hash, metadata_file="IPFSmetadata.json"):
    # Save the IPFS hash to a metadata file
    metadata = {"ipfs_hash": ipfs_hash}
    with open(metadata_file, "w") as f:
        json.dump(metadata, f)

def fetch_from_ipfs(ipfs_hash, output_file="encryptedAuthData.enc"):
    # Fetch a file from IPFS using its hash
    try:
        response = requests.post(
            f"{KALEIDO_IPFS_URL}/api/v0/cat?arg={ipfs_hash}",
            auth=(IPFS_USERNAME, IPFS_PASSWORD),  # Use Basic Auth with username and password
        )
        response.raise_for_status()
        with open(output_file, "wb") as f:
            f.write(response.content)
    except Exception as e:
        print(f"Error fetching from IPFS: {e}")
        raise

# Mock ZK-STARK Prover/Verifier
class MockZKProver:
    @staticmethod
    def generate_proof(password: str, salt: bytes) -> str:
        return f"mock_proof:{password}:{base64.b64encode(salt).decode()}"

class MockZKVerifier:
    @staticmethod
    def verify_proof(proof: str, salt: bytes) -> bool:
        return proof.startswith("mock_proof")

def derive_aes_key(password: str, salt: bytes, iterations=100000):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def generate_rsa_key(filename="TempCustodiedRSAKey.pem"):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(filename, "wb") as f:
        f.write(pem)
    return private_key

def removePlainKey(filename="TempCustodiedRSAKey.pem"):
    try:
        os.remove(filename)
        return True
    except FileNotFoundError:
        return False

def wrap_rsa_key(private_key, password: str, output_file="WrappedRSACustodykey.json"):
    salt = os.urandom(16)
    iv = os.urandom(12)
    aes_key = derive_aes_key(password, salt)
    
    proof = f"mock_proof:{password}:{base64.b64encode(salt).decode()}"
    proof_bytes = proof.encode("utf-8")
    
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    encryptor = Cipher(algorithms.AES(aes_key), modes.GCM(iv), backend=default_backend()).encryptor()
    ciphertext = encryptor.update(private_bytes) + encryptor.finalize()
    
    wrapped_data = {
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "salt": base64.b64encode(salt).decode(),
        "iv": base64.b64encode(iv).decode(),
        "tag": base64.b64encode(encryptor.tag).decode(),
    }
    with open(output_file, "w") as f:
        json.dump(wrapped_data, f)
    
    with open("eKYCPubKey.pem", "rb") as key_file:
        ekyc_public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    
    encrypted_proof = ekyc_public_key.encrypt(
        proof_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    with open("encryptedAuthData.enc", "wb") as f:
        f.write(encrypted_proof)
    
    return wrapped_data

def unwrap_rsa_key_zk(wrapped_file="WrappedRSACustodykey.json") -> rsa.RSAPrivateKey:
    with open(wrapped_file, "r") as f:
        wrapped_data = json.load(f)
    
    with open("eKYCKey.pem", "rb") as key_file:
        ekyc_private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    
    with open("encryptedAuthData.enc", "rb") as f:
        encrypted_proof = f.read()
    
    try:
        decrypted_proof = ekyc_private_key.decrypt(
            encrypted_proof,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
        raise ValueError("Failed to decrypt proof")
    
    try:
        proof_parts = decrypted_proof.split(b":")
        if len(proof_parts) != 3:
            raise ValueError("Invalid proof format")
        
        password = proof_parts[1].decode("utf-8")
        salt = base64.b64decode(proof_parts[2])
    except Exception as e:
        raise ValueError("Failed to parse proof")
    
    if not MockZKVerifier.verify_proof(decrypted_proof.decode("utf-8", errors="ignore"), salt):
        raise ValueError("ZK-STARK proof verification failed")
    
    aes_key = derive_aes_key(password, salt)
    iv = base64.b64decode(wrapped_data["iv"])
    tag = base64.b64decode(wrapped_data["tag"])
    ciphertext = base64.b64decode(wrapped_data["ciphertext"])
    
    decryptor = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()
    decrypted = decryptor.update(ciphertext) + decryptor.finalize()
    
    try:
        return serialization.load_pem_private_key(decrypted, password=None, backend=default_backend())
    except Exception as e:
        raise ValueError("Failed to load private key")
    
def sign_data(private_key, data: bytes = b"signTEST") -> bytes:
    return private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def verify_signature(public_key, signature: bytes, data: bytes = b"signTEST") -> bool:
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False

def save_unwrapped_key(private_key, filename="UnwrappedRSAKey.pem"):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(filename, "wb") as f:
        f.write(pem)
    return filename

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/generate_key', methods=['POST'])
def generate_key():
    private_key = generate_rsa_key()
    flash("RSA key generated successfully.")
    return redirect(url_for('index'))

@app.route('/wrap_key', methods=['POST'])
def wrap_key():
    password = request.form['password']
    private_key = generate_rsa_key()
    wrapped_data = wrap_rsa_key(private_key, password)

    # Upload encryptedAuthData to IPFS
    try:
        ipfs_hash = upload_to_ipfs("encryptedAuthData.enc")
        save_ipfs_metadata(ipfs_hash)
        flash(f"RSA key wrapped successfully. Encrypted data uploaded to IPFS with hash: {ipfs_hash}")
    except Exception as e:
        flash(f"Error uploading to IPFS: {str(e)}")

    return redirect(url_for('index'))

@app.route('/unwrap_key', methods=['POST'])
def unwrap_key():
    try:
        # Fetch IPFS metadata to get the hash
        with open("IPFSmetadata.json", "r") as f:
            metadata = json.load(f)
            ipfs_hash = metadata["ipfs_hash"]

        # Fetch encryptedAuthData.enc from IPFS
        fetch_from_ipfs(ipfs_hash)

        # Unwrap the RSA key
        unwrapped_key = unwrap_rsa_key_zk()
        signature = sign_data(unwrapped_key)
        public_key = unwrapped_key.public_key()
        is_valid = verify_signature(public_key, signature)

        if is_valid:
            filename = save_unwrapped_key(unwrapped_key)
            flash("RSA key unwrapped and verified successfully.")
            return send_file(filename, as_attachment=True)
        else:
            flash("Signature verification failed.")
            return redirect(url_for('index'))
    except Exception as e:
        flash(f"Error: {str(e)}")
        return redirect(url_for('index'))

@app.route('/download/<filename>')
def download(filename):
    flash("RSA key unwrapped and verified successfully.")
    return send_file(filename, as_attachment=True)

if __name__ == '__main__':
    app.run(host='0.0.0.0')