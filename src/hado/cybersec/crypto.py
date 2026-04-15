"""
hado.cybersec.crypto — Hashing, encoding, and cryptographic utilities.

Incluye: MD5/SHA/HMAC, Base64, AES-256-GCM, RSA-2048/4096, tokens.
Importado automáticamente por el transpilador Python en operaciones cripto.

Dependencias opcionales:
  - cryptography >= 3.0 (para AES/RSA) — pip install cryptography
  Sin esta librería, las funciones hash/base64 siguen funcionando.
"""

from __future__ import annotations
import hashlib
import base64
import hmac
import os
import secrets
from typing import Tuple, Optional


# ─── Hashing ─────────────────────────────────────────────────────────────────

def hash_md5(text: str) -> str:
    """Calculate MD5 hash of a string. Not for security — use for checksums."""
    return hashlib.md5(text.encode()).hexdigest()


def hash_sha1(text: str) -> str:
    """Calculate SHA-1 hash of a string."""
    return hashlib.sha1(text.encode()).hexdigest()


def hash_sha256(text: str) -> str:
    """Calculate SHA-256 hash of a string."""
    return hashlib.sha256(text.encode()).hexdigest()


def hash_sha512(text: str) -> str:
    """Calculate SHA-512 hash of a string."""
    return hashlib.sha512(text.encode()).hexdigest()


def hash_bytes_sha256(data: bytes) -> str:
    """Calculate SHA-256 hash of raw bytes."""
    return hashlib.sha256(data).hexdigest()


# ─── Encoding ────────────────────────────────────────────────────────────────

def b64_encode(data: str) -> str:
    """Base64-encode a string."""
    return base64.b64encode(data.encode()).decode()


def b64_decode(data: str) -> str:
    """Decode a base64-encoded string."""
    return base64.b64decode(data.encode()).decode()


def b64_encode_bytes(data: bytes) -> str:
    """Base64-encode raw bytes."""
    return base64.b64encode(data).decode()


def b64_decode_bytes(data: str) -> bytes:
    """Decode base64 string to raw bytes."""
    return base64.b64decode(data.encode())


def hex_encode(data: bytes) -> str:
    """Encode bytes to hex string."""
    return data.hex()


def hex_decode(data: str) -> bytes:
    """Decode hex string to bytes."""
    return bytes.fromhex(data)


# ─── HMAC ────────────────────────────────────────────────────────────────────

def hmac_sha256(key: str, message: str) -> str:
    """Compute HMAC-SHA256 signature."""
    return hmac.new(key.encode(), message.encode(), hashlib.sha256).hexdigest()


def hmac_sha512(key: str, message: str) -> str:
    """Compute HMAC-SHA512 signature."""
    return hmac.new(key.encode(), message.encode(), hashlib.sha512).hexdigest()


def hmac_verify(key: str, message: str, signature: str, algorithm: str = 'sha256') -> bool:
    """Constant-time HMAC verification."""
    algos = {'sha256': hmac_sha256, 'sha512': hmac_sha512}
    fn = algos.get(algorithm.lower(), hmac_sha256)
    computed = fn(key, message)
    return hmac.compare_digest(computed, signature)


# ─── Token generation ────────────────────────────────────────────────────────

def generate_token(length: int = 32) -> str:
    """Generate a cryptographically secure random hex token."""
    return secrets.token_hex(length)


def generate_password(length: int = 16, symbols: bool = True) -> str:
    """Generate a random password of given length."""
    import string
    chars = string.ascii_letters + string.digits
    if symbols:
        chars += '!@#$%^&*()-_=+[]{}|;:,.<>?'
    return ''.join(secrets.choice(chars) for _ in range(length))


def verify_hash(text: str, expected: str, algorithm: str = "sha256") -> bool:
    """Verify that a text matches an expected hash."""
    algos = {
        "md5": hash_md5,
        "sha1": hash_sha1,
        "sha256": hash_sha256,
        "sha512": hash_sha512,
    }
    fn = algos.get(algorithm.lower())
    if fn is None:
        raise ValueError(f"Algoritmo no soportado: {algorithm}")
    return fn(text) == expected


# ─── AES-256-GCM (authenticated encryption) ──────────────────────────────────

def _get_cryptography():
    """Import cryptography lazily, raise clear error if not installed."""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.asymmetric import rsa, padding
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.backends import default_backend
        return True
    except ImportError:
        raise ImportError(
            "Librería 'cryptography' requerida para AES/RSA.\n"
            "Instalar: pip install cryptography"
        )


def aes_generate_key(bits: int = 256) -> bytes:
    """
    Genera una clave AES aleatoria segura.

    Args:
        bits: 128, 192, o 256 (default: 256)

    Returns:
        bytes de la clave (16, 24, o 32 bytes)

    Ejemplo:
        >>> key = aes_generate_key(256)
        >>> len(key)
        32
    """
    if bits not in (128, 192, 256):
        raise ValueError("AES key bits debe ser 128, 192, o 256")
    return os.urandom(bits // 8)


def aes_encrypt(plaintext: bytes, key: bytes, aad: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    """
    Encripta datos con AES-256-GCM (authenticated encryption).

    AES-GCM provee confidencialidad + autenticación + detección de tampering.
    Cada cifrado usa un nonce aleatorio de 12 bytes.

    Args:
        plaintext: datos a cifrar (bytes)
        key:       clave AES de 16/24/32 bytes (use aes_generate_key())
        aad:       Additional Authenticated Data opcional (no cifrado, pero autenticado)

    Returns:
        (nonce, ciphertext_with_tag) — ambos necesarios para descifrar
        El tag GCM (16 bytes) está concatenado al final del ciphertext.

    Ejemplo:
        >>> key = aes_generate_key()
        >>> nonce, ct = aes_encrypt(b'secreto', key)
        >>> plain = aes_decrypt(ct, key, nonce)
        >>> plain == b'secreto'
        True
    """
    _get_cryptography()
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96-bit nonce recommended for GCM
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
    return nonce, ciphertext


def aes_decrypt(ciphertext: bytes, key: bytes, nonce: bytes, aad: Optional[bytes] = None) -> bytes:
    """
    Descifra datos AES-256-GCM.

    Args:
        ciphertext: ciphertext + tag GCM (output de aes_encrypt)
        key:        clave AES (misma que usada en encrypt)
        nonce:      nonce (output de aes_encrypt)
        aad:        mismos Additional Authenticated Data (si se usaron)

    Returns:
        plaintext decifrado

    Raises:
        cryptography.exceptions.InvalidTag: si el ciphertext fue modificado (tampering)
    """
    _get_cryptography()
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, aad)


def aes_encrypt_string(text: str, key: bytes) -> str:
    """
    Encripta un string con AES-256-GCM. Retorna base64(nonce + ciphertext).

    Ejemplo:
        >>> key = aes_generate_key()
        >>> enc = aes_encrypt_string('secreto', key)
        >>> aes_decrypt_string(enc, key)
        'secreto'
    """
    nonce, ct = aes_encrypt(text.encode('utf-8'), key)
    combined = nonce + ct
    return base64.b64encode(combined).decode()


def aes_decrypt_string(encrypted_b64: str, key: bytes) -> str:
    """
    Descifra un string AES-256-GCM desde base64(nonce + ciphertext).
    """
    combined = base64.b64decode(encrypted_b64.encode())
    nonce = combined[:12]
    ct = combined[12:]
    return aes_decrypt(ct, key, nonce).decode('utf-8')


def aes_encrypt_file(input_path: str, output_path: str, key: bytes) -> None:
    """
    Encripta un archivo con AES-256-GCM.
    Output: 12-byte nonce + ciphertext+tag.
    """
    with open(input_path, 'rb') as f:
        data = f.read()
    nonce, ct = aes_encrypt(data, key)
    with open(output_path, 'wb') as f:
        f.write(nonce + ct)


def aes_decrypt_file(input_path: str, output_path: str, key: bytes) -> None:
    """
    Descifra un archivo encriptado con aes_encrypt_file.
    """
    with open(input_path, 'rb') as f:
        combined = f.read()
    nonce = combined[:12]
    ct = combined[12:]
    plaintext = aes_decrypt(ct, key, nonce)
    with open(output_path, 'wb') as f:
        f.write(plaintext)


# ─── RSA asymmetric encryption ────────────────────────────────────────────────

def rsa_generate_keypair(bits: int = 2048) -> Tuple[bytes, bytes]:
    """
    Genera un par de claves RSA (privada, pública) en formato PEM.

    Args:
        bits: 2048 (rápido) o 4096 (más seguro). Default: 2048.

    Returns:
        (private_key_pem, public_key_pem) como bytes

    Ejemplo:
        >>> priv, pub = rsa_generate_keypair(2048)
        >>> ct = rsa_encrypt(b'secreto', pub)
        >>> rsa_decrypt(ct, priv)
        b'secreto'
    """
    _get_cryptography()
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=bits,
        backend=default_backend()
    )

    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return priv_pem, pub_pem


def rsa_encrypt(plaintext: bytes, public_key_pem: bytes) -> bytes:
    """
    Encripta datos con RSA-OAEP-SHA256.

    Nota: RSA solo puede cifrar datos más pequeños que el tamaño de la clave.
    Para datos grandes, usar AES para el contenido y RSA para la clave AES.

    Args:
        plaintext:      datos a cifrar (máx ~190 bytes para RSA-2048)
        public_key_pem: clave pública en formato PEM

    Returns:
        ciphertext cifrado (bytes)
    """
    _get_cryptography()
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.backends import default_backend

    pub_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())
    return pub_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def rsa_decrypt(ciphertext: bytes, private_key_pem: bytes) -> bytes:
    """
    Descifra datos RSA-OAEP-SHA256.

    Args:
        ciphertext:      datos cifrados (output de rsa_encrypt)
        private_key_pem: clave privada en formato PEM

    Returns:
        plaintext original
    """
    _get_cryptography()
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.backends import default_backend

    priv_key = serialization.load_pem_private_key(
        private_key_pem, password=None, backend=default_backend()
    )
    return priv_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def rsa_sign(data: bytes, private_key_pem: bytes) -> bytes:
    """
    Firma datos con RSA-PSS-SHA256.

    Args:
        data:            datos a firmar
        private_key_pem: clave privada PEM

    Returns:
        firma en bytes
    """
    _get_cryptography()
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.backends import default_backend

    priv_key = serialization.load_pem_private_key(
        private_key_pem, password=None, backend=default_backend()
    )
    return priv_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


def rsa_verify(data: bytes, signature: bytes, public_key_pem: bytes) -> bool:
    """
    Verifica una firma RSA-PSS-SHA256.

    Returns:
        True si la firma es válida, False si no
    """
    _get_cryptography()
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.backends import default_backend
    from cryptography.exceptions import InvalidSignature

    pub_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())
    try:
        pub_key.verify(
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


def rsa_hybrid_encrypt(plaintext: bytes, public_key_pem: bytes) -> bytes:
    """
    Hybrid encryption: AES-256-GCM para datos + RSA-OAEP para clave AES.
    Permite cifrar datos de cualquier tamaño con RSA.

    Formato: [4 bytes len_encrypted_key][encrypted_aes_key][nonce][ciphertext]

    Args:
        plaintext:      datos a cifrar (cualquier tamaño)
        public_key_pem: clave pública RSA PEM

    Returns:
        bytes cifrados (auto-contenido, include encrypted AES key)

    Ejemplo:
        >>> priv, pub = rsa_generate_keypair()
        >>> enc = rsa_hybrid_encrypt(b'datos grandes...', pub)
        >>> rsa_hybrid_decrypt(enc, priv)
        b'datos grandes...'
    """
    import struct

    # 1. Generar clave AES temporal
    aes_key = aes_generate_key(256)

    # 2. Cifrar datos con AES-GCM
    nonce, aes_ct = aes_encrypt(plaintext, aes_key)

    # 3. Cifrar clave AES con RSA
    encrypted_key = rsa_encrypt(aes_key, public_key_pem)

    # 4. Empaquetar: len(enc_key) | enc_key | nonce | aes_ciphertext
    key_len = struct.pack('>I', len(encrypted_key))
    return key_len + encrypted_key + nonce + aes_ct


def rsa_hybrid_decrypt(ciphertext: bytes, private_key_pem: bytes) -> bytes:
    """
    Descifra datos cifrados con rsa_hybrid_encrypt.
    """
    import struct

    # 1. Leer tamaño de clave cifrada
    key_len = struct.unpack('>I', ciphertext[:4])[0]

    # 2. Extraer componentes
    encrypted_key = ciphertext[4: 4 + key_len]
    nonce = ciphertext[4 + key_len: 4 + key_len + 12]
    aes_ct = ciphertext[4 + key_len + 12:]

    # 3. Descifrar clave AES
    aes_key = rsa_decrypt(encrypted_key, private_key_pem)

    # 4. Descifrar datos
    return aes_decrypt(aes_ct, aes_key, nonce)


# ─── Utility: check availability ─────────────────────────────────────────────

def crypto_available() -> dict:
    """
    Verifica qué funciones criptográficas están disponibles.

    Returns:
        dict con disponibilidad de cada módulo
    """
    result = {
        "hashing": True,         # Always available (stdlib)
        "base64": True,          # Always available (stdlib)
        "hmac": True,            # Always available (stdlib)
        "aes_gcm": False,
        "rsa": False,
        "library": None,
    }
    try:
        import cryptography
        result["aes_gcm"] = True
        result["rsa"] = True
        result["library"] = f"cryptography {cryptography.__version__}"
    except ImportError:
        pass
    return result
