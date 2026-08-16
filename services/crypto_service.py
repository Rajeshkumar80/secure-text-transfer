# Wraps DH.py (key math) + AES-CBC (random IV) into three functions:
#   derive_key(my_private, their_public) -> 32-hex-char AES key
#   encrypt_file(input_path, key, output_path) -> output path (IV prepended, base64)
#   decrypt_file(input_path, key, output_path) -> output path
#
# This is the port of the desktop engine (stand-alone-application/thrain.py +
# ENCDEC.AESCipher) into the Flask backend. Route handlers call these
# functions; no crypto logic lives inside app.py.
import base64
import os
import uuid

from Crypto import Random
from Crypto.Cipher import AES

import DH

BS = 16


def _pad(s):
    """PKCS#7 pad a byte-string to a multiple of the AES block size."""
    return s + (BS - len(s) % BS) * chr(BS - len(s) % BS).encode()


def _unpad(s):
    """Strip the PKCS#7 padding from a decrypted byte-string."""
    return s[:-ord(s[len(s)-1:])]


class AESCipher(object):
    """AES-CBC with a random 16-byte IV generated per message.

    The IV is prepended to the ciphertext before base64-encoding and
    stripped on decrypt. Never reuse an IV with CBC.
    """

    def __init__(self, key):
        self.key = key

    def encrypt(self, message):
        message = message.encode()
        raw = _pad(message)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key.encode("utf8"), AES.MODE_CBC, iv)
        enc = iv + cipher.encrypt(raw)
        return base64.b64encode(enc).decode('utf-8')

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key.encode("utf8"), AES.MODE_CBC, iv)
        dec = cipher.decrypt(enc[AES.block_size:])
        return _unpad(dec).decode('utf-8')


def derive_key(my_private, their_public):
    """Diffie-Hellman shared secret -> 32-hex-char AES key.

    Mirrors the desktop engine's derivation exactly (thrain.py):
    DH.generate_secret (SHA-256 of the shared secret) is hex-encoded and
    truncated to its first 32 characters.
    """
    secret = DH.generate_secret(int(my_private), int(their_public))
    return secret.encode("utf-8").hex()[0:32]


def encrypt_file(input_path, key, output_path=None):
    """Encrypt a text file with AES-CBC. Returns the output path."""
    if output_path is None:
        output_path = _scratch_path('.txt')
    with open(input_path, "r") as file_obj:
        message = file_obj.read()
    ciphertext = AESCipher(key).encrypt(message)
    with open(output_path, "w") as file_obj:
        file_obj.write(ciphertext)
    return output_path


def decrypt_file(input_path, key, output_path=None):
    """Decrypt a text file with AES-CBC. Returns the output path."""
    if output_path is None:
        output_path = _scratch_path('.txt')
    with open(input_path, "r") as file_obj:
        message = file_obj.read()
    plaintext = AESCipher(key).decrypt(message)
    with open(output_path, "w") as file_obj:
        file_obj.write(plaintext)
    return output_path


def _scratch_path(ext):
    """A unique, non-persistent path under the OS temp directory."""
    import tempfile
    return os.path.join(tempfile.gettempdir(), str(uuid.uuid4()) + ext)