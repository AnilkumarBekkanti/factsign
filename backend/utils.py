from Crypto.Cipher import AES
from base64 import b64encode, b64decode

# Must be 32 bytes for AES-256
SECRET_KEY = b'Qi"\x8cKl\xd9\x1d9A\xbaP9\xbd\xc9\x1b\xdb\xdba\x14\xee\xe0g\xd01\x12%\x92\xff\xf2.\x05'
BLOCK_SIZE = AES.block_size  # 16 bytes


def pad(data: bytes) -> bytes:
    padding = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([padding] * padding)


def unpad(data: bytes) -> bytes:
    return data[:-data[-1]]


# TEXT encryption (name, email, phone, etc.)
def encrypt_data(text: str) -> str:
    cipher = AES.new(SECRET_KEY, AES.MODE_ECB)
    padded = pad(text.encode())
    encrypted = cipher.encrypt(padded)
    return b64encode(encrypted).decode()  # return as base64 string


def decrypt_data(encrypted_text: str) -> str:
    cipher = AES.new(SECRET_KEY, AES.MODE_ECB)
    decrypted = cipher.decrypt(b64decode(encrypted_text))
    return unpad(decrypted).decode()


# FILE encryption (PDFs, etc.)
def encrypt_bytes(data: bytes) -> bytes:
    cipher = AES.new(SECRET_KEY, AES.MODE_ECB)
    return cipher.encrypt(pad(data))


def decrypt_bytes(encrypted_data: bytes) -> bytes:
    cipher = AES.new(SECRET_KEY, AES.MODE_ECB)
    return unpad(cipher.decrypt(encrypted_data))


def fix_base64_padding(data: str) -> str:
    """Fix padding issue with Base64 strings."""
    return data + '=' * (-len(data) % 4)


