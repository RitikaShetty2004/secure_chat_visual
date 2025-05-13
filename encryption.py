from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad, unpad
import base64

def encrypt_aes(data, key):
    cipher = AES.new(key.ljust(16).encode(), AES.MODE_CBC, iv=b'1234567812345678')
    ct_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))
    return base64.b64encode(ct_bytes).decode()

def decrypt_aes(enc_data, key):
    cipher = AES.new(key.ljust(16).encode(), AES.MODE_CBC, iv=b'1234567812345678')
    pt = unpad(cipher.decrypt(base64.b64decode(enc_data)), AES.block_size)
    return pt.decode()

def encrypt_des(data, key):
    cipher = DES.new(key.ljust(8).encode(), DES.MODE_CBC, iv=b'12345678')
    ct_bytes = cipher.encrypt(pad(data.encode(), DES.block_size))
    return base64.b64encode(ct_bytes).decode()

def decrypt_des(enc_data, key):
    cipher = DES.new(key.ljust(8).encode(), DES.MODE_CBC, iv=b'12345678')
    pt = unpad(cipher.decrypt(base64.b64decode(enc_data)), DES.block_size)
    return pt.decode()
