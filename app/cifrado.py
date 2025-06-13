from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import secrets

def generar_clave_chacha():
    return secrets.token_bytes(32)

def cifrar_clave(clave: bytes, llave_publica_pem: str) -> bytes:
    llave_publica = RSA.import_key(llave_publica_pem.encode())
    rsa = PKCS1_OAEP.new(llave_publica)
    clave_cifrada = rsa.encrypt(clave)

    return clave_cifrada

def descifrar_clave(clave_cifrada: bytes, llave_privada_pem: str) -> bytes:
    llave_privada = RSA.import_key(llave_privada_pem.encode())
    rsa = PKCS1_OAEP.new(llave_privada)
    clave_descifrada = rsa.decrypt(clave_cifrada)
    
    return clave_descifrada
