import hashlib
import hmac
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

def decrypt_data(input_b64, master_key_b64, salt_bytes, iterations):
    try:
        master_key_str = base64.b64decode(master_key_b64).decode('utf-8')
    except Exception as e:
        return f"Error: 마스터키 디코딩 실패 ({str(e)})"
    try:
        input_bytes = base64.b64decode(input_b64)
    except Exception as e:
        return f"Error: 대상 데이터 Base64 디코딩 실패 ({str(e)})"
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA1(),
        length=32 + 64,
        salt=salt_bytes,
        iterations=iterations,
        backend=default_backend()
    )
    derived_bytes = kdf.derive(master_key_str.encode('utf-8'))
    aes_key = derived_bytes[:32]
    auth_key = derived_bytes[32:]

    if len(input_bytes) < 48:
        return "Error: 데이터 길이가 유효하지 않습니다 (최소 48바이트 필요)."

    mac_received = input_bytes[:32]
    iv = input_bytes[32:48]
    ciphertext = input_bytes[48:]

    h = hmac.new(auth_key, input_bytes[32:], hashlib.sha256)
    mac_calculated = h.digest()
    
    if not hmac.compare_digest(mac_received, mac_calculated):
        return "Error: 무결성 검증 실패 (데이터가 변조되었거나 키가 일치하지 않음)"


    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    try:
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    except Exception as e:
        return f"Error: 복호화 처리 실패 ({str(e)})"

  
    unpadder = padding.PKCS7(128).unpadder()
    try:
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        return plaintext.decode('utf-8')
    except Exception as e:
        return f"복호화 성공(Binary 데이터): {padded_plaintext.hex()}"

for i,j in dic.items():
    result = decrypt_data(j, master_key_encoded, salt, iterations)
    print(f"{i} : {result}")
