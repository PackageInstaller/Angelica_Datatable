from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
import gzip
import json

def decrypt_file(encrypted_file_path):

    key = "LhqMEhM2JGfKGVek46hzwUH7jhtGx5J3"

    with open(encrypted_file_path, 'rb') as f:
        encrypted_data = f.read()

    iv = encrypted_data[16:32] # IV
    encrypted_content = encrypted_data[32:-16]
    salt = encrypted_data[-16:] # 盐

    key = PBKDF2(
        key.encode('utf-8'), 
        salt,
        dkLen=16,  # AES-128
        count=1010,
        hmac_hash_module=SHA256
    )

    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(encrypted_content)
    padding_length = decrypted_data[-1]
    decrypted_data = decrypted_data[:-padding_length]
    decompressed_data = gzip.decompress(decrypted_data)
    json_data = json.loads(decompressed_data)
    formatted_json = json.dumps(json_data, indent=4, ensure_ascii=False)


    with open('MasterData.json', 'w', encoding='utf-8') as f:
        f.write(formatted_json)


def main():
    import sys

    input_file = sys.argv[1]
    
    decrypt_file(input_file)

if __name__ == "__main__":
    main()