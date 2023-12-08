from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP, PKCS1_v1_5


class easyRSA:
    def session_key(self):
        key = RSA.generate(1024)
        private_key = key.export_key()
        public_key = key.publickey().export_key()

        return public_key.decode('utf-8'), private_key.decode('utf-8')

    def session_encrypted(self, data, session_public_key):
        public_key = RSA.import_key(session_public_key)
        cipher_rsa = PKCS1_v1_5.new(public_key)
        data_encrypted = cipher_rsa.encrypt(data)

        return data_encrypted.hex()

    def session_decrypted(self, data_encrypted, session_private_key):
        private_key = RSA.import_key(session_private_key)
        cipher_rsa = PKCS1_v1_5.new(private_key)
        data_decrypted = cipher_rsa.decrypt(data_encrypted, None)

        return data_decrypted.decode("utf-8")

    def encrypt(self, secret_code, oriText):
        key = RSA.generate(2048)

        encrypted_key = key.export_key(passphrase=secret_code, pkcs=8,
                                       protection="scryptAndAES128-CBC")

        public_key = key.publickey().export_key()

        recipient_key = RSA.import_key(public_key)
        session_key = get_random_bytes(16)
        cipher_rsa = PKCS1_OAEP.new(recipient_key)
        enc_session_key = cipher_rsa.encrypt(session_key)

        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(
            oriText.encode("utf-8"))

        res_dict = {
            "public_key": public_key,
            "private_encrypted": encrypted_key,
            "enc_session_key": enc_session_key,
            "secret_code": secret_code,
            "nonce": cipher_aes.nonce,
            "tag": tag,
            "ciphertext_bin": ciphertext,
            "ciphertext_hex": ciphertext.hex(),
        }

        return res_dict

    def decrypt(self, encrypted_key, secret_code, nonce, enc_session_key, ciphertext, tag):
        private_key = RSA.import_key(encrypted_key, passphrase=secret_code)
        cipher_rsa = PKCS1_OAEP.new(private_key)
        session_key = cipher_rsa.decrypt(enc_session_key)
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        res = cipher_aes.decrypt_and_verify(ciphertext, tag)

        return res.decode('utf-8')
