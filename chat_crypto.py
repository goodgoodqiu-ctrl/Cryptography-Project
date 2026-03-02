from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
import base64

class SecureChatSystem:
    def __init__(self):
        # 接收方生成 2048 位 RSA 密钥对
        self.rsa_key = RSA.generate(2048)
        self.public_key = self.rsa_key.publickey()

    def sender_encrypt_detailed(self, message: str):
        """发送方：返回详细的中间加密过程数据"""
        # 1. 生成一次性 AES 会话密钥 (明文)
        session_key = get_random_bytes(16)
        session_key_b64 = base64.b64encode(session_key).decode('utf-8')
        
        # 2. AES 加密原始消息
        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode('utf-8'))
        ciphertext_b64 = base64.b64encode(ciphertext).decode('utf-8')
        
        # 3. RSA 加密 AES 会话密钥
        cipher_rsa = PKCS1_OAEP.new(self.public_key)
        enc_session_key = cipher_rsa.encrypt(session_key)
        enc_session_key_b64 = base64.b64encode(enc_session_key).decode('utf-8')
        
        # 封装网络传输包
        packet = {
            "enc_session_key": enc_session_key_b64,
            "nonce": base64.b64encode(cipher_aes.nonce).decode('utf-8'),
            "tag": base64.b64encode(tag).decode('utf-8'),
            "ciphertext": ciphertext_b64
        }
        
        return session_key_b64, ciphertext_b64, enc_session_key_b64, packet

    def receiver_decrypt_detailed(self, data_packet: dict):
        """接收方：返回详细的中间解密过程数据"""
        enc_session_key = base64.b64decode(data_packet["enc_session_key"])
        nonce = base64.b64decode(data_packet["nonce"])
        # 直接读取 tag
        tag = base64.b64decode(data_packet["tag"]) 
        ciphertext = base64.b64decode(data_packet["ciphertext"])

        # 1. RSA 解密出 AES 会话密钥
        cipher_rsa = PKCS1_OAEP.new(self.rsa_key)
        session_key = cipher_rsa.decrypt(enc_session_key)
        recovered_session_key_b64 = base64.b64encode(session_key).decode('utf-8')

        # 2. AES 解密出原始消息
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce=nonce)
        decrypted_msg = cipher_aes.decrypt_and_verify(ciphertext, tag).decode('utf-8')
        
        return recovered_session_key_b64, decrypted_msg