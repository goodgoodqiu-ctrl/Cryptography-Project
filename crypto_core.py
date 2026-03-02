from phe import paillier

class IoTPrivacySystem:
    def __init__(self):
        # 边缘网关或云端生成公私钥对
        self.public_key, self.private_key = paillier.generate_paillier_keypair(n_length=1024)

    def encrypt_feature(self, value):
        """传感器端：使用公钥加密特征值"""
        return self.public_key.encrypt(value)

    def homomorphic_add(self, enc_a, enc_b):
        """密文加法：E(A) + E(B) = E(A + B)"""
        return enc_a + enc_b

    def homomorphic_sub(self, enc_a, enc_b):
        """密文减法：E(A) - E(B) = E(A - B)"""
        return enc_a - enc_b

    def homomorphic_mul(self, enc_a, scalar):
        """密文标量乘法：E(A) * k = E(A * k)"""
        return enc_a * scalar

    def decrypt_result(self, enc_result):
        """可信中心：私钥解密"""
        if enc_result is None:
            return None
        return self.private_key.decrypt(enc_result)