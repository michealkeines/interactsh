from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Hash import SHA256
from Cryptodome.Cipher import AES
import requests
import base64
import uuid
import time

class Client:
    def __init__(
        self,
        correlation_id,
        secret_key,
        server_url,
        priv_key,
        token,
        correlation_id_len,
        correlation_id_nonce_len,
    ) -> None:
        self.correlation_id = correlation_id
        self.secret_key = secret_key
        self.server_url = server_url
        self.priv_key = priv_key
        self.token = token
        self.correlation_id_len = correlation_id_len
        self.correlation_id_nonce_len = correlation_id_nonce_len 
    
    def __init__(
        self,
        token
    ) -> None:
        self.correlation_id_len = 20
        self.correlation_id_nonce_len = 13
        temp = f'{uuid.uuid4()}'.split("-")

        self.correlation_id = f'{temp[-1]}{temp[-2]}{temp[-3]}'
        if len(self.correlation_id) > self.correlation_id_len:
            self.correlation_id = self.correlation_id[:self.correlation_id_len]
        self.secret_key = uuid.uuid4()
        self.server_url = "https://blackeye.icu"
        self.priv_key = None
        self.token = token
        

    def set_rsa_keys(self):
        if self.priv_key is None:
            private_key = RSA.generate(2048)
            pub_key = private_key.public_key()

            self.priv_key = private_key.export_key()
            self.pub_key = pub_key.export_key()

    def register(self):
        encoded = base64.b64encode(self.pub_key)
        print(encoded)
        print("\n\n")
        print(encoded.decode("ascii"))
        data = {
            "public-key": encoded.decode("ascii"),"secret-key": f'{self.secret_key}',
            "correlation-id": self.correlation_id
        }
        headers = {
            "Authorization": self.token
        }
        try:
            res = requests.post(
                url=f"{self.server_url}/register",
                json=data,
                verify=False,
                headers=headers
            )
            print(res.text)
            print("registered")
        except Exception as e:
            print(e)
            print("request failed")

    def check(self) -> dict:
        url = f'{self.server_url}/poll?id={self.correlation_id}&secret={self.secret_key}&check=test'
        print(url)
        headers = {
            "Authorization": self.token
        }

        try:
            res = requests.get(
                url=url,
                headers=headers,
                verify=False
            )
            print(res.text)
            print("polled")
            return res.json()
        except Exception as e:
            print(e)
            print("request failed")
            return {"error": "request failed"}

    def decrypt_response(self, value, key):
        decoded_key = base64.b64decode(key)
        priv_key = RSA.import_key(self.priv_key)
        ciper = PKCS1_OAEP.new(
            key=priv_key,
            hashAlgo=SHA256,
        )
        
        plain_key = ciper.decrypt(decoded_key)
        print("plain plain_key")
        print(plain_key)
        # https://stackoverflow.com/questions/35811119/aes-encryption-golang-and-python
        value = str(value)
        # We add back the padding ("=") here so that the decode won't fail.
        value = base64.b64decode(value + '=' * (4 - len(value) % 4), '-_')
        iv, value = value[:AES.block_size], value[AES.block_size:]

        # Python uses 8-bit segments by default for legacy reasons. In order to support
        # languages that encrypt using 128-bit segments, without having to use data with
        # a length divisible by 16, we need to pad and truncate the values.
        remainder = len(value) % 16
        padded_value = value + b'\0' * (16 - remainder) if remainder else value
        cipher = AES.new(plain_key, AES.MODE_CFB, iv, segment_size=128)
        # Return the decrypted string with the padding removed.
        decoded =  cipher.decrypt(padded_value)[:len(value)]

        print("decode final out")

        try:
            print(decoded.decode("utf-8"))
        except Exception as e:
            print(e)
            print("decod failed")
                 


temp_client = Client(token="152d88c7c6b428fc55fa8ccbb3eab085b8a7a6aca8c101a7d3258fc3badecb72")

temp_client.set_rsa_keys()

print(temp_client.priv_key)
print("\n\n")
print(temp_client.pub_key)
temp_client.register()

try:
    while True:
        time.sleep(4)
        out = temp_client.check()
        if "error" in out:
            print("no data in poll")
            continue
        temp_client.decrypt_response(
            value=out["encrypted_data"],
            key=out["key"]
        )
except KeyboardInterrupt:
    print("stopped polling")