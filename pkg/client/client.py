from Cryptodome.PublicKey import RSA
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

    def check(self):
        url = f'{self.server_url}/poll?id={self.correlation_id}&secret={self.secret_key}&check=test'

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
        except Exception as e:
            print(e)
            print("request failed")


temp_client = Client(token="43ccfd520d55deaf1a037e6bafb577d5f41c93b38156870022b2d8c2120250ae")

temp_client.set_rsa_keys()

print(temp_client.priv_key)
print("\n\n")
print(temp_client.pub_key)
temp_client.register()

try:
    while True:
        time.sleep(4)
        temp_client.check()
except KeyboardInterrupt:
    print("stopped polling")