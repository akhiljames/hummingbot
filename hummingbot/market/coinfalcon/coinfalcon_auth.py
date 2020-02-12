import hashlib
import hmac
import time
import json

COINFALCON_HOST = "https://beta.coinfalcon.com"


class CoinfalconAuth:

    def __init__(self, api_key: str, secret_key: str):
        self.hostname = COINFALCON_HOST
        self.api_key = api_key
        self.secret_key = secret_key

    def generate_api_headers(self, request_path, body={}, method="GET"):
        """
        Generate headers for a signed payload
        """
        timestamp = str(int(time.time()))
        signature = self._auth_sig(timestamp, request_path, body, method)

        return {
            "cf-api-key": self.api_key,
            "cf-api-timestamp": timestamp,
            "cf-api-signature": signature,
            "content-type": "application/json"
        }

    # private methods

    def _auth_sig(self, timestamp, request_path, body, method) -> str:
        auth_payload = "|".join([timestamp, method, request_path])
        if (method != "GET"):
            auth_payload = "|".join([auth_payload, json.dumps(body)])

        sig = hmac.new(self.secret_key.encode("utf8"),
                       auth_payload.encode("utf8"),
                       hashlib.sha256).hexdigest()
        return sig
