import base64
import hashlib
import time
from typing import Dict
from urllib.parse import urlparse

import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


class EbayKey:
    def __init__(self, privateKey, publicKey, public_key_jwe, signingKeyId):
        self.privateKey = privateKey
        self.publicKey = publicKey
        self.public_key_jwe = public_key_jwe
        self.signingKeyId = signingKeyId


class SignatureService:
    def __init__(self, token: str) -> None:
        self.token = token
        self.signing_key = self.create_signing_key()

    @staticmethod
    def generate_content_digest(body: str) -> str:
        """
        Create the Content-Digest header value using SHA-256.
        """
        digest = hashlib.sha256(body.encode("utf-8")).digest()
        return base64.b64encode(digest).decode()

    def create_signing_key(self) -> EbayKey:
        """
        Generate a new signing key using the eBay Key Management API.
        """
        headers = {
            "Authorization": "Bearer " + self.token,
            "Content-Type": "application/json",
        }

        response = requests.post(
            "https://apiz.ebay.com/developer/key_management/v1/signing_key",
            headers=headers,
            data='{"signingKeyCipher": "RSA"}',
            timeout=10,
        )
        response.raise_for_status()
        key = response.json()

        print("eBay API Signing Key Generation")
        print("Private Key: " + key["privateKey"])
        print("Public Key: " + key["publicKey"])
        print("Public Key JWE: " + key["jwe"])
        print("Key ID: " + key["signingKeyId"])

        self.signing_key = EbayKey(
            privateKey=key["privateKey"],
            publicKey=key["publicKey"],
            public_key_jwe=key["jwe"],
            signingKeyId=key["signingKeyId"],
        )
        return self.signing_key

    def extract_rsa_private_key(self, der_private_key_str: str) -> rsa.RSAPrivateKey:
        """
        Extract the RSA private key object from the DER-encoded string.

        :param der_private_key_str: The private key in DER format, encoded as base64.
        :return: An `rsa.RSAPrivateKey` object.
        """
        # Decode the base64-encoded DER key
        der_private_key_bytes = base64.b64decode(der_private_key_str)

        # Load the private key using cryptography
        private_key = serialization.load_der_private_key(
            der_private_key_bytes, password=None, backend=default_backend()
        )

        # Ensure the key is an RSA key
        if isinstance(private_key, rsa.RSAPrivateKey):
            return private_key
        else:
            raise ValueError("The private key provided is not of type RSA.")

    def get_digital_signature(
        self,
        ebay_private_key: str,
        ebay_public_key_jwe: str,
        request_url: str,
        signature_params: str,
        content_digest: str,
        method: str = "POST",
    ) -> str:
        """
        Generate the digital signature using the details provided. The signature is created
        using RSASSA-PKCS1-v1_5.
        """
        url = urlparse(request_url)
        params = (
            f'"content-digest": sha-256=:{content_digest}:\n'
            f'"x-ebay-signature-key": {ebay_public_key_jwe}\n'
            f'"@method": {method}\n'
            f'"@path": {url.path}\n'
            f'"@authority": {url.netloc}\n'
            f'"@signature-params": {signature_params}'
        ).encode()

        # Extract the RSA private key object
        private_key = self.extract_rsa_private_key(ebay_private_key)

        # Sign the message using RSASSA-PKCS1-v1_5
        signature = private_key.sign(params, padding.PKCS1v15(), hashes.SHA256())

        # Return the encoded signature
        return base64.b64encode(signature).decode()

    def get_signature_dict(
        self, url: str, body: str = "", method: str = "POST"
    ) -> Dict:
        if not self.signing_key:
            raise ValueError(
                "No signing key available. Please create or set a signing key."
            )

        creation_time = int(time.time())
        content_digest = SignatureService.generate_content_digest(body) if body else ""
        signature_input = f'("content-digest" "x-ebay-signature-key" "@method" "@path" "@authority");created={creation_time}'
        signature = self.get_digital_signature(
            ebay_private_key=self.signing_key.privateKey,
            ebay_public_key_jwe=self.signing_key.public_key_jwe,
            request_url=url,
            signature_params=signature_input,
            content_digest=content_digest,
            method=method,
        )
        return {
            "Authorization": "Bearer " + self.token,
            "Signature-Input": f"sig1={signature_input}",
            "Signature": f"sig1=:{signature}:",
            "x-ebay-signature-key": self.signing_key.public_key_jwe,
            "content-digest": f"sha-256=:{content_digest}:",
        }
