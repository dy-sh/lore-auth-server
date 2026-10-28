"""Signing key, JWKS and JWT minting/verification."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import time
import uuid
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from .config import Config
from .store import User


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def _int_b64(n: int) -> str:
    return _b64(n.to_bytes((n.bit_length() + 7) // 8, "big"))


class TokenError(Exception):
    pass


class TokenExpired(TokenError):
    pass


class TokenIssuer:
    """Issues RS256 JWTs in the shape Lore clients and loreserver expect."""

    def __init__(self, config: Config):
        self.config = config
        self._key = self._load_or_create_key(config.signing_key_path)
        public = self._key.public_key()
        der = public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        self.kid = _b64(hashlib.sha256(der).digest()[:12])
        numbers = public.public_numbers()
        self.jwks = {
            "keys": [
                {
                    "kty": "RSA",
                    "kid": self.kid,
                    "use": "sig",
                    "alg": "RS256",
                    "n": _int_b64(numbers.n),
                    "e": _int_b64(numbers.e),
                }
            ]
        }

    @staticmethod
    def _load_or_create_key(path: Path) -> rsa.RSAPrivateKey:
        if path.exists():
            key = serialization.load_pem_private_key(path.read_bytes(), password=None)
            if not isinstance(key, rsa.RSAPrivateKey):
                raise ValueError(f"{path} is not an RSA private key")
            return key
        path.parent.mkdir(parents=True, exist_ok=True)
        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        pem = key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(pem)
        return key

    def _sign(self, claims: dict) -> str:
        header = {"alg": "RS256", "typ": "JWT", "kid": self.kid}
        signing_input = _b64(json.dumps(header, separators=(",", ":")).encode()) + "." + _b64(
            json.dumps(claims, separators=(",", ":")).encode()
        )
        signature = self._key.sign(signing_input.encode(), padding.PKCS1v15(), hashes.SHA256())
        return signing_input + "." + _b64(signature)

    def _base_claims(self, user: User, ttl_seconds: int) -> dict:
        now = int(time.time())
        return {
            "iss": self.config.issuer,
            # The audience doubles as the list of domains a Lore client may
            # send the token to, so it must name the Lore server host.
            "aud": self.config.audience,
            "sub": user.name,
            "name": user.display_name,
            "preferred_username": user.name,
            "is_service_account": False,
            "iat": now,
            "exp": now + ttl_seconds,
            "jti": uuid.uuid4().hex,
        }

    def user_token(self, user: User) -> tuple[str, int]:
        """Authentication (identity) token. Returns the token and its expiry."""
        claims = self._base_claims(user, self.config.user_token_ttl_hours * 3600)
        return self._sign(claims), claims["exp"]

    def access_token(self, user: User, resources: list[dict]) -> tuple[str, int]:
        """Authorization token scoped to repositories, carried in the `resources` claim."""
        claims = self._base_claims(user, self.config.access_token_ttl_minutes * 60)
        claims["resources"] = resources
        return self._sign(claims), claims["exp"]

    def verify(self, token: str) -> dict:
        try:
            header_b64, claims_b64, signature_b64 = token.split(".")
            header = json.loads(_b64_decode(header_b64))
            claims = json.loads(_b64_decode(claims_b64))
            signature = _b64_decode(signature_b64)
        except ValueError as e:  # also covers JSON, base64 and UTF-8 decoding errors
            raise TokenError("malformed token") from e
        if not isinstance(header, dict) or not isinstance(claims, dict):
            raise TokenError("malformed token")
        if header.get("alg") != "RS256" or header.get("kid") != self.kid:
            raise TokenError("token was not issued by this service")
        try:
            self._key.public_key().verify(
                signature,
                f"{header_b64}.{claims_b64}".encode(),
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
        except InvalidSignature as e:
            raise TokenError("bad token signature") from e
        if claims.get("iss") != self.config.issuer:
            raise TokenError("unexpected issuer")
        if int(claims.get("exp", 0)) < time.time():
            raise TokenExpired("token expired")
        return claims
