"""OIDC authorization-code + PKCE client for enterprise identity providers."""

import json
import logging
import secrets
from urllib.parse import urlencode

import httpx
import jwt

from app.core.config import settings

logger = logging.getLogger("rtip.oidc")
ALLOWED_ID_TOKEN_ALGORITHMS = ("RS256", "RS384", "RS512", "ES256", "ES384", "ES512")


class OIDCService:
    def __init__(self) -> None:
        self.enabled = settings.OIDC_ENABLED
        self.issuer_url = (settings.OIDC_ISSUER_URL or "").rstrip("/")
        self.client_id = settings.OIDC_CLIENT_ID or ""
        self.client_secret = settings.OIDC_CLIENT_SECRET or ""
        self.redirect_uri = settings.OIDC_REDIRECT_URI or ""
        self.scopes = settings.OIDC_SCOPES
        self._provider_metadata: dict | None = None

    async def get_metadata(self) -> dict:
        if self._provider_metadata:
            return self._provider_metadata
        if not self.issuer_url:
            raise ValueError("OIDC issuer is not configured")
        if settings.ENVIRONMENT == "production" and not self.issuer_url.startswith("https://"):
            raise ValueError("OIDC discovery must use HTTPS in production")

        discovery_url = f"{self.issuer_url}/.well-known/openid-configuration"
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
            response = await client.get(discovery_url)
            response.raise_for_status()
            metadata = response.json()

        if metadata.get("issuer", "").rstrip("/") != self.issuer_url:
            raise ValueError("OIDC discovery issuer does not match configured issuer")
        for endpoint_name in ("authorization_endpoint", "token_endpoint", "userinfo_endpoint", "jwks_uri"):
            endpoint = metadata.get(endpoint_name)
            if not endpoint or not endpoint.startswith(("https://", "http://")):
                raise ValueError(f"OIDC discovery is missing a valid {endpoint_name}")
            if settings.ENVIRONMENT == "production" and not endpoint.startswith("https://"):
                raise ValueError(f"OIDC {endpoint_name} must use HTTPS in production")

        self._provider_metadata = metadata
        return metadata

    async def get_authorization_url(
        self,
        *,
        state: str,
        nonce: str,
        code_challenge: str,
    ) -> str:
        metadata = await self.get_metadata()
        params = {
            "client_id": self.client_id,
            "response_type": "code",
            "scope": self.scopes,
            "redirect_uri": self.redirect_uri,
            "state": state,
            "nonce": nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        separator = "&" if "?" in metadata["authorization_endpoint"] else "?"
        return f"{metadata['authorization_endpoint']}{separator}{urlencode(params)}"

    async def _verify_id_token(
        self,
        raw_id_token: str,
        *,
        expected_nonce: str,
        metadata: dict,
        client: httpx.AsyncClient,
    ) -> dict:
        header = jwt.get_unverified_header(raw_id_token)
        algorithm = header.get("alg")
        if algorithm not in ALLOWED_ID_TOKEN_ALGORITHMS or not header.get("kid"):
            raise ValueError("OIDC ID token uses an unsupported signing algorithm or key")

        jwks_response = await client.get(metadata["jwks_uri"])
        jwks_response.raise_for_status()
        jwks = jwks_response.json().get("keys", [])
        matching_jwk = next(
            (
                key
                for key in jwks
                if key.get("kid") == header["kid"]
                and key.get("use", "sig") == "sig"
                and key.get("alg", algorithm) == algorithm
            ),
            None,
        )
        if matching_jwk is None:
            raise ValueError("OIDC signing key was not found in the provider JWKS")
        key = jwt.algorithms.get_default_algorithms()[algorithm].from_jwk(json.dumps(matching_jwk))
        claims = jwt.decode(
            raw_id_token,
            key=key,
            algorithms=[algorithm],
            audience=self.client_id,
            issuer=metadata["issuer"],
            leeway=60,
            options={
                "require": ["exp", "iat", "iss", "aud", "sub", "nonce"],
            },
        )
        if not secrets.compare_digest(str(claims["nonce"]), expected_nonce):
            raise ValueError("OIDC nonce mismatch")
        return claims

    async def exchange_code_for_user_info(
        self,
        code: str,
        *,
        nonce: str,
        code_verifier: str,
    ) -> dict | None:
        """Exchange a one-use code and validate issuer, signature, audience, nonce and email."""
        try:
            metadata = await self.get_metadata()
            async with httpx.AsyncClient(timeout=15.0, follow_redirects=False) as client:
                token_response = await client.post(
                    metadata["token_endpoint"],
                    data={
                        "grant_type": "authorization_code",
                        "code": code,
                        "redirect_uri": self.redirect_uri,
                        "code_verifier": code_verifier,
                    },
                    auth=(self.client_id, self.client_secret),
                    headers={"Accept": "application/json"},
                )
                token_response.raise_for_status()
                tokens = token_response.json()
                raw_id_token = tokens.get("id_token")
                access_token = tokens.get("access_token")
                if not raw_id_token or not access_token:
                    raise ValueError("OIDC token response did not contain required tokens")

                id_claims = await self._verify_id_token(
                    raw_id_token,
                    expected_nonce=nonce,
                    metadata=metadata,
                    client=client,
                )
                userinfo_response = await client.get(
                    metadata["userinfo_endpoint"],
                    headers={"Authorization": f"Bearer {access_token}"},
                )
                userinfo_response.raise_for_status()
                userinfo = userinfo_response.json()

                if not userinfo.get("sub") or userinfo["sub"] != id_claims["sub"]:
                    raise ValueError("OIDC UserInfo subject does not match the ID token")
                email = userinfo.get("email")
                if not email or userinfo.get("email_verified") is not True:
                    raise ValueError("OIDC provider did not return a verified email claim")

                return {
                    "email": email.lower().strip(),
                    "full_name": userinfo.get("name") or userinfo.get("given_name"),
                    "sub": str(id_claims["sub"]),
                    "issuer": metadata["issuer"],
                }
        except Exception:  # noqa: BLE001 — don't leak provider tokens or claims to logs
            logger.warning("OIDC authorization-code exchange or token validation failed")
            return None


oidc_service = OIDCService()
