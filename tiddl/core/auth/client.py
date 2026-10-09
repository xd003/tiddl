import base64
import json
import logging
from os import environ
from requests import request
from typing import Any, TypeAlias

from tiddl.core.auth.exceptions import AuthClientError

log = logging.getLogger("tiddl")


DEFAULT_CLIENT_ID, DEFAULT_CLIENT_SECRET = (
    base64.b64decode(
        "NE4zbjZRMXg5NUxMNUs3cDtvS09YZkpXMzcxY1g2eGFaMFB5aGdHTkJkTkxsQlpkNEFLS1lvdWdNamlrPQ=="
    )
    .decode()
    .split(";")
)


def get_auth_credentials() -> tuple[str, str]:
    ENV_KEY = "TIDDL_AUTH"

    client_id, client_secret = DEFAULT_CLIENT_ID, DEFAULT_CLIENT_SECRET

    env_value = environ.get(ENV_KEY, None)

    if env_value:
        client_id, client_secret = env_value.split(";")

    log.debug(f"{client_id=}, {bool(env_value)=}")

    return client_id, client_secret


AUTH_URL = "https://auth.tidal.com/v1/oauth2"
CLIENT_ID, CLIENT_SECRET = get_auth_credentials()


def granted_scope(refresh_token: str, requested_scope: str) -> str:
    """Narrow ``requested_scope`` to the scopes ``refresh_token`` was issued with.

    TIDAL rejects a refresh that asks for any scope the original grant lacked
    (e.g. ``w_sub`` for a token issued as ``r_usr w_usr``), so requesting a fixed
    superset breaks tokens minted by other clients. The grant is read from the
    token's JWT ``scope`` claim; an undecodable token keeps the requested scope.
    """
    try:
        payload = refresh_token.split(".")[1]
        claims = json.loads(
            base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
        )
        granted = set(str(claims["scope"]).split())
    except Exception:
        return requested_scope

    scopes = [s for s in requested_scope.split("+") if s in granted]
    return "+".join(scopes) if scopes else requested_scope


JSON: TypeAlias = dict[str, Any]


class AuthClient:

    def __init__(
        self,
        client_id: str = CLIENT_ID,
        client_secret: str = CLIENT_SECRET,
        refresh_with_basic_auth: bool = True,
        refresh_scope: str = "r_usr+w_usr+w_sub",
    ) -> None:
        self.auth_url = AUTH_URL
        self.client_id = client_id
        self.client_secret = client_secret
        self.refresh_with_basic_auth = refresh_with_basic_auth
        self.refresh_scope = refresh_scope

    def get_device_auth(self) -> JSON:
        res = request(
            "POST",
            f"{self.auth_url}/device_authorization",
            data={"client_id": self.client_id, "scope": "r_usr+w_usr+w_sub"},
        )

        res.raise_for_status()

        return res.json()

    def get_auth(self, device_code: str) -> JSON:
        res = request(
            "POST",
            f"{self.auth_url}/token",
            data={
                "client_id": self.client_id,
                "device_code": device_code,
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "scope": "r_usr+w_usr+w_sub",
            },
            auth=(self.client_id, self.client_secret),
        )

        json_data = res.json()

        if res.status_code != 200:
            raise AuthClientError(**json_data)

        return json_data

    def refresh_token(self, refresh_token: str) -> JSON:
        data = {
            "client_id": self.client_id,
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
            "scope": granted_scope(refresh_token, self.refresh_scope),
        }

        if self.refresh_with_basic_auth:
            res = request(
                "POST",
                f"{self.auth_url}/token",
                data=data,
                auth=(self.client_id, self.client_secret),
            )
        else:
            data["client_secret"] = self.client_secret
            res = request(
                "POST",
                f"{self.auth_url}/token",
                data=data,
            )

        res.raise_for_status()

        return res.json()

    def logout_token(self, access_token: str) -> None:
        res = request(
            "POST",
            "https://api.tidal.com/v1/logout",
            headers={"authorization": f"Bearer {access_token}"},
        )

        res.raise_for_status()
