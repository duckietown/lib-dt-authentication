import copy
import datetime
import json
import os
from typing import Dict, Union, List, Optional

import requests
from base58 import b58decode, b58encode
# noinspection PyProtectedMember
from ecdsa import NIST192p
from ecdsa.keys import VerifyingKey, BadSignatureError, SigningKey

from .exceptions import InvalidToken, ExpiredToken, GenericException, NotARenewableToken
from .scope import Scope

PUBLIC_KEYS = {
    # dt1 was introduced in 2017
    "dt1": """-----BEGIN PUBLIC KEY-----
MEkwEwYHKoZIzj0CAQYIKoZIzj0DAQEDMgAEQr/8RJmJZT+Bh1YMb1aqc2ao5teE
ixOeCMGTO79Dbvw5dGmHJLYyNPwnKkWayyJS
-----END PUBLIC KEY-----""",
    # dt2 was introduced in May 2023
    "dt2": """-----BEGIN PUBLIC KEY-----
MEkwEwYHKoZIzj0CAQYIKoZIzj0DAQEDMgAEHIqMBPGB2tzRgrMKhQSkEiKQ317q
msEAqq1CS86oV1vjHYVq6FLvtnDsuWzbW2Nz
-----END PUBLIC KEY-----"""
}
DATETIME_FORMAT = {
    "dt1": "%Y-%m-%d",
    "dt2": "%Y-%m-%d/%H:%M"
}

PAYLOAD_FIELDS = {"uid", "exp"}
CURVE = NIST192p
SUPPORTED_VERSIONS = ["dt1", "dt2"]
SUPPORTED_FIELDS = {
    "dt1": [],
    "dt2": ["scope", "data", "duration"],
}
DEFAULT_VERSION = "dt2"


ScopeList = List[Union[Scope, str]]
DEFAULT_SCOPE = [Scope(action="auth")]

TOKEN_RENEW_ONLINE_HOST = os.environ.get("DT_TOKEN_RENEW_HOST", "hub.duckietown.com")
TOKEN_RENEW_ONLINE_URL = f"https://{TOKEN_RENEW_ONLINE_HOST}/api/v1/auth/token/renew"


class DuckietownToken(object):
    """
    Class modeling a Duckietown Token.

    Args:
        payload:    The token's payload as a dictionary.
        signature:  The token's signature.
    """

    def __init__(self, version: str, payload: Dict[str, Union[str, int]], signature: Union[str, bytes]):
        """
        Creates a Duckietown Token from a payload and a signature.

        Most users will create instances of this class using the method
        :py:method:`dt_authentication.DuckietownToken.from_string` instead of instantiating this
        class directly.

        :param version:     A string indicating the version of the token
        :param payload:     A dictionary containing the token payload
        :param signature:   A signature, either as a base58 encoded string or as raw bytes
        """
        self._version: str = version
        self._payload: Dict[str, Union[str, int, list]] = payload
        self._signature: bytes = signature if isinstance(signature, (bytes,)) else b58decode(signature)

    @property
    def version(self) -> str:
        """
        The version of this token
        """
        return self._version

    @property
    def payload(self) -> Dict[str, object]:
        """
        The token's payload.
        """
        return copy.copy(self._payload)

    @property
    def signature(self) -> bytes:
        """
        The token's signature.
        """
        return copy.copy(self._signature)

    @property
    def uid(self) -> int:
        """
        The ID of the user the token belongs to.
        """
        return self._payload['uid']

    @property
    def scope(self) -> List[Scope]:
        """
        The scope of this token.
        """
        scope = self._payload.get("scope", DEFAULT_SCOPE)
        return [(s if isinstance(s, Scope) else Scope.parse(s)) for s in scope]

    @property
    def data(self) -> Optional[dict]:
        """
        The data baked into the token.
        """
        return self._payload.get("data", None)

    @property
    def duration(self) -> Optional[int]:
        """
        The duration of the token in minutes.
        """
        return self._payload.get("duration", None)

    @property
    def renewable(self) -> bool:
        """
        Whether the token can be renewed.
        """
        return self.duration is not None

    @property
    def expiration(self) -> Optional[datetime.datetime]:
        """
        The token's expiration date.
        """
        if self._payload['exp'] is None:
            return None
        return datetime.datetime.strptime(self._payload['exp'], DATETIME_FORMAT[self._version])

    @property
    def expired(self) -> bool:
        """ Whether the token is already expired """
        exp: Optional[datetime.date] = self.expiration
        if exp is None:
            # never-expiring tokens
            return False
        # compare now() with token expiration date
        return exp < datetime.datetime.utcnow()

    def as_string(self) -> str:
        """
        Returns the Duckietown Token string.
        """
        # encode payload into JSON
        payload_json: str = self.payload_as_json()
        # encode payload and signature
        payload_base58: str = b58encode(payload_json).decode("utf-8")
        signature_base58: str = b58encode(self._signature).decode("utf-8")
        # compile token
        return f"{self._version}-{payload_base58}-{signature_base58}"

    def payload_as_json(self, sort_keys: bool = True, **kwargs) -> str:
        """
        The token's payload as JSON string.
        """
        # get a copy of the payload dictionary
        payload = copy.deepcopy(self._payload)
        # replace parsed scope
        scope: List[Union[str, dict]] = [s.compact() for s in self.scope]
        if "scope" in SUPPORTED_FIELDS[self.version]:
            payload["scope"] = scope
        # encode payload into JSON
        return json.dumps(payload, sort_keys=sort_keys, **kwargs)

    def grants(self, action: str, resource: Optional[str] = None, identifier: Optional[str] = None,
               service: Optional[str] = None) -> bool:
        """
        Checks whether this token grants the given scope.

        :param action:      Action of the scope to check for
        :param resource:    Resource of the scope to check for
        :param identifier:  Resource identifier of the scope to check for
        :param service:     Service of the scope to check for
        :return:            'True' if this token grants this scope, 'False' otherwise.
        """
        for s in self.scope:
            if s.grants(action, resource, identifier, service):
                return True
        return False

    def renew(self, key: Optional[SigningKey] = None, in_place: bool = False) -> 'DuckietownToken':
        """
        Renews this token using the given signing key or by reaching out to the remote Duckietown auth
        service if no keys are given.

        :param key:         (Optional) Signing key to use to sign the new token.
        :param in_place:    Update this very instance with the new token.
        :return:            A new token with the same scope and duration of the old one.
        """
        # make sure the token is renewable
        if not self.renewable:
            raise NotARenewableToken()

        if key is not None:
            # generate new token with the given key
            new: DuckietownToken = self.generate(
                key,
                self.uid,
                minutes=self.duration,
                renewable=True,
                data=self.data,
                scope=self.scope,
                version=self.version,
            )
        else:
            # request new token
            try:
                response = requests.get(
                    url=TOKEN_RENEW_ONLINE_URL,
                    headers={
                        "Authorization": f"Token {self.as_string()}"
                    }
                ).json()
            except requests.RequestException as e:
                raise e
            except requests.JSONDecodeError as e:
                raise e
            # ---
            if not response["success"]:
                raise GenericException(response["messages"])
            # parse new token
            new: DuckietownToken = DuckietownToken.from_string(response["result"]["token"])
        # apply in-place edits
        if in_place:
            # copy token content
            self.copy_from(new)
        # ---
        return new

    def copy_from(self, other: 'DuckietownToken'):
        """
        Turns this instance into an exact copy of the given token.

        :param other:   The token to duplicate.
        """
        self._version = other._version
        self._payload = other._payload
        self._signature = other._signature

    @staticmethod
    def from_string(s: str, vk: Optional[VerifyingKey] = None, allow_expired: bool = True) \
            -> 'DuckietownToken':
        """
        Decodes a Duckietown Token string into an instance of
        :py:class:`dt_authentication.DuckietownToken`.

        Args:
            s:                  The Duckietown Token string.
            vk:                 Optional verification key if different from default
            allow_expired:      Do not throw exception if token expired

        Raises:
            InvalidToken:   The given token is not valid.
            ExpiredToken:   The given token is expired.
        """
        # break token into 3 pieces, dt1-PAYLOAD-SIGNATURE
        p = s.split('-')
        # check number of components
        if len(p) != 3:
            raise InvalidToken("The token should be comprised of three (dash-separated) parts")
        # unpack components
        version, payload_base58, signature_base58 = p
        # check token version
        if version not in SUPPORTED_VERSIONS:
            raise InvalidToken("Duckietown Token version '%s' not supported" % version)
        # decode payload and signature
        payload_json = b58decode(payload_base58)
        signature = b58decode(signature_base58)
        # verify token
        if not vk:
            vk = VerifyingKey.from_pem(PUBLIC_KEYS[version])
        is_valid = False
        try:
            is_valid = vk.verify(signature, payload_json)
        except BadSignatureError:
            pass
        # raise exception if the token is not valid
        if not is_valid:
            raise InvalidToken("Duckietown Token not valid")
        # unpack payload
        payload = json.loads(payload_json.decode("utf-8"))
        if not isinstance(payload, dict) or \
                len(set(payload.keys()).intersection(PAYLOAD_FIELDS)) != len(PAYLOAD_FIELDS):
            raise InvalidToken("Duckietown Token has an invalid payload")
        # parse scope
        if "scope" in payload:
            payload["scope"] = [Scope.parse(s) for s in payload["scope"]]
        # create token object
        token = DuckietownToken(version, payload, signature)
        # make sure the token is not expired
        if not allow_expired and token.expired:
            raise ExpiredToken(
                token.expiration,
                f"This token is expired on '{str(token.expiration)}'. Obtain a new one"
            )
        # ---
        return token

    @classmethod
    def generate(cls, key: SigningKey, user_id: int, *,
                 # duration
                 days: int = 0, hours: int = 0, minutes: int = 0,
                 # payload
                 renewable: bool = False, data: Optional[dict] = None, scope: ScopeList = None,
                 # metadata
                 version: str = DEFAULT_VERSION) -> 'DuckietownToken':
        # get supported fields for version
        fields = SUPPORTED_FIELDS[version]
        # compute expiration date
        exp = None
        if (days + hours + minutes) > 0:
            now = datetime.datetime.utcnow()
            delta = datetime.timedelta(days=days, hours=hours, minutes=minutes)
            exp = (now + delta).strftime(DATETIME_FORMAT[version])
        # initialize payload
        payload = {
            "uid": user_id,
            "exp": exp
        }
        # - scope
        if "scope" in fields:
            # sanitize scope
            if scope is None:
                scope = DEFAULT_SCOPE
            else:
                # a scope list is given, prepend the default scope to it
                for s in DEFAULT_SCOPE:
                    if s not in scope:
                        scope = [s] + scope
            # make sure the scope is valid
            if not isinstance(scope, list):
                raise ValueError("Argument 'scope' must be a list")
            scope_parsed: List[Scope] = []
            scope_encoded: List[Union[str, dict]] = []
            for s in scope:
                if not isinstance(s, Scope):
                    s = Scope.parse(s)
                scope_parsed.append(s)
                scope_encoded.append(s.compact())
            # ---
            # noinspection PyTypedDict
            payload["scope"] = scope_encoded

        # - data
        if "data" in fields:
            # check data
            if data is not None:
                if not isinstance(data, dict):
                    raise ValueError("Argument 'data' must be a dictionary")
                try:
                    json.dumps(data)
                except TypeError:
                    raise ValueError("The given 'data' is not JSON-serializable")
                # ---
                payload["data"] = data

        # - duration
        if "duration" in fields:
            # add duration (only if renewable)
            if renewable:
                payload["duration"] = days * 1440 + hours * 60 + minutes

        def entropy(numbytes):
            e = b"duckietown is a place of relaxed introspection, and hub extends this place a lot"
            return e[:numbytes]

        # compile payload
        payload_bytes = str.encode(json.dumps(payload, sort_keys=True))
        signature = key.sign(payload_bytes, entropy=entropy)

        return DuckietownToken(version, payload, signature)
