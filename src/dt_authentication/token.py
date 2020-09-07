import copy
import json
import datetime
from typing import Dict, Union

from base58 import b58decode
from ecdsa.keys import VerifyingKey, BadSignatureError

from .exceptions import InvalidToken

PUBLIC_KEY = \
    """-----BEGIN PUBLIC KEY-----
MEkwEwYHKoZIzj0CAQYIKoZIzj0DAQEDMgAEQr/8RJmJZT+Bh1YMb1aqc2ao5teE
ixOeCMGTO79Dbvw5dGmHJLYyNPwnKkWayyJS
-----END PUBLIC KEY-----"""

PAYLOAD_FIELDS = {'uid', 'exp'}


class DuckietownToken(object):
    """
    Class modeling a Duckietown Token.

    Args:
        payload:    The token's payload as a dictionary.
        signature:  The token's signature.
    """
    VERSION = 'dt1'

    def __init__(self, payload: Dict[str, Union[str, int]], signature: str):
        self._payload = payload
        self._signature = signature

    @property
    def payload(self) -> Dict[str, str]:
        """
        The token's payload.
        """
        return copy.copy(self._payload)

    @property
    def signature(self) -> str:
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
    def expiration(self) -> datetime.date:
        """
        The token's expiration date.
        """
        return datetime.date(*map(int, self._payload['exp'].split('-')))

    @staticmethod
    def from_string(s: str) -> 'DuckietownToken':
        """
        Decodes a Duckietown Token string into an instance of
        :py:class:`dt_authentication.DuckietownToken`.

        Args:
            s:  The Duckietown Token string.

        Raises:
            InvalidToken:   The given token is not valid.
        """
        # break token into 3 pieces, dt1-PAYLOAD-SIGNATURE
        p = s.split('-')
        # check number of components
        if len(p) != 3:
            raise InvalidToken("The token should be comprised of three (dash-separated) parts")
        # unpack components
        version, payload_base58, signature_base58 = p
        # check token version
        if version != DuckietownToken.VERSION:
            raise InvalidToken("Duckietown Token version '%s' not supported" % version)
        # decode payload and signature
        payload_json = b58decode(payload_base58)
        signature = b58decode(signature_base58)
        # verify token
        vk = VerifyingKey.from_pem(PUBLIC_KEY)
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
        # ---
        return DuckietownToken(payload, str(signature))
