import copy
import json
import datetime
from typing import Dict, Union

from base58 import b58decode, b58encode
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

    def __init__(self, payload: Dict[str, Union[str, int]], signature: Union[str, bytes]):
        """
        Creates a Duckietown Token from a payload and a signature.

        Most users will create instances of this class using the method
        :py:method:`dt_authentication.DuckietownToken.from_string` instead of instantiating this
        class directly.

        :param payload:     A dictionary containing the token payload
        :param signature:   A signature, either as a base58 encoded string or as raw bytes
        """
        self._payload: Dict[str, Union[str, int]] = payload
        self._signature: bytes = signature if isinstance(signature, (bytes,)) else b58decode(signature)

    @property
    def payload(self) -> Dict[str, str]:
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
    def expiration(self) -> datetime.date:
        """
        The token's expiration date.
        """
        return datetime.date(*map(int, self._payload['exp'].split('-')))

    def as_string(self) -> str:
        """
        Returns the Duckietown Token string.
        """
        # encode payload into JSON
        payload_json: str = json.dumps(self._payload)
        # encode payload and signature
        payload_base58: str = b58encode(payload_json).decode("utf-8")
        signature_base58: str = b58encode(self._signature).decode("utf-8")
        # compile token
        return f"{self.VERSION}-{payload_base58}-{signature_base58}"

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
        return DuckietownToken(payload, signature)
