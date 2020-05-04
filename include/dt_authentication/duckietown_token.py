import json
import datetime
from base58 import b58decode
from ecdsa import VerifyingKey, BadSignatureError


PUBLIC_KEY = \
"""-----BEGIN PUBLIC KEY-----
MEkwEwYHKoZIzj0CAQYIKoZIzj0DAQEDMgAEQr/8RJmJZT+Bh1YMb1aqc2ao5teE
ixOeCMGTO79Dbvw5dGmHJLYyNPwnKkWayyJS
-----END PUBLIC KEY-----"""

PAYLOAD_FIELDS = {'uid', 'exp'}


class InvalidToken(Exception):
    pass


class DuckietownToken(object):

    VERSION = 'dt1'

    def __init__(self, payload, signature):
        self.payload = payload
        self.signature = signature

    @property
    def uid(self):
        return self.payload['uid']

    @property
    def expiration(self):
        return datetime.date(*map(int, self.payload['exp'].split('-')))

    @staticmethod
    def from_string(s):
        # break token into 3 pieces, dt1-PAYLOAD-SIGNATURE
        p = s.split('-')
        # check number of components
        if len(p) != 3:
            raise ValueError(p)
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
