import os
from typing import cast, Tuple

# noinspection PyProtectedMember
from ecdsa import SigningKey, VerifyingKey

from dt_authentication.token import CURVE, DuckietownToken, PUBLIC_KEYS

__all__ = [
    "get_or_create_key_pair",
    "get_id_from_token",
]


def get_verify_key(version: str) -> VerifyingKey:
    return VerifyingKey.from_pem(PUBLIC_KEYS[version])


def get_or_create_key_pair(version: str, path: str) -> Tuple[SigningKey, VerifyingKey]:
    """ Creates a key-pair """
    private: str = os.path.join(path, f"{version}-key-private.pem")
    public: str = os.path.join(path, f"{version}-key-public.pem")
    if not os.path.exists(private):
        sk0 = SigningKey.generate(curve=CURVE)
        with open(private, "wb") as f:
            p = cast(bytes, sk0.to_pem())  # docstring is wrong
            f.write(p)

        vk = sk0.get_verifying_key()
        with open(public, "wb") as f:
            q = cast(bytes, vk.to_pem())  # docstring is wrong
            f.write(q)
    with open(private, "r") as _:
        pem = _.read()
    sk = SigningKey.from_pem(pem)
    with open(public, "r") as _:
        pem = _.read()
    vk = VerifyingKey.from_pem(pem)
    return sk, vk


def get_id_from_token(s: str, *args, **kwargs) -> int:
    """
    Returns a numeric ID from the token, or raises InvalidToken.

    """
    token = DuckietownToken.from_string(s, *args, **kwargs)
    return token.uid
