import datetime
import json
import logging
import tempfile
from typing import List

from dt_authentication import DuckietownToken, InvalidToken
from dt_authentication.token import DEFAULT_SCOPE, Scope
from dt_authentication.utils import get_id_from_token, get_or_create_key_pair

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


SAMPLE_TOKEN = (
    "dt2-FifqUXc5FqUotojkAVpYG5JWebZRH6SUHM3DRgk1kRSKdq1uKcL9CFaNT9dRhCVKwFoEnMgm6Hu6v8-"
    "43dzqWFnWd8KBa1yev1g3UKnzVxZkkTbfaF8L9aHLLmc5bPTTmQhQzybqT8rKAADZa"
)
SAMPLE_TOKEN_UID = -1
SAMPLE_TOKEN_EXP = "2024-05-06/02:48"


def scope(s) -> str:
    return json.dumps([str(s1) for s1 in s])


def date(d) -> datetime.date:
    return datetime.datetime.strptime(d, "%Y-%m-%d/%H:%M")


def test1():
    token = DuckietownToken.from_string(SAMPLE_TOKEN)
    assert token.version == "dt2"
    data = token.payload

    assert data["uid"] == token.uid
    assert date(data["exp"]) == token.expiration

    assert token.uid == SAMPLE_TOKEN_UID

    assert token.expiration == date(SAMPLE_TOKEN_EXP)
    assert scope(token.scope) == scope(DEFAULT_SCOPE)

    seq = SAMPLE_TOKEN[6:8]
    msg_bad = SAMPLE_TOKEN.replace(seq, "XY")
    try:
        DuckietownToken.from_string(msg_bad)
    except InvalidToken:
        pass
    else:
        raise Exception(token)

    assert SAMPLE_TOKEN_UID == get_id_from_token(SAMPLE_TOKEN)

    try:
        get_id_from_token(msg_bad)
    except InvalidToken:
        pass
    else:
        raise Exception()


def test_verify1():
    # in this token, uid is string
    invalid = (
        "dt2-wEJsmra4x9TT5bxVq1QYEEGQQW18bje1MvVmg4sDEdUSQjA4k-"
        "43dzqWFnWd8KBa1yev1g3UKnzVxZkkTbfTxZ1tQ5rvJk3Vaa9gHKwhoV38ms4nNR2X"
    )
    try:
        DuckietownToken.from_string(invalid)
    except InvalidToken:
        pass
    else:
        msg = "Expected invalid"
        raise Exception(msg)


def test_create_simple():
    with tempfile.TemporaryDirectory() as tmp:
        sk, vk = get_or_create_key_pair("dt2", tmp)
        token = DuckietownToken.generate(sk, SAMPLE_TOKEN_UID)
        token.from_string(token.as_string(), vk=vk)
    assert not token.expired


def test_create_never_expires():
    days: int = -1
    with tempfile.TemporaryDirectory() as tmp:
        sk, vk = get_or_create_key_pair("dt2", tmp)
        token = DuckietownToken.generate(sk, SAMPLE_TOKEN_UID, days=days)
        token = DuckietownToken.from_string(token.as_string(), vk=vk)
    assert token.expiration is None
    assert not token.expired


def test_already_expired():
    s: str = (
        "dt2-FifqUXc5FqUotojkAUPJcyTpMcCh8x8xonB8Dc6PLo3VZcQGUcukHiYBzTjHAzkDEF9xApqFvvLc8L-"
        "43dzqWFnWd8KBa1yev1g3UKnzVxZkkTbfkRuAQ3kSBB4pz9LGE8epBAfwwttWthQ9b"
    )
    token = DuckietownToken.from_string(s, allow_expired=True)
    assert token.expired


def test_scope_action():
    s: List[Scope] = [Scope("auth")]
    with tempfile.TemporaryDirectory() as tmp:
        sk, vk = get_or_create_key_pair("dt2", tmp)
        token = DuckietownToken.generate(sk, SAMPLE_TOKEN_UID, scope=s)
        token = DuckietownToken.from_string(token.as_string(), vk=vk)
    assert scope(token.scope) == scope(s)
    assert token.grants(s[0].action)


def test_scope_resource():
    s: List[Scope] = [Scope("create", "class")]
    with tempfile.TemporaryDirectory() as tmp:
        sk, vk = get_or_create_key_pair("dt2", tmp)
        token = DuckietownToken.generate(sk, SAMPLE_TOKEN_UID, scope=s)
        token = DuckietownToken.from_string(token.as_string(), vk=vk)
    assert scope(token.scope) == scope(DEFAULT_SCOPE + s)
    assert token.grants(s[0].action, s[0].resource)


def test_scope_resource_id():
    s: List[Scope] = [Scope("create", "class", "55")]
    with tempfile.TemporaryDirectory() as tmp:
        sk, vk = get_or_create_key_pair("dt2", tmp)
        token = DuckietownToken.generate(sk, SAMPLE_TOKEN_UID, scope=s)
        token = DuckietownToken.from_string(token.as_string(), vk=vk)
    assert scope(token.scope) == scope(DEFAULT_SCOPE + s)
    assert token.grants(s[0].action, s[0].resource, s[0].identifier)


def test_scope_service():
    s: List[Scope] = [Scope("create", "class", "55", "hub.duckietown.com")]
    with tempfile.TemporaryDirectory() as tmp:
        sk, vk = get_or_create_key_pair("dt2", tmp)
        token = DuckietownToken.generate(sk, SAMPLE_TOKEN_UID, scope=s)
        token = DuckietownToken.from_string(token.as_string(), vk=vk)
    assert scope(token.scope) == scope(DEFAULT_SCOPE + s)
    assert token.grants(s[0].action, s[0].resource, s[0].identifier, s[0].service)


def test_scope_not_granted():
    s: List[Scope] = [Scope("create", "class")]
    with tempfile.TemporaryDirectory() as tmp:
        sk, vk = get_or_create_key_pair("dt2", tmp)
        token = DuckietownToken.generate(sk, SAMPLE_TOKEN_UID, scope=s)
        token = DuckietownToken.from_string(token.as_string(), vk=vk)
    try:
        # this is a less restricted scope than the one assigned
        assert token.grants("create")
    except AssertionError:
        pass
    else:
        raise AssertionError("A token was granting a larger scope than expected")


def test_not_renewable():
    s: List[Scope] = [Scope("create", "class")]
    with tempfile.TemporaryDirectory() as tmp:
        sk, vk = get_or_create_key_pair("dt2", tmp)
        token = DuckietownToken.generate(sk, SAMPLE_TOKEN_UID, scope=s)
        token = DuckietownToken.from_string(token.as_string(), vk=vk)
    assert not token.renewable
    assert token.duration is None


def test_renewable():
    s: List[Scope] = [Scope("create", "class")]
    d, h, m = 13, 45, 27
    with tempfile.TemporaryDirectory() as tmp:
        sk, vk = get_or_create_key_pair("dt2", tmp)
        token = DuckietownToken.generate(
            sk, SAMPLE_TOKEN_UID, scope=s, days=d, hours=h, minutes=m, renewable=True
        )
        token = DuckietownToken.from_string(token.as_string(), vk=vk)
    assert token.renewable
    assert isinstance(token.duration, int)
    assert token.duration == d * 1440 + h * 60 + m


def test_renew_not_renewable():
    with tempfile.TemporaryDirectory() as tmp:
        sk, vk = get_or_create_key_pair("dt2", tmp)
        # generate first token
        token1 = DuckietownToken.generate(sk, SAMPLE_TOKEN_UID, minutes=5)
        token1 = DuckietownToken.from_string(token1.as_string(), vk=vk)
        # ask for a new token
        try:
            _ = token1.renew(sk)
        except ValueError:
            pass
        else:
            raise AssertionError("We were able to renew a non-renewable token")


def test_renew():
    data = {"a": 27, "b": 32.4, "c": None, "d": [12, 13.5, None, {}, []]}
    with tempfile.TemporaryDirectory() as tmp:
        sk, vk = get_or_create_key_pair("dt2", tmp)
        # generate first token
        token1 = DuckietownToken.generate(
            sk, SAMPLE_TOKEN_UID, minutes=5, data=data, renewable=True
        )
        token1 = DuckietownToken.from_string(token1.as_string(), vk=vk)
        # ask for a new token
        # NOTE: this will fail if the system clock bumps the minutes at this point
        token2 = token1.renew(sk)
    assert token1.payload_as_json() == token2.payload_as_json()


def test_empty_data():
    with tempfile.TemporaryDirectory() as tmp:
        sk, vk = get_or_create_key_pair("dt2", tmp)
        token = DuckietownToken.generate(sk, SAMPLE_TOKEN_UID)
        token = DuckietownToken.from_string(token.as_string(), vk=vk)
    assert token.data is None


def test_data1():
    data = {"a": 27, "b": 32.4, "c": None, "d": [12, 13.5, None, {}, []]}
    with tempfile.TemporaryDirectory() as tmp:
        sk, vk = get_or_create_key_pair("dt2", tmp)
        token = DuckietownToken.generate(sk, SAMPLE_TOKEN_UID, data=data)
        token = DuckietownToken.from_string(token.as_string(), vk=vk)
    assert isinstance(token.data, dict)
    assert json.dumps(data, sort_keys=True) == json.dumps(token.data, sort_keys=True)
