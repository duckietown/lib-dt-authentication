import datetime
import json
import logging
import tempfile

from dt_authentication import DuckietownToken, InvalidToken
from dt_authentication.token import DEFAULT_SCOPE
from dt_authentication.utils import get_id_from_token, get_or_create_key_pair

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


SAMPLE_TOKEN = (
    "dt1-9Hfd69b5ythetkCiNG12pKDrL987sLJT6KejWP2Eo5QQ"
    "-43dzqWFnWd8KBa1yev1g3UKnzVxZkkTbfWWn6of92V5Bf8qGV24rZHe6r7sueJNtWF"
)
SAMPLE_TOKEN_UID = -1
SAMPLE_TOKEN_EXP = "2018-10-20"


def scope(s) -> str:
    return json.dumps(s, sort_keys=True, default=lambda o: o.__dict__)


def date(d) -> datetime.date:
    return datetime.datetime.strptime(d, "%Y-%m-%d")


def test1():
    token = DuckietownToken.from_string(SAMPLE_TOKEN, allow_expired=True)
    assert token.version == "dt1"
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

    assert SAMPLE_TOKEN_UID == get_id_from_token(SAMPLE_TOKEN, allow_expired=True)

    try:
        get_id_from_token(msg_bad, allow_expired=True)
    except InvalidToken:
        pass
    else:
        raise Exception()


def test_verify1():
    # in this token, uid is string
    invalid = "dt1-wEJsmra4x9TT5bxVq1QYEEGQQW18bje1MvVmg4sDEdUSQjA4k-" \
              "43dzqWFnWd8KBa1yev1g3UKnzVxZkkTbfTxZ1tQ5rvJk3Vaa9gHKwhoV38ms4nNR2X"
    try:
        DuckietownToken.from_string(invalid)
    except InvalidToken:
        pass
    else:
        msg = "Expected invalid"
        raise Exception(msg)


def test_create():
    uid: int = 22
    with tempfile.TemporaryDirectory() as tmp:
        sk, vk = get_or_create_key_pair("dt1", tmp)
        token = DuckietownToken.generate(sk, uid)
        token.from_string(token.as_string(), vk=vk)
        assert not token.expired
