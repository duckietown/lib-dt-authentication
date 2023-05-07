import argparse
import datetime
import logging
import sys

# noinspection PyProtectedMember
from ecdsa import SigningKey
from future import builtins

from dt_authentication import DuckietownToken, InvalidToken

logging.basicConfig()
logger = logging.getLogger("duckietown-tokens ")
logger.setLevel(logging.INFO)

__all__ = ["cli_verify", "cli_generate"]


def cli_verify(args=None):
    try:
        if args is None:
            args = sys.argv[1:]

        if args:
            token_s = args[0]
        else:
            msg = "Please enter token:\n> "
            token_s = builtins.input(msg)

        try:
            token = DuckietownToken.from_string(token_s)
        except InvalidToken:
            msg = "Invalid token format."
            logger.error(msg)
            sys.exit(1)

        if token.expired:
            msg = f"This token has expired on {token.expiration}"
            logger.error(msg)
            sys.exit(2)

        _print_token_info(token)
        sys.exit(0)
    except Exception as e:
        logger.error(str(e))
        sys.exit(3)


def cli_generate(args=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--uid", type=int, help="ID to sign")
    parser.add_argument("--key", type=str, help="Path to signing key")
    parser.add_argument("--ndays", type=int, default=365, help="Number of days for validity")
    parser.add_argument("--nhours", type=int, default=0, help="Number of hours for validity")
    parser.add_argument("--nminutes", type=int, default=0, help="Number of minutes for validity")

    args = parser.parse_args(args=args)

    if args.key is None:
        msg = "Please supply --key "
        raise Exception(msg)
    if args.uid is None:
        msg = "Please supply --uid "
        raise Exception(msg)

    # load private key
    with open(args.key, "r") as _:
        pem = _.read()
    sk = SigningKey.from_pem(pem)

    # generate token
    token: DuckietownToken = DuckietownToken.generate(
        key=sk,
        user_id=args.uid,
        days=args.ndays,
        hours=args.nhours,
        minutes=args.nminutes,
        scope=None,
    )
    _print_token_info(token)


def _print_token_info(token: DuckietownToken):
    exp_info: str = "expired" if token.expired else \
        f"in {(token.expiration - datetime.datetime.now()).days} days"
    print(f"""
Payload:
--------
{token.payload_as_json(sort_keys=True, indent=4).strip("{}")}

Expiration:
--------\n
    {token.expiration}    -    ({exp_info})

Token:
--------\n
    {token.as_string()}
    """)
