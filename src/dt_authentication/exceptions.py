from datetime import datetime


class GenericException(BaseException):
    """
    A generic exception
    """

    pass


class InvalidToken(GenericException):
    """
    An invalid Duckietown Token was encountered
    """

    pass


class ExpiredToken(GenericException):
    """
    An expired Duckietown Token was encountered
    """

    def __init__(self, expiration: datetime, *args):
        super(ExpiredToken, self).__init__(*args)
        self._expiration: datetime = expiration

    @property
    def expiration(self) -> datetime:
        return self._expiration


class NotARenewableToken(GenericException):
    """
    A not renewable token was encountered in a context where a renewable token was expected.
    """

    pass
