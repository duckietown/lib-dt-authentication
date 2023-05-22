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

    pass


class NotARenewableToken(GenericException):
    """
    A not renewable token was encountered in a context where a renewable token was expected.
    """

    pass
