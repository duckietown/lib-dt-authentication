class InvalidToken(BaseException):
    """
    An invalid Duckietown Token was encountered
    """
    pass


class ExpiredToken(BaseException):
    """
    An expired Duckietown Token was encountered
    """
    pass
