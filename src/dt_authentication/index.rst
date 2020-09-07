Get Started
===========

Use the class :py:class:`dt_authentication.DuckietownToken` to work with Duckietown
Tokens. The :py:class:`dt_authentication.DuckietownToken.from_string` allows you to
decode a Duckietown Token. For example,

.. code-block:: python

    from dt_authentication import DuckietownToken

    token = DuckietownToken.from_string("YOU-TOKEN-HERE")

Where the string ``"YOUR-TOKEN-HERE"`` is replaced with your real Duckietown Token.


Code API: dt_authentication
===========================

`DuckietownToken`
-----------------

.. autoclass:: dt_authentication.DuckietownToken
   :members:


Exceptions
----------

.. autoclass:: dt_authentication.InvalidToken
   :members:
