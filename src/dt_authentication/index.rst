Get Started
===========

Use the class :py:class:`dt_authentication.DuckietownToken` to work with Duckietown
Tokens. The :py:class:`dt_authentication.DuckietownToken.from_string` allows you to
decode a Duckietown Token. For example,

.. code-block:: python

    from dt_authentication import DuckietownToken

    token = DuckietownToken("YOU-TOKEN-HERE")

Where the string ``"YOUR-TOKEN-HERE"`` is replaced with your real Duckietown Token.


Code API: dt_authentication
===========================


.. automodule:: dt_authentication
   :members:
