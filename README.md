# Library: dt_authentication

This repository contains the Python library `dt_authentication`
used to authenticate Duckietown users using the Duckietown Token.


## Usage

You can decode a Duckietown Token as follows,

```python
from dt_authentication import DuckietownToken

token = DuckietownToken.from_string("YOUR-TOKEN-HERE")
print('UID: %r; Expiration: %r' % (token.uid, token.expiration))
```
