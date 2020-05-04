# Library: dt_authentication

This repository contains the Python library `dt_authentication`
used to authenticate Duckietown users using the Duckietown Token.


## Usage

Given a Duckietown Token `dtt`, you can decode it as shown 
in the following snippet:

```python
from dt_authentication import DuckietownToken

token = DuckietownToken.from_string(dtt)
print('UID: %r; Expiration: %r' % (token.uid, token.expiration))
```
