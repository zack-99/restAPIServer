import cryptography
from jwt import (
  JWT,
  exceptions,
  jwk_from_pem
)

ISSUER = 'sample-auth-server'

with open('public.pem', 'rb') as fh:
    public_key = jwk_from_pem(fh.read())

def verify_access_token(access_token):
  try:
    decoded_token = JWT().decode(access_token, public_key, algorithms= 'RS256', do_time_check=False)
    print(decoded_token)
    
  except Exception as e:
    print(e)
    return False

  return True
