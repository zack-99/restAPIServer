import base64
import cryptography
import hashlib
import json
import os
from jwt import (
    JWT,
    jwk_from_pem
)
import secrets
import time
from passlib.context import CryptContext

from cryptography.fernet import Fernet

#KEY = Fernet.generate_key()
KEY = b'YHD1m3rq3K-x6RxT1MtuGzvyLz4EWIJAEkRtBRycDHA='

ISSUER = 'sample-auth-server'
CODE_LIFE_SPAN = 600
JWT_LIFE_SPAN = 6000

authorization_codes = {}

f = Fernet(KEY)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

#with open('private.pem', 'rb') as file:
#  private_key = file.read()
with open('public.pem', 'rb') as fh:
    public_key = jwk_from_pem(fh.read())

with open('private.pem', 'rb') as fh:
    private_key = jwk_from_pem(fh.read())

"""
read_self, read_all, read_group, read_under (mio gruppo + quelli sotto)

"""

users_db = {
    #password: secret
    "user1": {'username': 'user1', 'password': '$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW','access_token':''},
    #password: ciao
    "user2": {'username': 'user2', 'password': '$2a$12$NI6.SJfjudcy44XGBue5Q.YwC0bKijENIac1VFKEL1u/RBx9xX6T6','access_token':''},
    #password: ciao
    "user3": {'username': 'user3', 'password': '$2a$12$NI6.SJfjudcy44XGBue5Q.YwC0bKijENIac1VFKEL1u/RBx9xX6T6','access_token':''}
}

clients_db = {
    #client_secret: secret
    "sample-client-id": {'client_secret': '$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW', 'redirect_urls': [
        "http://localhost:5000/callback"
    ]},
    #client_secret: ciao
    "sample-client-id-2": {'client_secret': '$2a$12$NI6.SJfjudcy44XGBue5Q.YwC0bKijENIac1VFKEL1u/RBx9xX6T6', 'redirect_urls': [
        "http://localhost:5000/callback"
    ]},
    #client_secret: ciao
    "sample-client-id-3": {'client_secret': '$2a$12$NI6.SJfjudcy44XGBue5Q.YwC0bKijENIac1VFKEL1u/RBx9xX6T6', 'redirect_urls': [
        "http://localhost:5000/callback"
    ]}
}


def get_username_by_token(access_token):
  
  for user in users_db:
    print(f"user: {user}")
    record = users_db.get(user)
    u = get_db_entry(users_db, record['username'])
    print(f"db entry {u}")
    print(record)
    print(record['access_token'])
    print(record['access_token'] == access_token)
    if record['access_token'] == access_token:
      return record['username']


def verify_password(plain_password, hashed_password):
  return pwd_context.verify(plain_password, hashed_password)


def get_db_entry(db, id: str):
  if id in db:
    entry = db[id]
    return entry


def authenticate_user_credentials(username: str, password: str):
  user = get_db_entry(users_db, username)
  if not user:
      return False
  if not verify_password(password, user['password']):
      return False
  return True

def register_client(redirect_urls):
  client_id = base64.urlsafe_b64encode(os.urandom(10)).decode('utf-8').replace('=', '')
  client_secret = base64.urlsafe_b64encode(os.urandom(30)).decode('utf-8').replace('=', '')

  clients_db[client_id] = {
    'client_secret': pwd_context.hash(client_secret),
    'redirect_urls': redirect_urls
  }

  print(clients_db)

  return (client_id, client_secret)

def authenticate_client(client_id, client_secret):
  client = get_db_entry(clients_db, client_id)
  if not client:
      return False
  if not verify_password(client_secret, client['client_secret']):
      return False
  return True


def verify_client_info(client_id, redirect_url):
  client = get_db_entry(clients_db, client_id)
  if not client:
      return False
  if not any(redirect_url.startswith(ru) for ru in client['redirect_urls']):
      return False
  return True


def generate_code_challenge(code_verifier):
  m = hashlib.sha256()
  m.update(code_verifier.encode())
  code_challenge = m.digest()
  return base64.b64encode(code_challenge, b'-_').decode().replace('=', '')


def generate_authorization_code(client_id, redirect_url, code_challenge, username):
  #f = Fernet(KEY)
  authorization_code = f.encrypt(json.dumps({
      "client_id": client_id,
      "redirect_url": redirect_url,
  }).encode())

  authorization_code = base64.b64encode(
      authorization_code, b'-_').decode().replace('=', '')

  expiration_date = time.time() + CODE_LIFE_SPAN

  authorization_codes[authorization_code] = {
      "client_id": client_id,
      "redirect_url": redirect_url,
      "exp": expiration_date,
      "code_challenge": code_challenge,
      "username": username
  }

  return authorization_code


def verify_authorization_code(authorization_code, client_id, redirect_url,
                              code_verifier):
  #f = Fernet(KEY)
  record = authorization_codes.get(authorization_code)
  if not record:
    return False

  client_id_in_record = record.get('client_id')
  redirect_url_in_record = record.get('redirect_url')
  exp = record.get('exp')
  code_challenge_in_record = record.get('code_challenge')

  if client_id != client_id_in_record or \
     not redirect_url_in_record.startswith(redirect_url):
    return False

  if exp < time.time():
    return False

  code_challenge = generate_code_challenge(code_verifier)

  if code_challenge != code_challenge_in_record:
    return False

  return True


def generate_access_token(authorization_code):
  #print(time.time())
  #print(authorization_codes)
  record = authorization_codes.get(authorization_code)
  username = record['username']
  #print(record)
  """for code in authorization_codes:
    print(f"code {code}")
    if code == authorization_code:
      username = authorization_code['username']
  """
  payload = {
      "iss": ISSUER,
      "exp": time.time() + JWT_LIFE_SPAN,
  }

  access_token = JWT().encode(payload, private_key, alg='RS256')
  #access_token = JWT().decode(access_token, public_key, do_time_check=False)
  #print(access_token)
  #print(f"record: {record}")
  #print(users_db[username])
  users_db[username]['access_token'] = access_token

  del authorization_codes[authorization_code]

  return access_token