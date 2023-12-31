import json
import requests
#import ssl

from flask import (Flask, make_response, render_template, redirect, request,
                   url_for, session)
import base64
import os
import re
import hashlib

#os.environ["TOKEN_PATH"] = 'http://localhost:5001/token'
#os.environ["AUTH_PATH"] = 'http://localhost:5001/auth'
#os.environ["RES_PATH"] = 'http://localhost:8000/'
#os.environ["REGISTER_CLIENT_URL"]  = 'http://localhost:5001/register'
#os.environ["REDIRECT_URL"] = 'http://localhost:5000/callback'
#os.environ["CLIENT_CREDENTIALS_URL"] = 'http://localhost:5000/client-credentials'
REGISTER_CLIENT_URL = 'http://localhost:5001/register'
AUTH_PATH = 'http://localhost:5001/auth'
TOKEN_PATH = 'http://localhost:5001/token'
RES_PATH = 'http://localhost:5002/users'
RES_PATH = 'http://localhost:8000/'
REDIRECT_URL = 'http://localhost:5000/callback'
CLIENT_CREDENTIALS_URL = 'http://localhost:5000/client-credentials'

CLIENT_ID = 'sample-client-id'
CLIENT_SECRET = 'secret'

# TODO: random generate
CODE_VERIFIER = "samp-code-verifier"

states = {}

app = Flask(__name__)

app.secret_key = 'SECRET-SESSION-KEY'

def generate_code_challenge_pair() -> tuple:
  state = base64.urlsafe_b64encode(os.urandom(10)).decode('utf-8').replace('=', '')

  code_verifier = base64.urlsafe_b64encode(os.urandom(40)).decode('utf-8')
  code_verifier = re.sub('[^a-zA-Z0-9]+', '', code_verifier)

  m = hashlib.sha256()
  m.update(code_verifier.encode())
  code_challenge = m.digest()
  return (code_verifier, base64.b64encode(code_challenge, b'-_').decode().replace('=', ''), state)

@app.before_request
def before_request():
  # Redirects user to the login page if access token is not present
  if request.endpoint not in ['login', 'callback', 'client_credentials', 'save_client_credentials']:
    access_token = session.get('access_token', None)
    if access_token:
      pass
    else:
      return redirect(url_for('login'))

@app.route('/logout')
def logout():
  session['access_token'] = None
  return redirect(url_for('main'))

@app.route('/client-credentials')
def client_credentials():
  return render_template('AC_client_credentials.html')

@app.route('/save-client-credentials', methods = ['POST'])
def save_client_credentials():
  global CLIENT_ID, CLIENT_SECRET

  CLIENT_ID = request.form.get('client_id')
  CLIENT_SECRET = request.form.get('client_secret')

  print(CLIENT_ID)
  print(CLIENT_SECRET)

  return redirect(url_for('main'))

@app.route('/')
def main():
  # Retrieves a list of users
  access_token = session['access_token']

  """r = requests.get(RES_PATH, headers = {
    'Authorization': 'Bearer {}'.format(access_token)
  })

  if r.status_code != 200:
    return json.dumps({
      'error': 'The resource server returns an error: \n{}'.format(
        r.text)
    }), 500

  print("TEST-TOKEN")
  print(r.text)
  #users = json.loads(r.text).get('results')
  #print(users) """

  return render_template('result_api.html')


@app.get('/result_api')
def print_result_api():
  # Retrieves a list of users
  access_token = session['access_token']

  end_point = request.args.get('end_point')

  id = request.args.get('id')
  if id is not None:
    end_point += "?id=" + id




  print(os.getenv("RES_PATH", default=RES_PATH) + end_point)

  r = requests.post(os.getenv("RES_PATH", default=RES_PATH) + end_point, headers = {
    'Authorization': 'Bearer {}'.format(access_token)
  })

  if r.status_code != 200:
    return render_template('result_api.html',result = 'The resource server returns an error: \n{}'.format(r.text))
    """return json.dumps({
      'error': 'The resource server returns an error: \n{}'.format(
        r.text)
    }), 500"""

  print("TEST-TOKEN")
  print(r.text)
  #users = json.loads(r.text).get('results')
  #print(users)

  return render_template('result_api.html',result = r.text)


@app.route('/login')
def login():
  (code_verifier, code_challenge, state) = generate_code_challenge_pair()

  states[state] = { 'code_verifier': code_verifier, 'code_challenge': code_challenge }

  # Presents the login page
  return render_template('AC_login.html', 
                         dest = os.getenv("AUTH_PATH",default=AUTH_PATH),
                         client_id = CLIENT_ID,
                         redirect_url = os.getenv("REDIRECT_URL",default=REDIRECT_URL),
                         code_challenge = code_challenge,
                         state = state,
                         client_register_url = os.getenv("REGISTER_CLIENT_URL",default=REGISTER_CLIENT_URL),
                         client_credentials_url = os.getenv("CLIENT_CREDENTIALS_URL",default=CLIENT_CREDENTIALS_URL))

@app.route('/callback')
def callback():
  # Accepts the authorization code and exchanges it for access token
  authorization_code = request.args.get('authorization_code')
  state = request.args.get('state')

  #authorization_code = base64.b64encode(authorization_code, b'-_').decode().replace('=', '')

  if not authorization_code:
    return json.dumps({
      'error': 'No authorization code is received.'
    }), 500

  if not state or not state in states:
    return json.dumps({
      'error': 'Invalid state received.'
    }), 500

  r = requests.post(os.getenv("TOKEN_PATH",default=TOKEN_PATH), data = {
    "grant_type": "authorization_code",
    "authorization_code": authorization_code,
    "client_id" : CLIENT_ID,
    "client_secret" : CLIENT_SECRET,
    "code_verifier" : states[state]['code_verifier'],
    "redirect_url": os.getenv("REDIRECT_URL",default=REDIRECT_URL)
  })

  del states[state]
  
  if r.status_code != 200:
    return json.dumps({
      'error': 'The authorization server returns an error: \n{}'.format(
        r.text)
    }), 500
  
  
  access_token = json.loads(r.text).get('access_token')
  response = make_response(redirect(url_for('main')))
  session['access_token'] = access_token
  return response


if __name__ == '__main__':
  #context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
  #context.load_cert_chain('domain.crt', 'domain.key')
  #app.run(port = 5000, debug = True, ssl_context = context)
  app.run(host = '0.0.0.0', port = 5000, debug = True)