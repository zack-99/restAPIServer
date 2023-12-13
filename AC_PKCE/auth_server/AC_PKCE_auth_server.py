import json
#import ssl
import urllib.parse as urlparse
from auth import (authenticate_user_credentials, register_client, authenticate_client,
                  generate_access_token, generate_authorization_code, 
                  verify_authorization_code, verify_client_info, get_username_by_token,
                  JWT_LIFE_SPAN)
from flask import Flask, redirect, render_template, request
from urllib.parse import urlencode

app = Flask(__name__)

@app.route('/register')
def register():
  return render_template('AC_PKCE_register_client.html')

@app.route('/client-signup', methods = ['POST'])
def client_signup():
  urls = request.form.getlist('redirect_url[]')
  (client_id, client_secret) = register_client(urls)
  return render_template('AC_PKCE_register_client.html',
                          client_id = client_id,
                          client_secret = client_secret)

# CLIENT auth, verifies partial of the client credentials: client_id, redirect_url, code_challenge
@app.route('/auth')
def auth():
  # Describe the access request of the client and ask user for approval
  client_id = request.args.get('client_id')
  redirect_url = request.args.get('redirect_url')
  code_challenge = request.args.get('code_challenge')

  if None in [ client_id, redirect_url, code_challenge ]:
    return json.dumps({
      "error": "invalid_request 1"
    }), 400

  if not verify_client_info(client_id, redirect_url):
    return json.dumps({
      "error": "invalid_client"
    })

  return render_template('AC_PKCE_grant_access.html',
                         client_id = client_id,
                         redirect_url = redirect_url,
                         code_challenge = code_challenge)

def process_redirect_url(redirect_url, authorization_code):
  # Prepare the redirect URL
  url_parts = list(urlparse.urlparse(redirect_url))
  queries = dict(urlparse.parse_qsl(url_parts[4]))
  queries.update({ "authorization_code": authorization_code })
  url_parts[4] = urlencode(queries)
  url = urlparse.urlunparse(url_parts)
  return url


# USER sign in, verifies user's credentials and code_challenge
@app.route('/signin', methods = ['POST'])
def signin():
  # Issues authorization code
  username = request.form.get('username')
  password = request.form.get('password')
  client_id = request.form.get('client_id')
  redirect_url = request.form.get('redirect_url')
  code_challenge = request.form.get('code_challenge')

  if None in [username, password, client_id, redirect_url, code_challenge]:
    return json.dumps({
      "error": "invalid_request 2"
    }), 400

  if not verify_client_info(client_id, redirect_url):
    return json.dumps({
      "error": "invalid_client"
    })

  if not authenticate_user_credentials(username, password):
    return json.dumps({
      'error': 'access_denied'
    }), 401

  authorization_code = generate_authorization_code(client_id, redirect_url,
                                                   code_challenge,username)

  url = process_redirect_url(redirect_url, authorization_code)
  
  return redirect(url, code = 303)

@app.route('/token', methods = ['POST'])
def exchange_for_token():
  # Issues access token
  authorization_code = request.form.get('authorization_code')
  client_id = request.form.get('client_id')
  client_secret = request.form.get('client_secret')
  code_verifier = request.form.get('code_verifier')
  redirect_url = request.form.get('redirect_url')

  if None in [ authorization_code, client_id, code_verifier, redirect_url ]:
    return json.dumps({
      "error": "invalid_request 3"
    }), 400

  if not authenticate_client(client_id, client_secret):
    return json.dumps({
      'error': 'access_denied'
    }), 401

  if not verify_authorization_code(authorization_code, client_id, redirect_url,
                                   code_verifier):
    return json.dumps({
      "error": "access_denied"
    }), 400

  access_token = generate_access_token(authorization_code)
  return json.dumps({ 
    "access_token": access_token,
    "token_type": "JWT",
    "expires_in": JWT_LIFE_SPAN
  })

@app.route('/user', methods=['POST'])
def get_user_information_by_token():
  access_token = request.form.get('access_token')
  username = get_username_by_token(access_token)
  return json.dumps({
    "username": username
  })

if __name__ == '__main__':
  #context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
  #context.load_cert_chain('domain.crt', 'domain.key')
  #app.run(port = 5000, debug = True, ssl_context = context)
  app.run(port = 5001, debug = True)