from datetime import datetime, timedelta
import json
from typing import Annotated
from fastapi import Depends, FastAPI, HTTPException, Security, status, Form, Request
from fastapi.security import (
    OAuth2PasswordBearer,
    OAuth2PasswordRequestForm,
    OAuth2AuthorizationCodeBearer,
    SecurityScopes,
)
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, ValidationError
from jwt import (
  JWT,
  exceptions,
  jwk_from_pem
)

# to get a string like this run:
# openssl rand -hex 32
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "RS256"#"HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
        "disabled": False,
        "scopes": ["me", "items"]
    },
    "alice": {
        "username": "alice",
        "full_name": "Alice Chains",
        "email": "alicechains@example.com",
        "hashed_password": "$2a$12$NI6.SJfjudcy44XGBue5Q.YwC0bKijENIac1VFKEL1u/RBx9xX6T6",
        "disabled": False,
        "scopes": ["me"]
    },
}

class OAuth2AuthorizationCodeRequestForm(BaseModel):
    client_id: str
    scopes: list[str] = []

class LoginRequestForm(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None
    scopes: list[str] = []


class AuthorizationCode(BaseModel):
    authorization_code: str

class User(BaseModel):
    username: str
    email: str | None = None
    full_name: str | None = None
    disabled: bool | None = None
    scopes: list[str]


class UserInDB(User):
    hashed_password: str


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="token",
    scopes={"me": "Read information about the current user.", "items": "Read items."},
)

oauth2_scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl="authorization",
    tokenUrl="token",
    scopes={"me": "Read information about the current user.", "items": "Read items."},
)


app = FastAPI()


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)



async def get_current_user_old(
        security_scopes: SecurityScopes, token: Annotated[str, Depends(oauth2_scheme)]
): #Rimuovere
    if security_scopes.scopes:
        authenticate_value = f'Bearer scope="{security_scopes.scope_str}"'
    else:
        authenticate_value = "Bearer"
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": authenticate_value},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_scopes = payload.get("scopes", [])
        token_data = TokenData(scopes=token_scopes, username=username)
    except (JWTError, ValidationError):
        raise credentials_exception
    user = get_user(fake_users_db, username=token_data.username)
    if user is None:
        raise credentials_exception
    for scope in security_scopes.scopes:
        if scope not in token_data.scopes:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not enough permissions",
                headers={"WWW-Authenticate": authenticate_value},
            )
    return user


@app.get("/login")  #Rimuovere
async def login_for_authentication(
        form_data: Annotated[LoginRequestForm, Depends()]
):
    print("")


@app.get("/authorization", response_model=AuthorizationCode) #Rimuovere
async def login_for_authorization_code(
        form_data: Annotated[OAuth2AuthorizationCodeRequestForm, Depends()]
):
    print(form_data)
    return {"authorization_code": "vsanvkm"}

async def get_current_user(
        security_scopes: SecurityScopes, token: Annotated[str, Depends(oauth2_scheme)]
): #Rimuovere in futuro, ma per ora lasciare
    if security_scopes.scopes:
        authenticate_value = f'Bearer scope="{security_scopes.scope_str}"'
    else:
        authenticate_value = "Bearer"
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": authenticate_value},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_scopes = payload.get("scopes", [])
        token_data = TokenData(scopes=token_scopes, username=username)
    except (JWTError, ValidationError):
        raise credentials_exception
    user = get_user(fake_users_db, username=token_data.username)
    if user is None:
        raise credentials_exception
    for scope in security_scopes.scopes:
        if scope not in token_data.scopes:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not enough permissions",
                headers={"WWW-Authenticate": authenticate_value},
            )
    return user

with open('public.pem', 'rb') as fh:
    public_key = jwk_from_pem(fh.read())


#Return token payload if it's valid or HTTPException
async def check_valid_token(req: Request) -> dict | None:
    
    token_auth = req.headers.get("authorization")
    if token_auth is None:
        #return None
        raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token invalid",
                #headers={"WWW-Authenticate": authenticate_value},
            )
    if token_auth.startswith("Bearer "):
        token = token_auth[7:]
        payload = JWT().decode(token, public_key, algorithms= 'RS256', do_time_check=False) #jwt.decode(token, public_key, algorithms=[ALGORITHM])
        current_time = datetime.now()
        #print(current_time)
        #print(datetime.fromtimestamp((payload['exp'])))
        if current_time > datetime.fromtimestamp((payload['exp'])):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token expired",
                #headers={"WWW-Authenticate": authenticate_value},
            )
        #print(payload)
        return payload
    raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token invalid",
                #headers={"WWW-Authenticate": authenticate_value},
            )

@app.get("/patients/") #Ritorna tutti i pazienti disponibili (ne vengono creati 5 per semplicità)
async def get_patients_info(payload = Depends(check_valid_token)):
    # Returns a list of users.
    result = [
        {
            'nome': 'test_nome_1',
            'cognome': 'test_cognome_1',
            'codice_fiscale': 'test_codice_fiscale_1',
            'ricoverato': 'si',
            'fine_ricovero': '02/02/01',
            'inizio_ricovero': '01/01/01',
            'dottore': 'dottore_1',
            'farmaci_da_assumere': [
                {
                    'nome' : 'farmaco_1_1',
                    'descrizione':'descrizione_1_1'

                },
                {
                    'nome' : 'farmaco_2_1',
                    'descrizione':'descrizione_2_1'

                }
            ],
            'data': 'test_data_1',
            'luogo': 'test_luogo_1',
        },
        {
            'nome': 'test_nome_2',
            'cognome': 'test_cognome_2',
            'codice_fiscale': 'test_codice_fiscale_2',
            'ricoverato': 'no',
            'fine_ricovero': 'null',
            'inizio_ricovero': 'null',
            'dottore': 'dottore_2',
            'farmaci_da_assumere': [
                
            ],
            'data': 'test_data_2',
            'luogo': 'test_luogo_2',
        }
    ]

    return result

    return json.dumps({
        'result' : result
    })

@app.post("/patient/") #Crea un nuovo paziente con dati creati a caso
async def get_patient_info(id: int,payload = Depends(check_valid_token)):
    # Returns a list of users.
    users = [
        { 'username': 'L', 'email': 'janedoe@example.com'},
        { 'username': 'C', 'email': 'johndoe@example.com'}
    ]

    return json.dumps({
        'results': payload
    })

@app.get("/prescriptions/") #Restituisce le informazioni di tutte le prescrizioni
async def get_prescriptions_info(payload = Depends(check_valid_token)):
    # Returns a list of users.
    
    result = [
        {
            'prescrizione_id': 1,
            'nome': 'test_nome_1',
            'cognome': 'test_cognome_1',
            'codice_fiscale': 'test_codice_fiscale_1',
            'farmaci': [
                {
                    'nome' : 'farmaco_1_1',
                    'descrizione':'descrizione_1_1'

                },
                {
                    'nome' : 'farmaco_2_1',
                    'descrizione':'descrizione_2_1'

                }
            ],
            'data': 'test_data_1',
            'luogo': 'test_luogo_1',
        },
        {
            'prescrizione_id': 2,
            'nome': 'test_nome_2',
            'cognome': 'test_cognome_2',
            'codice_fiscale': 'test_codice_fiscale_2',
            'farmaci': [
                {
                    'nome' : 'farmaco_1_2',
                    'descrizione':'descrizione_1_2'

                },
                {
                    'nome' : 'farmaco_2_2',
                    'descrizione':'descrizione_2_2'

                }
            ],
            'data': 'test_data_2',
            'luogo': 'test_luogo_2',
        }
    ]
    return result

@app.get("/prescription") #Restituisce le informazioni di una specifica prescrizione
async def get_prescription_info(id: int, payload = Depends(check_valid_token)):
    # Returns a list of users.

    result = {
        'prescrizione_id': id,
        'nome': 'test_nome',
        'cognome': 'test_cognome',
        'codice_fiscale': 'test_codice_fiscale',
        'farmaci': [
            {
                'nome' : 'farmaco_1',
                'descrizione':'descrizione_1'

            },
            {
                'nome' : 'farmaco_2',
                'descrizione':'descrizione_2'

            }
        ],
        'data': 'test_data',
        'luogo': 'test_luogo',
    }
    return result
    return json.dumps({
        'results': result
    })

@app.post("/prescription") #Inserisce una nuova prescrizione
async def add_new_prescription(payload = Depends(check_valid_token)):
    # Returns a list of users.
    users = [
        { 'username': 'L', 'email': 'janedoe@example.com'},
        { 'username': 'C', 'email': 'johndoe@example.com'}
    ]

    return json.dumps({
        'results': payload
    })

@app.get("/doctors")
async def get_doctors_info(payload = Depends(check_valid_token)):
    # Returns a list of users.

    result = [
        {
            'nome': 'test_nome_1',
            'cognome': 'test_cognome_1',
            'codice_fiscale': 'test_codice_fiscale_1',
            'disponibile': 'si',
            'in_ferie' : 'no',
            'pazienti_seguiti':[
                {
                    'nome':'nome_1',
                    'farmaci':[
                        {
                            'nome':'farmaco_1'
                        }
                    ],
                },
                {
                    'nome':'nome_2',
                    'farmaci':[
                        {
                            'nome':'farmaco_2'
                        }
                    ],
                }
            ]
        },
        {
            'nome': 'test_nome_2',
            'cognome': 'test_cognome_2',
            'codice_fiscale': 'test_codice_fiscale_2',
            'disponibile': 'no',
            'in_ferie' : 'si',
            'pazienti_seguiti':[]
        }
    ]
    return result
    return json.dumps({
        'results': result
    })

#TODO:
#Verifica del token
#Dal token ottenere l'user (da fare quando verrà modificato il contenuto del token su auth_server)
#Verifica degli scope -> metterli nel token e verificare quelli che ha l'utente, oppure farlo a priori in base al client_id dell'auth_server
