from datetime import datetime, timedelta
import json
import requests
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
from langchain.callbacks.manager import CallbackManager
from langchain.callbacks.streaming_stdout import StreamingStdOutCallbackHandler
from langchain.chains import LLMChain
from langchain.llms import LlamaCpp
from langchain.prompts import PromptTemplate


# to get a string like this run:
# openssl rand -hex 32
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "RS256"#"HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
TOKEN_PATH = "http://127.0.0.1:5001/user"

#MODEL
MODEL_PATH = "llama-model/openorca-platypus2-13b.ggmlv3.gguf.q4_0.bin"
callback_manager = CallbackManager([StreamingStdOutCallbackHandler()])
template = """Question: {question}
Answer: Let's work this out in a step by step way to be sure we have the right answer."""
prompt = PromptTemplate(template=template, input_variables=["question"])
# Make sure the model path is correct for your system!
n_gpu_layers = 1  # Metal set to 1 is enough.
n_batch = 512  # Should be between 1 and n_ctx, consider the amount of RAM of your Apple Silicon Chip.
llm = LlamaCpp(
    model_path=MODEL_PATH,
    temperature=1,
    #max_tokens=150,
    #top_p=1,
    n_gpu_layers=n_gpu_layers,
    n_batch=n_batch,
    f16_kv=True,
    callback_manager=callback_manager,
    verbose=True,  # Verbose is required to pass to the callback manager
    grammar_path="llama-model/json.gbnf",
)
use_model = True #Set False to not use llm

"""
patients?department=ciaica (info su tutti i pazienti di un reparto)
patient?department=cica&username=1212121 (info su un paziente di un reparto)
prescriptions?department=cicaciac
prescription?department=cicaciac&username=23232323
doctors?deparment=caiaicaic


patient/me (info su di me)

"""


fake_users_db = {
    "user1": { #Primario
        "authorized_api": ["/patients", "/prescriptions", "/doctors", "/doctors/department", "/patient", "/patient/me", "/prescription/me"],
        "department": "Cardiologia",
    },
    "user2": { #Infermire -> può aggiungere solo pazienti
        "authorized_api": ["/doctors","/prescriptions","/patient/me","prescription/me"],
        "department": "Urologia",
    },
    "user3": { #Paziente
        "authorized_api": ["/patient/me", "/prescriptions/me","/doctors"],
        "department": "Oncologia"
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


#Return username if it's valid or HTTPException
async def check_valid_token(req: Request) -> str | None:
    
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
        username = requests.post(TOKEN_PATH, data = {
        "access_token": token
        })
        return json.loads(username.text).get('username')
    raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token invalid",
                #headers={"WWW-Authenticate": authenticate_value},
            )

def create_data(prompt:str, num:int):
    res_list = []
    for _ in range(num):
        result = llm(prompt)
        json_object = json.loads(result)
        res_list.append(json_object)
    return res_list

def verify_authorization(api, username):
    for user in fake_users_db:
        if(user==username):
            if api in fake_users_db[user]['authorized_api']:
                return True
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not enough permissions",
                #headers={"WWW-Authenticate": authenticate_value},
            )
    
    raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not enough permissions",
                #headers={"WWW-Authenticate": authenticate_value},
            )

def verify_department(department, username):
    for user in fake_users_db:
        if(user==username):
            if department in fake_users_db[user]['department']:
                return True
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="You don't belong to this department",
                #headers={"WWW-Authenticate": authenticate_value},
            )
    
    raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="You don't belong to this department",
                #headers={"WWW-Authenticate": authenticate_value},
            )


@app.post("/patients/") #Ritorna tutti i pazienti di un reparto
async def get_patients_info(department:str, username = Depends(check_valid_token)):
    # Returns a list of users.
    verify_authorization("/patients", username)
    """
    url prendo reparto -> verifico il reparto corretto -> creo dati finti/401
    """
    verify_department(department, username)

    if use_model:
        result = create_data(f"Describe patient with name, tax id code, data of start recovery (in format DD-MM-YYYY), data of end recovery (in format DD-MM-YYYY), department equals to {department} , illness, and a list with one or two elements of drugs with name, dose, frequency and duration in JSON format:",2)
    else:
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

@app.post("/patient") #ritorna un paziente di un reparto
async def get_patient_info(department:str, patient:str, username = Depends(check_valid_token)):
    # Returns a list of users.

    verify_authorization("/patient", username)
    verify_department(department, username) #Non si controlla che l'utente esista e appartenga al reparto indicato

    if use_model:
        result = create_data(f"Describe patient with name equals to {patient}, tax id code, department equals to {department}, data of start recovery (in format DD-MM-YYYY), data of end recovery (in format DD-MM-YYYY), illness, and a list with one or two elements of drugs with name, dose, frequency and duration in JSON format:",1)
    else:
        result = {
            "a":1
        }
    
    users = [
        { 'username': 'L', 'email': 'janedoe@example.com'},
        { 'username': 'C', 'email': 'johndoe@example.com'}
    ]

    return result

@app.post("/patient/me/") #ritorna le mie informazioni
async def get_patient_me_info(username = Depends(check_valid_token)):

    verify_authorization("/patient/me", username)
    """
    url prendo reparto -> verifico il reparto corretto -> creo dati finti/401
    """

    if use_model:
        result = create_data(f"Describe patient with name, tax id code, name of his doctor, department, data of start recovery (in format DD-MM-YYYY), data of end recovery (in format DD-MM-YYYY), illness, and a list with one or two elements of drugs with name, dose, frequency and duration in JSON format:",1)
    else:
        result = {
            "a":1
        }
    
    users = [
        { 'username': 'L', 'email': 'janedoe@example.com'},
        { 'username': 'C', 'email': 'johndoe@example.com'}
    ]

    return result

@app.post("/prescriptions") #Restituisce le informazioni di tutte le prescrizioni all'interno di un reparto
async def get_prescriptions_of_department(department:str, username = Depends(check_valid_token)):

    verify_authorization("/prescriptions", username)
    verify_department(department, username) #Non si controlla che l'utente esista e appartenga al reparto indicato

    if use_model:
        result = create_data(f"Describe prescription with name of client, tax id code of client, department of the client equal to {department} and a list with one or two elements of drugs with name, dose, frequency and duration in JSON format:",2)
    else:
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

@app.post("/prescription") #Restituisce le prescrizioni di un particolare utente
async def get_patient_prescription_info(department:str, patient:str, username = Depends(check_valid_token)):

    verify_authorization("/prescriptions", username)
    verify_department(department, username) #Non si controlla che l'utente esista e appartenga al reparto indicato

    if use_model:
        result = create_data(f"Describe prescription with name of client equals to {patient}, tax id code of client, department of the client equal to {department} and a list with one or two elements of drugs with name, dose, frequency and duration in JSON format:",2)
    else:
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

@app.post("/prescription/me") #Tutte le mie prescrizioni
async def add_new_prescription(username = Depends(check_valid_token)):
    # Returns a list of users.

    verify_authorization("/prescription/me", username)
    if use_model:
        result = create_data(f"Describe prescription with name of client equals to {username}, tax id code of client, department of the client and a list with one or two elements of drugs with name, dose, frequency and duration in JSON format:",2)
    else:
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

@app.post("/doctors") #Tutti i dottori presenti
async def get_doctors(username = Depends(check_valid_token)):
    # Returns a list of users.

    verify_authorization("/doctors", username)

    if use_model:
        result = create_data("Describe doctor with name, tax id code, his department, age, telephone number:",3)
    else:
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

@app.post("/doctors/department") #Tutti i dottori di un reparto presenti
async def get_doctors(department:str, username = Depends(check_valid_token)):
    # Returns a list of users.

    verify_authorization("/doctors", username)

    if use_model:
        result = create_data(f"Describe doctor with name, tax id code, department equals to {department}, age, telephone number:",3)
    else:
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