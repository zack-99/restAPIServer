from datetime import datetime, timedelta
import json
import requests
import os
from typing import Annotated
from fastapi import Depends, FastAPI, HTTPException, Security, status, Form, Request, Query
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
VERIFY_TOKEN_PATH = "http://127.0.0.1:5001/user" 
#TOKEN_PATH = "http://127.0.0.1:5001/user"

#MODEL
MODEL_PATH = "./llama-model/openorca-platypus2-13b.ggmlv3.gguf.q4_0.bin"
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
    grammar_path="./llama-model/json.gbnf",
)
use_model = True #Set False to not use llm



fake_users_db = {
    "user1": { #Primario
        "authorized_api": ["/patients", "/prescriptions", "/doctors", "/doctors/department", "/patient", "/patient/me", "/prescription/me"],
        "department": "Cardiologia",
    },
    "user2": { #Infermire
        "authorized_api": ["/doctors","/prescriptions","/patient/me","prescription/me"],
        "department": "Urologia",
    },
    "user3": { #Paziente
        "authorized_api": ["/patient/me", "/prescription/me","/doctors"],
        "department": "Oncologia"
    },
}


tags_metadata = [
    {
        "name": "Doctor",
        "description": "Operations allowed to doctors",
    },
    {
        "name":"Nurse",
        "description": "Operations allowed to nurses",
    },
    {
        "name": "Patient",
        "description": "Operations allowed to patients",
    },
]

app = FastAPI(title="Hospital fake server",openapi_tags=tags_metadata)

with open('public.pem', 'rb') as fh:
    public_key = jwk_from_pem(fh.read())


#Return username if token is valid or HTTPException
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
        username = requests.post(os.getenv("VERIFY_TOKEN_PATH",default=VERIFY_TOKEN_PATH), data = {
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
    print(f"api {api}, username {username}")
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

class User(BaseModel):
    name:str | None = None
    age:str | None = None


@app.post("/patients/",summary="Get info about all patients of one department", tags=["Doctor"], response_model=User)
async def get_patients_info(department:str, username = Depends(check_valid_token)):
    
    verify_authorization("/patients", username)
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

@app.post("/patient", summary="Get info about a patient of one department",tags=["Doctor"])
async def get_patient_info(department:str, patient:str, username = Depends(check_valid_token)):

    verify_authorization("/patient", username)
    verify_department(department, username)

    if use_model:
        result = create_data(f"Describe patient with name equals to {patient}, tax id code, department equals to cardiology, data of start recovery (in format DD-MM-YYYY), data of end recovery (in format DD-MM-YYYY), illness, and a list with one or two elements of drugs with name, dose, frequency and duration in JSON format:",1)
    else:
        result = {
            "a":1
        }

    return result

@app.post("/patient/me/", summary="Get my info as a patient",tags=["Doctor","Nurse","Patient"])
async def get_patient_me_info(username = Depends(check_valid_token)):

    verify_authorization("/patient/me", username)

    if use_model:
        result = create_data(f"Describe patient with name, tax id code, name of his doctor, department, data of start recovery (in format DD-MM-YYYY), data of end recovery (in format DD-MM-YYYY), illness, and a list with one or two elements of drugs with name, dose, frequency and duration in JSON format:",1)
    else:
        result = {
            "a":1
        }

    return result

@app.post("/prescriptions", summary="Get all prescriptions of one department",tags=["Doctor","Nurse"]) 
async def get_prescriptions_of_department(department:str, username = Depends(check_valid_token)):

    verify_authorization("/prescriptions", username)
    verify_department(department, username)

    if use_model:
        result = create_data(f"Describe prescription with name of client, tax id code of client, department of the client equal to urology and a list with one or two elements of drugs with name, dose, frequency and duration in JSON format:",2)
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

@app.post("/prescription", summary="Get all prescriptions of one patient",tags=["Doctor","Nurse"]) 
async def get_patient_prescription_info(department:str, patient:str, username = Depends(check_valid_token)):

    verify_authorization("/prescriptions", username)
    verify_department(department, username) 

    if use_model:
        result = create_data(f"Describe prescription with name of client equals to {patient}, tax id code of client, department of the client equal to cardiology and a list with one or two elements of drugs with name, dose, frequency and duration in JSON format:",2)
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

@app.post("/prescription/me", summary="Get all personal prescriptions",tags=["Doctor","Nurse","Patient"]) 
async def add_new_prescription(username = Depends(check_valid_token)):

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

@app.post("/doctors", summary="Get all doctors",tags=["Doctor","Nurse","Patient"])
async def get_doctors(username = Depends(check_valid_token)):

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

@app.post("/doctors/department", summary="Get all doctors of one department",tags=["Doctor","Nurse","Patient"])
async def get_doctors(department:str, username = Depends(check_valid_token)):

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
