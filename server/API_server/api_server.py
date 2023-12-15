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

# to get a string like this run:
# openssl rand -hex 32
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "RS256"#"HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
VERIFY_TOKEN_PATH = "http://127.0.0.1:5001/user" 
#TOKEN_PATH = "http://127.0.0.1:5001/user"

class Drug(BaseModel):
    name:str | None = "Drug name"
    dose:str | None = "Drug dose"
    frequency:str | None = "Drug frequency"
    duration:str | None = "Drug duration"

class Patient(BaseModel):
    name: str | None = "Patient name"
    doctor_name: str | None = "Patient doctor_name"
    tax_id_code: str | None = "Patient tax_id_code"
    date_start_recovery: str | None = "Patient date_start_recovery"
    date_end_recovery: str | None = "Patient date_end_recovery"
    department: str | None = "Patient department"
    illness: str | None = "Patient illness"
    drugs: list[Drug] | None = []

class Prescription(BaseModel):
    client_name: str | None = "Prescription client_name"
    client_tax_id_code: str | None = "Prescription client_tax_id_code"
    department: str | None = "Prescription department"
    drugs: list[Drug] | None = []

class Doctor(BaseModel):
    name: str | None = "Doctor name"
    tax_id_code: str | None = "Doctor tax_id_code"
    department: str | None = "Doctor department"
    age: str | None = "Doctor age"
    telephone_number: str | None = "Doctor telephone_number"

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

def verify_authorization(api, username):
    print(f"api {api}, username {username}")
    for user in fake_users_db:
        if(user==username):
            if api in fake_users_db[user]['authorized_api']:
                return True
            raise HTTPException(
                status_code=403,
                detail="Not enough permissions",
                #headers={"WWW-Authenticate": authenticate_value},
            )
    
    raise HTTPException(
                status_code=403,
                detail="Not enough permissions",
                #headers={"WWW-Authenticate": authenticate_value},
            )

def verify_department(department, username):
    for user in fake_users_db:
        if(user==username):
            if department in fake_users_db[user]['department']:
                return True
            raise HTTPException(
                status_code=403,
                detail="You don't belong to this department",
                #headers={"WWW-Authenticate": authenticate_value},
            )
    
    raise HTTPException(
                status_code=403,
                detail="You don't belong to this department",
                #headers={"WWW-Authenticate": authenticate_value},
            )

@app.post("/patients/",summary="Get info about all patients of one department", tags=["Doctor"], response_model=list[Patient],responses={
            403: {"description": "You don't belong to this department or you don't have enough permissions"}, 401: {"description": "Token invalid or expired"}
         })
async def get_patients_info(department:str, username = Depends(check_valid_token)):
    


    verify_authorization("/patients", username)
    verify_department(department, username)
    #res = list[Patient]
    res = []

    if username=="user1": #Solo user1 può usare questo endpoint
        #Patient 1
        patient = Patient()
        patient.name = "John Smith"
        patient.doctor_name = "Dr. Jane Smith"
        patient.department = department
        patient.date_start_recovery = "01-02-2020"
        patient.date_end_recovery = "01-06-2020"
        patient.illness = "Coronary artery disease"
        patient.tax_id_code = "123-456-789"
        drug1 = Drug()
        drug1.name = "Metoprolol"
        drug1.dose = "50 mg"
        drug1.duration = "2 weeks"
        drug1.frequency = "1 time/day"
        drug2 = Drug()
        drug2.name = "Aspirin"
        drug2.dose = "325 mg"
        drug2.duration = "3 weeks"
        drug2.frequency = "1 time/day"
        drugs = []
        drugs.append(drug1)
        drugs.append(drug2)
        patient.drugs = drugs
        res.append(patient)
        #Patient 2
        patient = Patient()
        patient.name = "Alex Sanchez"
        patient.department = department
        patient.doctor_name = username
        patient.date_start_recovery = "14-07-2022"
        patient.date_end_recovery = "01-09-2022"
        patient.illness = "Heart Attack"
        patient.tax_id_code = "99887654"
        drug1 = Drug()
        drug1.name = "Acetylcysteine"
        drug1.dose = "240 mg"
        drug1.duration = "35 days"
        drug1.frequency = "2 time/day"
        drugs = []
        drugs.append(drug1)
        patient.drugs = drugs
        res.append(patient)

    return res

@app.post("/patient", summary="Get info about a patient of one department",tags=["Doctor"],response_model=Patient, responses={
            403: {"description": "You don't belong to this department or you don't have enough permissions"}, 401: {"description": "Token invalid or expired"}})
async def get_patient_info(department:str, patient:str, username = Depends(check_valid_token)):

    verify_authorization("/patient", username)
    verify_department(department, username)
    p = Patient()

    if username=="user1": #Solo user1 può usare questo endpoint
        #Patient 1
        p.name = patient
        p.department = department
        p.doctor_name = "Dr. Doe"
        p.date_start_recovery = "20-07-2021"
        p.date_end_recovery = "22-08-2021"
        p.illness = "Cardiomyopathy"
        p.tax_id_code = "125-756-489"
        drug1 = Drug()
        drug1.name = "Lisinopril"
        drug1.dose = "5"
        drug1.duration = "30 days"
        drug1.frequency = "2 times/day"
        drug2 = Drug()
        drug2.name = "Atenolol"
        drug2.dose = "25 mg"
        drug2.duration = "60 days"
        drug2.frequency = "1 time/day"
        drugs = []
        drugs.append(drug1)
        drugs.append(drug2)
        p.drugs = drugs

    return p

@app.post("/patient/me/", summary="Get my info as a patient",tags=["Doctor","Nurse","Patient"], response_model=Patient, responses={
            403: {"description": "You don't have enough permissions"}, 401: {"description": "Token invalid or expired"}})
async def get_patient_me_info(username = Depends(check_valid_token)):

    verify_authorization("/patient/me", username)
    department = ""
    for user in fake_users_db:
        if(user==username):
            department = fake_users_db[user]['department']
    patient = Patient()

    if username == "user1":
        patient.name = username
        patient.doctor_name = "Dr. Rose"
        patient.department = department
        patient.date_start_recovery = "20-07-2021"
        patient.date_end_recovery = "22-08-2021"
        patient.illness = "Cardiomyopathy"
        patient.tax_id_code = "125-756-489"
        drug1 = Drug()
        drug1.name = "Lisinopril"
        drug1.dose = "5"
        drug1.duration = "30 days"
        drug1.frequency = "2 times/day"
        drug2 = Drug()
        drug2.name = "Atenolol"
        drug2.dose = "25 mg"
        drug2.duration = "60 days"
        drug2.frequency = "1 time/day"
        drugs = []
        drugs.append(drug1)
        drugs.append(drug2)
        patient.drugs = drugs
    elif username == "user2":
        patient.name = username
        patient.doctor_name = "Dr. Dahmer"
        patient.department = department
        patient.date_start_recovery = "22-05-2022"
        patient.date_end_recovery = "28-06-2022"
        patient.illness = "Cardiomyopathy"
        patient.tax_id_code = "Gastroenteritis"
        drug1 = Drug()
        drug1.name = "Ondansetron"
        drug1.dose = "5 mg"
        drug1.duration = "6 days"
        drug1.frequency = "3 times/day"
        drug2 = Drug()
        drug2.name = "Loperamide"
        drug2.dose = "1 capsule every 8 hours"
        drug2.duration = "6 weeks"
        drug2.frequency = "As needed"
        drugs = []
        drugs.append(drug1)
        drugs.append(drug2)
        patient.drugs = drugs
    else:
        patient.name = username
        patient.department = department
        patient.doctor_name = "Dr. Gacy"
        patient.date_start_recovery = "21-08-2021"
        patient.date_end_recovery = "31-12-2021"
        patient.illness = "Depression"
        patient.tax_id_code = "135-656-252"
        drug1 = Drug()
        drug1.name = "Amitriptyline"
        drug1.dose = "50mg"
        drug1.duration = "90 days"
        drug1.frequency = "once a day"
        drug2 = Drug()
        drug2.name = "Diazepam"
        drug2.dose = "5 mg"
        drug2.duration = "20 days"
        drug2.frequency = "as needed"
        drugs = []
        drugs.append(drug1)
        drugs.append(drug2)
        patient.drugs = drugs

    return patient

@app.post("/prescriptions", summary="Get all prescriptions of one department",tags=["Doctor","Nurse"], response_model=list[Prescription], responses={
            403: {"description": "You don't belong to this department or you don't have enough permissions"}, 401: {"description": "Token invalid or expired"}}) 
async def get_prescriptions_of_department(department:str, username = Depends(check_valid_token)):

    verify_authorization("/prescriptions", username)
    verify_department(department, username)

    res = []
    if username == "user1":
        p = Prescription()
        p.client_name = "Jane Doe"
        p.client_tax_id_code = "123-45-6789"
        p.department = department
        drugs = []
        d = Drug()
        d.name = "Drug1"
        d.dose = "20mg"
        d.duration = "Once a day"
        d.frequency = "3 weeks"
        drugs.append(d)
        d = Drug()
        d.name = "Lisinopril"
        d.dose = "20mg"
        d.duration = "Twice daly"
        d.frequency = "3 months"
        drugs.append(d)
        p.drugs = drugs
        res.append(p)
        p = Prescription()
        p.client_name = "John Smith"
        p.client_tax_id_code = "173-48-2709"
        p.department = department
        drugs = []
        d = Drug()
        d.name = "Metoprolol"
        d.dose = "50mg"
        d.duration = "Twice daly"
        d.frequency = "6 months"
        drugs.append(d)
        d = Drug()
        d.name = "Lisinopril"
        d.dose = "5"
        d.duration = "30 days"
        d.frequency = "2 times/day"
        drugs.append(d)
        p.drugs = drugs
        res.append(p)
    else: #urology
        p = Prescription()
        p.client_name = "Alex Doe"
        p.client_tax_id_code = "343-75-9729"
        p.department = department
        drugs = []
        d = Drug()
        d.name = "Ciprofloxacin"
        d.dose = "500mg"
        d.duration = "Two times a day"
        d.frequency = "1 week"
        drugs.append(d)
        d = Drug()
        d.name = "Cephalexin"
        d.dose = "1 g"
        d.duration = "Four times a day"
        d.frequency = "5 days"
        drugs.append(d)
        p.drugs = drugs
        res.append(p)
        p = Prescription()
        p.client_name = "John Frank"
        p.client_tax_id_code = "347-28-4641"
        p.department = department
        drugs = []
        d = Drug()
        d.name = "Darifenacin"
        d.dose = "10mg"
        d.duration = "Four times a day"
        d.frequency = "6 weeks"
        drugs.append(d)
        d = Drug()
        d.name = "Mirabegron"
        d.dose = "50 g"
        d.duration = "12 weeks"
        d.frequency = "2 times/day"
        drugs.append(d)
        p.drugs = drugs
        res.append(p)
    return res

@app.post("/prescription", summary="Get all prescriptions of one patient",tags=["Doctor","Nurse"], response_model=list[Prescription], responses={
            403: {"description": "You don't belong to this department or you don't have enough permissions"}, 401: {"description": "Token invalid or expired"}})
async def get_patient_prescription_info(department:str, patient:str, username = Depends(check_valid_token)):

    verify_authorization("/prescriptions", username)
    verify_department(department, username)

    res = []
    if username == "user1":
        p = Prescription()
        p.client_name = patient
        p.client_tax_id_code = "123-45-6789"
        p.department = department
        drugs = []
        d = Drug()
        d.name = "Drug1"
        d.dose = "20mg"
        d.duration = "Once a day"
        d.frequency = "3 weeks"
        drugs.append(d)
        d = Drug()
        d.name = "Lisinopril"
        d.dose = "20mg"
        d.duration = "Twice daly"
        d.frequency = "3 months"
        drugs.append(d)
        p.drugs = drugs
        res.append(p)
        p = Prescription()
        p.client_name = patient
        p.client_tax_id_code = "173-48-2709"
        p.department = department
        drugs = []
        d = Drug()
        d.name = "Metoprolol"
        d.dose = "50mg"
        d.duration = "Twice daly"
        d.frequency = "6 months"
        drugs.append(d)
        d = Drug()
        d.name = "Lisinopril"
        d.dose = "5"
        d.duration = "30 days"
        d.frequency = "2 times/day"
        drugs.append(d)
        p.drugs = drugs
        res.append(p)
    else: #urology
        p = Prescription()
        p.client_name = patient
        p.client_tax_id_code = "343-75-9729"
        p.department = department
        drugs = []
        d = Drug()
        d.name = "Ciprofloxacin"
        d.dose = "500mg"
        d.duration = "Two times a day"
        d.frequency = "1 week"
        drugs.append(d)
        d = Drug()
        d.name = "Cephalexin"
        d.dose = "1 g"
        d.duration = "Four times a day"
        d.frequency = "5 days"
        drugs.append(d)
        p.drugs = drugs
        res.append(p)
        p = Prescription()
        p.client_name = patient
        p.client_tax_id_code = "347-28-4641"
        p.department = department
        drugs = []
        d = Drug()
        d.name = "Darifenacin"
        d.dose = "10mg"
        d.duration = "Four times a day"
        d.frequency = "6 weeks"
        drugs.append(d)
        d = Drug()
        d.name = "Mirabegron"
        d.dose = "50 g"
        d.duration = "12 weeks"
        d.frequency = "2 times/day"
        drugs.append(d)
        p.drugs = drugs
        res.append(p)
    return res

@app.post("/prescription/me", summary="Get all personal prescriptions",tags=["Doctor","Nurse","Patient"], response_model=list[Prescription], responses={
            403: {"description": "You don't have enough permissions"}, 401: {"description": "Token invalid or expired"}}) 
async def add_new_prescription(username = Depends(check_valid_token)):

    verify_authorization("/prescription/me", username)

    res = []
    if username == "user1":
        p = Prescription()
        p.client_name = username
        p.client_tax_id_code = "123-45-6789"
        p.department = "Cardiology"
        drugs = []
        d = Drug()
        d.name = "Drug1"
        d.dose = "20mg"
        d.duration = "Once a day"
        d.frequency = "3 weeks"
        drugs.append(d)
        d = Drug()
        d.name = "Lisinopril"
        d.dose = "20mg"
        d.duration = "Twice daly"
        d.frequency = "3 months"
        drugs.append(d)
        p.drugs = drugs
        res.append(p)
        p = Prescription()
        p.client_name = username
        p.client_tax_id_code = "173-48-2709"
        p.department = "Cardiology"
        drugs = []
        d = Drug()
        d.name = "Metoprolol"
        d.dose = "50mg"
        d.duration = "Twice daly"
        d.frequency = "6 months"
        drugs.append(d)
        d = Drug()
        d.name = "Lisinopril"
        d.dose = "5"
        d.duration = "30 days"
        d.frequency = "2 times/day"
        drugs.append(d)
        p.drugs = drugs
        res.append(p)
    elif username=="user2": #urology
        p = Prescription()
        p.client_name = username
        p.client_tax_id_code = "343-75-9729"
        p.department = "Urology"
        drugs = []
        d = Drug()
        d.name = "Ciprofloxacin"
        d.dose = "500mg"
        d.duration = "Two times a day"
        d.frequency = "1 week"
        drugs.append(d)
        d = Drug()
        d.name = "Cephalexin"
        d.dose = "1 g"
        d.duration = "Four times a day"
        d.frequency = "5 days"
        drugs.append(d)
        p.drugs = drugs
        res.append(p)
        p = Prescription()
        p.client_name = username
        p.client_tax_id_code = "343-75-9729"
        p.department = "Urology"
        drugs = []
        d = Drug()
        d.name = "Darifenacin"
        d.dose = "10mg"
        d.duration = "Four times a day"
        d.frequency = "6 weeks"
        drugs.append(d)
        d = Drug()
        d.name = "Mirabegron"
        d.dose = "50 g"
        d.duration = "12 weeks"
        d.frequency = "2 times/day"
        drugs.append(d)
        p.drugs = drugs
        res.append(p)
    else:
        p = Prescription()
        p.client_name = username
        p.client_tax_id_code = "321-55-2172"
        p.department = "Oncology"
        drugs = []
        d = Drug()
        d.name = "Morphine"
        d.dose = "5mg"
        d.duration = "3 week"
        d.frequency = "One time a day"
        drugs.append(d)
        d = Drug()
        d.name = "Dacomitinib"
        d.dose = "10 mg"
        d.duration = "5 weeks"
        d.frequency = "Four times a day"
        drugs.append(d)
        p.drugs = drugs
        res.append(p)
        p = Prescription()
        p.client_name = username
        p.client_tax_id_code = "321-55-2172"
        p.department = "Urology"
        drugs = []
        d = Drug()
        d.name = "Fentanyl"
        d.dose = "2mg"
        d.duration = "6 weeks"
        d.frequency = "One times a day"
        drugs.append(d)
        d = Drug()
        d.name = "Pentostatin"
        d.dose = "10 mg"
        d.duration = "10 weeks"
        d.frequency = "3 times/day"
        drugs.append(d)
        p.drugs = drugs
        res.append(p)
    return res

@app.post("/doctors", summary="Get all doctors",tags=["Doctor","Nurse","Patient"], response_model=list[Doctor], responses={
            403: {"description": "You don't have enough permissions"}, 401: {"description": "Token invalid or expired"}})
async def get_doctors(username = Depends(check_valid_token)):

    verify_authorization("/doctors", username)

    res = []
    
    d = Doctor()
    d.name = "Dr. John Smith"
    d.tax_id_code = "123-45-6780"
    d.department = "Neurosurgery Department"
    d.telephone_number = "(123) 456-7890"
    d.age = "58"
    res.append(d)
    d = Doctor()
    d.name = "Dr. Josh Jackson"
    d.tax_id_code = "243-85-7720"
    d.department = "General Surgery"
    d.telephone_number = "(123) 466-2844"
    d.age = "41"
    res.append(d)
    d = Doctor()
    d.name = "Dr. Alexia Doe"
    d.tax_id_code = "423-15-9746"
    d.department = "Orthopedics"
    d.telephone_number = "(123) 555-1395"
    d.age = "35"
    res.append(d)

    return res

@app.post("/doctors/department", summary="Get all doctors of one department",tags=["Doctor","Nurse","Patient"], response_model=list[Doctor], responses={
            403: {"description": "You don't have enough permissions"}, 401: {"description": "Token invalid or expired"}})
async def get_doctors(department:str, username = Depends(check_valid_token)):

    verify_authorization("/doctors", username)

    res = []
    
    d = Doctor()
    d.name = "Dr. Alex Theory"
    d.tax_id_code = "522-15-8720"
    d.department = department
    d.telephone_number = "(123) 126-5670"
    d.age = "68"
    res.append(d)
    d = Doctor()
    d.name = "Dr. Josh Dowe"
    d.tax_id_code = "233-62-2528"
    d.department = department
    d.telephone_number = "(123) 416-5362"
    d.age = "35"
    res.append(d)
    d = Doctor()
    d.name = "Dr. Josh Green"
    d.tax_id_code = "226-53-6676"
    d.department = department
    d.telephone_number = "(133) 563-6337"
    d.age = "30"
    res.append(d)

    return res