# restAPIServer

Project for Cybersecurity M.

Made by:
- Luca Dominici
- Enrico Zacchiroli
- Lorenzo Ziosi

## Usage
docker-compose.yaml unico file necessario per l'avvio del sistema, utilizzabile con il comando:  
`docker-compose -f docker-compose.yaml up`

## OAuth login credentials
- `dottore:secret` , appartiene al dipartimento di Cardiologia, API a cui può avere accesso:  
"authorized_api": ["/patients", "/prescriptions", "/doctors", "/doctors/department", "/patient", "/patient/me", "/prescription/me"]
- `infermiere:ciao` , appartiene al dipartimento di Urologia (quindi non può vedere le informazioni riguardanti il dipartimento di cardiologia), API a cui può avere accesso:  
"authorized_api": ["/doctors","/prescriptions","/patient/me","/prescription/me"]
- `paziente:ciao` , API a cui può avere accesso:  
"authorized_api": ["/patient/me", "/prescription/me","/doctors"]

## Client registration redirect URL
`http://localhost:5000/callback`

## API docs
`http://localhost:8000/redoc`

`http://localhost:8000/docs`
