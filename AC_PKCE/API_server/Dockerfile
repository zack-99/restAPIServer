FROM python:3.11.7-alpine
WORKDIR /app

COPY . /app
RUN apk update && apk upgrade
RUN apk add build-base 
RUN pip install -r requirements.txt
CMD ["python", "-m", "uvicorn", "FASTAPI_server:app", "--reload", "--port=8000", "--host=0.0.0.0"]

