FROM python:3.11.7-alpine
WORKDIR /app

COPY . /app
EXPOSE 5001
RUN pip install -r requirements.txt
CMD ["python", "auth_server.py"]