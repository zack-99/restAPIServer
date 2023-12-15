FROM python:3.11.7-alpine
WORKDIR /app

COPY . /app
EXPOSE 5000
RUN pip install -r requirements.txt
CMD ["python", "client.py"]