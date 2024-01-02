FROM python:3.11.6

ADD . /app
WORKDIR /app

RUN pip install -r requirements.txt
CMD ["flask", "run", "--host=0.0.0.0", "--port=80"]