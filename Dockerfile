FROM python:3.9.22-slim-bullseye

WORKDIR /app

COPY  /app . 

#CAs Location
#RUN mkdir -p /app/certs/CAs

RUN python -m pip install --upgrade pip

RUN pip install --no-cache-dir -r requirements.txt

ENV PYTHONUNBUFFERED=1

CMD ["flask", "run", "--host=0.0.0.0"]

