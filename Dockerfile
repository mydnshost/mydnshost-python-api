FROM python:3-alpine

WORKDIR /usr/src/app

COPY requirements.txt ./

# Install dependencies for building cryptography package
RUN apk add libffi-dev openssl-dev build-base

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENTRYPOINT [ "python", "./cli.py" ]
