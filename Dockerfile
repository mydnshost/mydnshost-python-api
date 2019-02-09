FROM python:3-alpine

WORKDIR /usr/src/app

COPY requirements.txt ./

# Install dependencies for building cryptography package
RUN apk add libffi-dev openssl-dev build-base

# Use --no-use-pep517 due to https://github.com/pypa/pip/issues/6197
RUN pip install --no-cache-dir --no-use-pep517 -r requirements.txt

COPY . .

ENTRYPOINT [ "python", "./cli.py" ]
