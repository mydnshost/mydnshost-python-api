FROM python:3-alpine AS builder

WORKDIR /usr/src/app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install dependencies for building cryptography package
RUN apk add git libffi-dev openssl-dev build-base && \
    pip install --upgrade pip && \
    python -m pip install --upgrade pip build wheel

COPY pyproject.toml pyproject.toml
COPY mydnshost mydnshost
COPY .git .git
COPY README.md README.md

RUN python -m build && \
    pip wheel --no-cache-dir --no-deps --wheel-dir /usr/src/app/wheels -r mydnshost/requirements.txt && \
    pip wheel --no-cache-dir --no-deps --wheel-dir /usr/src/app/wheels dist/*.whl

FROM python:3-alpine AS app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /usr/src/app

COPY --from=builder /usr/src/app/wheels /wheels/
RUN pip install --no-cache /wheels/*

ENTRYPOINT [ "mydnshost" ]
