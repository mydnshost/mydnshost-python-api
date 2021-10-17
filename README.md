# mydnshost-python-api

Python API and CLI tool for [mydnshost.co.uk](https://www.mydnshost.co.uk/).

This implements version 1.0 of the API as documented at https://api.mydnshost.co.uk/1.0/docs/

## Installation

### Using pip

To install the latest version from git:

```
    $ pip3 install --upgrade git+https://github.com/mydnshost/mydnshost-python-api.git
```

Note that this tool requires Python 3.

### Using docker

To run using docker, simply:

```
    $ docker run --rm -it registry.shanemcc.net/mydnshost-public/python-api -h
```

## Command line

### Basic usage

Creating two new AAAA records:

```
    $ mydnshost records add fqdn.example.com AAAA fdda:5cc1:23:4::1f fdda:5cc1:23:4::10
```

Using a custom TTL:

```
    $ mydnshost records add fqdn.example.com A 8.8.8.8 --ttl 1440
```

Listing records:

```
    $ mydnshost records list fqdn.example.com
```

Deleting all records for a subdomain:

```
    $ mydnshost records rm fqdn.example.com
```

Deleting two specific AAAA records:

```
    $ mydnshost records add fqdn.example.com AAAA fdda:5cc1:23:4::1f fdda:5cc1:23:4::10
```

### Authentication

The command-line interface only supports API-key based authentication. Supply the username
and API key in the environment variables `MYDNSHOST_AUTH_USER` and `MYDNSHOST_AUTH_KEY`.
Alternatively, pass them in using the `--auth-user` and `--auth-key` arguments (but bear
in mind that your credentials will be visible in the process list).
