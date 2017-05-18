# mydnshost-python-api

Python API for [mydnshost.co.uk](https://www.mydnshost.co.uk/).

This implements version 1.0 of the API as documented at https://api.mydnshost.co.uk/1.0/docs/

## Command line

### Basic usage

```
mydnsapi records {list|add|rm} [--ttl N] [--priority N] fqdn.example.com AAAA fdda:5cc1:23:4::1f
```

### Authentication

The command-line interface only supports API-key based authentication. Supply the username
and API key in the environment variables `MYDNSHOST_AUTH_USER` and `MYDNSHOST_AUTH_KEY`.
Alternatively, pass them in using the `--auth-user` and `--auth-key` arguments (but bear
in mind that your credentials will be visible in the process list).