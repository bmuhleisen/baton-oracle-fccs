# `baton-oracle-fccs`

`baton-oracle-fccs` is a connector for Oracle Financial Consolidation and Close Cloud Service (FCCS) built using the Baton SDK. It works with the Oracle FCCS REST API to sync data about users, groups, and roles.

Check out [Baton](https://github.com/ConductorOne/baton) to learn more about the project in general.

## Prerequisites

This connector is scoped to **FCCS only** (sync + grants for FCCS groups and roles). User lifecycle operations (create/update/delete) are intentionally **not** supported here and should be handled via your dedicated IDCS connector.

## Authentication

This connector uses **OAuth JWT User Assertion** authentication. This method provides user-context tokens required by Oracle FCCS Security APIs.

> **Note:** OAuth 2 authentication is only available in **OCI Gen 2** environments. Classic environments must be migrated to Gen 2 to use this connector.

### Required Configuration

| Field | Environment Variable | Description |
|-------|---------------------|-------------|
| `--base-url` | `BATON_BASE_URL` | Base URL of your Oracle FCCS instance (e.g., `https://example.epm.us2.oraclecloud.com`) |
| `--oracle-client-id` | `BATON_ORACLE_CLIENT_ID` | OAuth client ID from Oracle IDCS |
| `--oracle-client-secret` | `BATON_ORACLE_CLIENT_SECRET` | OAuth client secret from Oracle IDCS |
| `--token-url` | `BATON_TOKEN_URL` | OAuth2 token URL (e.g., `https://idcs-xxx.identity.oraclecloud.com/oauth2/v1/token`) |
| `--jwt-private-key` | `BATON_JWT_PRIVATE_KEY` | RSA private key (PEM or base64-encoded PEM) for signing JWT assertions |
| `--jwt-subject` | `BATON_JWT_SUBJECT` | Username to impersonate in the JWT assertion (sub claim) |

### Optional Configuration

| Field | Environment Variable | Description |
|-------|---------------------|-------------|
| `--jwt-key-id` | `BATON_JWT_KEY_ID` | Key ID (kid) matching the certificate uploaded to IDCS |
| `--jwt-issuer` | `BATON_JWT_ISSUER` | JWT issuer claim (defaults to `--oracle-client-id`) |
| `--jwt-audience` | `BATON_JWT_AUDIENCE` | JWT audience claim (defaults to `--token-url`) |
| `--scope` | `BATON_SCOPE` | OAuth2 scope for the token request (see below) |

### OAuth Scope

The `--scope` parameter specifies which Oracle Cloud resources the access token can access. Common values:

| Scope | Description |
|-------|-------------|
| `urn:opc:idm:__myscopes__` | Request all scopes the client is authorized for (recommended) |

For EPM Cloud environments, Oracle IDCS typically configures scopes in the format:
```
urn:opc:serviceInstanceID=<instance-id>:urn:opc:resource:consumer/*
```

You can find the exact scope in your IDCS application configuration under **Resources > Scopes**. If omitted, the token will use the default scopes configured in your IDCS application.

### Setting Up JWT Authentication

1. Create an OAuth client in Oracle Identity Cloud Service (IDCS) or OCI IAM Identity Domain
2. Enable the **JWT Assertion** grant type for the client
3. Generate an RSA key pair (2048-bit or higher recommended)
4. Upload the public key certificate to IDCS under **Security > Trusted Partner Certificates**
5. Note the certificate alias (this becomes your `--jwt-key-id`)
6. Ensure the service user specified in `--jwt-subject` has appropriate access to Oracle FCCS

## Getting Started

### brew

```bash
brew install conductorone/baton/baton conductorone/baton/baton-oracle-fccs

BATON_BASE_URL=https://example.epm.us2.oraclecloud.com \
BATON_ORACLE_CLIENT_ID=your_client_id \
BATON_ORACLE_CLIENT_SECRET=your_client_secret \
BATON_TOKEN_URL=https://idcs-xxx.identity.oraclecloud.com/oauth2/v1/token \
BATON_JWT_PRIVATE_KEY="$(cat /path/to/private_key.pem)" \
BATON_JWT_SUBJECT=fccs_service_account \
BATON_JWT_KEY_ID=my-key-id \
baton-oracle-fccs

baton resources
```

### docker

```bash
docker run --rm -v $(pwd):/out \
  -e BATON_BASE_URL=https://example.epm.us2.oraclecloud.com \
  -e BATON_ORACLE_CLIENT_ID=your_client_id \
  -e BATON_ORACLE_CLIENT_SECRET=your_client_secret \
  -e BATON_TOKEN_URL=https://idcs-xxx.identity.oraclecloud.com/oauth2/v1/token \
  -e BATON_JWT_PRIVATE_KEY="$(cat /path/to/private_key.pem)" \
  -e BATON_JWT_SUBJECT=fccs_service_account \
  -e BATON_JWT_KEY_ID=my-key-id \
  ghcr.io/conductorone/baton-oracle-fccs:latest -f "/out/sync.c1z"

docker run --rm -v $(pwd):/out ghcr.io/conductorone/baton:latest -f "/out/sync.c1z" resources
```

### source

```bash
go install github.com/conductorone/baton/cmd/baton@main
go install github.com/conductorone/baton-oracle-fccs/cmd/baton-oracle-fccs@main

BATON_BASE_URL=https://example.epm.us2.oraclecloud.com \
BATON_ORACLE_CLIENT_ID=your_client_id \
BATON_ORACLE_CLIENT_SECRET=your_client_secret \
BATON_TOKEN_URL=https://idcs-xxx.identity.oraclecloud.com/oauth2/v1/token \
BATON_JWT_PRIVATE_KEY="$(cat /path/to/private_key.pem)" \
BATON_JWT_SUBJECT=fccs_service_account \
BATON_JWT_KEY_ID=my-key-id \
baton-oracle-fccs

baton resources
```

## Data Model

`baton-oracle-fccs` syncs the following Oracle FCCS resources:

| Resource | Description |
|----------|-------------|
| **Users** | All users with access to the FCCS application |
| **Groups** | EPM and IDCS groups (excludes PREDEFINED type which are IDCS roles) |
| **Roles** | Predefined and application roles |

## Provisioning Actions

`baton-oracle-fccs` supports the following provisioning actions:

| Action | Description |
|--------|-------------|
| **Group Membership** | Grant and revoke user/group membership in groups |
| **Role Assignment** | Grant and revoke role assignments to users and groups |

### Grant Expansion

The connector implements `GrantExpandable` annotations to support inherited access:

- **Nested Groups**: Users in child groups inherit membership in parent groups
- **Group-to-Role**: Users in groups inherit role assignments granted to those groups

**Note:** User lifecycle operations (create/update/delete) are not supported. User management should be handled via your IDCS connector.

## Contributing, Support and Issues

We started Baton because we were tired of taking screenshots and manually building spreadsheets. We welcome contributions and ideas, no matter how small -- our goal is to make identity and permissions sprawl less painful for everyone. If you have questions, problems, or ideas: Please open a GitHub Issue!

See [CONTRIBUTING.md](CONTRIBUTING.md) for more details.

## Command Line Reference

```
baton-oracle-fccs

Usage:
  baton-oracle-fccs [flags]
  baton-oracle-fccs [command]

Available Commands:
  capabilities       Get connector capabilities
  completion         Generate the autocompletion script for the specified shell
  help               Help about any command

Required Flags:
      --base-url string              The base URL of your Oracle FCCS instance ($BATON_BASE_URL)
      --oracle-client-id string      Oracle IDCS OAuth client ID ($BATON_ORACLE_CLIENT_ID)
      --oracle-client-secret string  Oracle IDCS OAuth client secret ($BATON_ORACLE_CLIENT_SECRET)
      --token-url string             The OAuth2 Token URL ($BATON_TOKEN_URL)
      --jwt-private-key string       Private key (PEM or base64 PEM) for JWT assertion ($BATON_JWT_PRIVATE_KEY)
      --jwt-subject string           Username to impersonate in JWT assertion ($BATON_JWT_SUBJECT)

Optional Flags:
      --jwt-key-id string            Key ID (kid) header for the JWT assertion ($BATON_JWT_KEY_ID)
      --jwt-issuer string            JWT issuer claim, defaults to oracle-client-id ($BATON_JWT_ISSUER)
      --jwt-audience string          JWT audience claim, defaults to token-url ($BATON_JWT_AUDIENCE)
      --scope string                 OAuth2 scope for the token request ($BATON_SCOPE)

General Flags:
      --client-id string             ConductorOne client ID ($BATON_CLIENT_ID)
      --client-secret string         ConductorOne client secret ($BATON_CLIENT_SECRET)
  -f, --file string                  Path to the c1z sync file (default "sync.c1z") ($BATON_FILE)
      --log-format string            Log output format: json, console (default "json") ($BATON_LOG_FORMAT)
      --log-level string             Log level: debug, info, warn, error (default "info") ($BATON_LOG_LEVEL)
  -p, --provisioning                 Enable provisioning actions ($BATON_PROVISIONING)
      --skip-full-sync               Skip full sync ($BATON_SKIP_FULL_SYNC)
      --ticketing                    Enable ticketing support ($BATON_TICKETING)
  -h, --help                         Help for baton-oracle-fccs
  -v, --version                      Version for baton-oracle-fccs

Use "baton-oracle-fccs [command] --help" for more information about a command.
```
