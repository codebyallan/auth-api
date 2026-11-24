# auth-api

A minimal authentication microservice.

## About

`auth-api` is a small microservice responsible for handling authentication for the auth flow:

- **Register** — creates a new user
- **Login** — authenticates an existing user and issues tokens
- **Refresh** — rotates an existing refresh token
- **Logout** — revokes a refresh token family

It issues **RS256 JWT access tokens** (15 minutes TTL) and **refresh tokens** (30 days TTL, stored as SHA-256 hashes with rotation and reuse detection). Public keys are exposed via the **JWKS** endpoint (`GET /.well-known/jwks.json`) for token verification by other services.

Data is persisted in **PostgreSQL** using **pgx**.

## Tech Stack

- [Go](https://go.dev/) (net/http with `ServeMux` method-based routing)
- [PostgreSQL](https://www.postgresql.org/) + [pgx](https://github.com/jackc/pgx)
- [golang-jwt](https://github.com/golang-jwt/jwt) (RS256)
- [godotenv](https://github.com/joho/godotenv)
- [bcrypt](https://github.com/golang.org/x/crypto/bcrypt)

## Requirements

- [Go](https://go.dev/dl/) 1.27+
- A running [PostgreSQL](https://www.postgresql.org/) database
- An RSA private key in PEM format (used to sign the access tokens)

## Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/codebyallan/auth-api.git
cd auth-api
```

### 2. Install dependencies

```bash
go mod download
```

### 3. Configure the environment

Copy the example environment file and adjust the values:

```bash
cp .env.example .env
```

See [Environment Variables](#environment-variables) for details.

The service automatically loads the `.env` file located in the project root (via [godotenv](https://github.com/joho/godotenv)) if present. If no `.env` file is found, it falls back to the real environment variables.

### 4. Run the database migrations

The migrations are plain SQL files located in the `migrations/` directory and must be run **manually**.

```bash
psql "$DATABASE_URL" -f migrations/001_create_users_table.sql
psql "$DATABASE_URL" -f migrations/002_create_refresh_tokens_table.sql
psql "$DATABASE_URL" -f migrations/003_add_refresh_tokens_cleanup_indexes.sql
```

### 5. Generate the RSA private key

The service requires an RSA private key to sign the JWT access tokens:

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out private.pem
```

### 6. Run the service

```bash
go run ./cmd/api
```

The API will be available at the address set by `HTTP_ADDR` (default `http://localhost:8080`).

## Environment Variables

| Variable               | Description                                                          |
| ---------------------- | -------------------------------------------------------------------- |
| `DATABASE_URL`               | PostgreSQL connection string used by the service                     |
| `JWT_PRIVATE_KEY_PATH`       | Path to the RSA private key (PEM) used to sign the access tokens     |
| `HTTP_ADDR`                  | HTTP server listen address (default `:8080`)                         |
| `CLEANUP_INTERVAL`           | Interval between cleanup runs (Go duration, default `24h`)           |
| `EXPIRED_TOKEN_RETENTION`    | How long to keep expired refresh tokens (Go duration, default `168h`) |
| `REVOKED_TOKEN_RETENTION`    | How long to keep revoked refresh tokens (Go duration, default `720h`) |
| `CLEANUP_BATCH_SIZE`         | Rows deleted per batch during cleanup (default `1000`)               |
| `CLEANUP_MAX_BATCHES`        | Maximum batches per cleanup cycle (default `100`)                    |
| `CLEANUP_TIMEOUT`            | Timeout for a single cleanup cycle (Go duration, default `5m`)       |

Example (`.env.example`):

```env
DATABASE_URL=postgres://user:password@localhost:5432/auth_api?sslmode=disable
JWT_PRIVATE_KEY_PATH=./private.pem
HTTP_ADDR=:8080
CLEANUP_INTERVAL=24h
EXPIRED_TOKEN_RETENTION=168h
REVOKED_TOKEN_RETENTION=720h
CLEANUP_BATCH_SIZE=1000
CLEANUP_MAX_BATCHES=100
CLEANUP_TIMEOUT=5m
```

The JWT issuer, audience, key ID and token TTLs are fixed in `internal/config` and are not configurable via environment variables.

## Token cleanup

The service runs a background cleanup routine that removes old refresh tokens:

- Runs once at startup and then every `CLEANUP_INTERVAL`.
- Removes tokens expired for longer than `EXPIRED_TOKEN_RETENTION`.
- Removes tokens revoked for longer than `REVOKED_TOKEN_RETENTION` (kept longer than the refresh token TTL to preserve reuse detection).
- Deletions are performed in batches (`CLEANUP_BATCH_SIZE`, up to `CLEANUP_MAX_BATCHES` per cycle) with a per-cycle timeout (`CLEANUP_TIMEOUT`).

Durations use Go's format (`24h`, `168h`, `5m`); the shorthand `d` (days) is not supported.

Invalid values fall back to the default and are logged at startup.

## Endpoints

Base URL: `http://localhost:8080`

### `POST /auth/register`

Creates a new user and returns a token pair.

**Request body:**

```json
{
  "email": "user@example.com",
  "password": "password123"
}
```

**Responses:**

- `201 Created` — user created successfully

```json
{
  "access_token": "<jwt>",
  "refresh_token": "<opaque-token>",
  "token_type": "Bearer",
  "expires_at": 1735689600
}
```

- `400 Bad Request` — invalid request body, invalid email, or invalid password
- `409 Conflict` — email is already in use
- `500 Internal Server Error` — internal server error

### `POST /auth/login`

Authenticates a user and returns a token pair.

**Request body:**

```json
{
  "email": "user@example.com",
  "password": "password123"
}
```

**Responses:**

- `200 OK` — authentication successful

```json
{
  "access_token": "<jwt>",
  "refresh_token": "<opaque-token>",
  "token_type": "Bearer",
  "expires_at": 1735689600
}
```

- `400 Bad Request` — invalid request body
- `401 Unauthorized` — invalid email or password

### `POST /auth/refresh`

Rotates a refresh token and returns a new token pair.

**Request body:**

```json
{
  "refresh_token": "<opaque-token>"
}
```

**Responses:**

- `200 OK` — token pair issued

```json
{
  "access_token": "<jwt>",
  "refresh_token": "<opaque-token>",
  "token_type": "Bearer",
  "expires_at": 1735689600
}
```

- `400 Bad Request` — invalid request body
- `401 Unauthorized` — invalid refresh token

### `POST /auth/logout`

Revokes a refresh token family.

**Request body:**

```json
{
  "refresh_token": "<opaque-token>"
}
```

**Responses:**

- `204 No Content` — refresh token revoked successfully

- `400 Bad Request` — invalid request body
- `500 Internal Server Error` — internal server error

### `GET /.well-known/jwks.json`

Returns the public key used to verify the access tokens.

**Responses:**

- `200 OK` — JSON Web Key Set

```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "auth-key-1",
      "alg": "RS256",
      "use": "sig",
      "n": "<base64url-encoded-n>",
      "e": "<base64url-encoded-e>"
    }
  ]
}
```

## Errors

All errors are returned as JSON in the following format:

```json
{
  "error": "error message"
}
```

| Status | Error                          | Description                                                    |
| ------ | ------------------------------ | -------------------------------------------------------------- |
| 400    | `invalid request body`        | Malformed JSON body                                            |
| 400    | `email invalid`                | Email format is invalid                                       |
| 400    | `password must have at least 8 characters` | Password is shorter than 8 characters        |
| 400    | `password must have at most 72 bytes`         | Password is longer than 72 bytes       |
| 401    | `invalid email or password`   | Login credentials are invalid                                 |
| 401    | `invalid refresh token`       | Refresh token is invalid, expired or already revoked          |
| 409    | `email is already in use`     | Email is already registered                                   |
| 500    | `internal server error`       | Unexpected internal error                                     |

## License

This project is licensed under the [MIT License](LICENSE).
