# Auth Service

A stateless Spring Boot 3.x REST API secured with Spring Security 6 and Keycloak as the Identity Provider (IDP). Tokens are issued by Keycloak (OAuth2 / OIDC) and validated by the service on every request using JWT signature verification via the Keycloak JWKS endpoint.

---

## Architecture

```
┌─────────────┐   1. POST /token   ┌──────────────────┐
│   Client    │ ─────────────────► │  Keycloak :8180  │
│             │ ◄───────────────── │  (IDP / AS)      │
│             │   access_token     └──────────────────┘
│             │
│             │   2. GET /api/**                ┌──────────────────────┐
│             │   Authorization: Bearer <token> │  Auth Service :8080  │
│             │ ──────────────────────────────► │  (Resource Server)   │
│             │ ◄────────────────────────────── │                      │
└─────────────┘   JSON response                └──────────────────────┘
                                                        │
                                          Validates JWT signature via
                                          Keycloak JWKS endpoint on
                                          first request, then caches keys
```

**Token flow**
1. Client authenticates against Keycloak and receives a signed JWT access token.
2. Client sends every API request with `Authorization: Bearer <token>`.
3. Spring Security's `BearerTokenAuthenticationFilter` intercepts the request.
4. `KeycloakJwtAuthenticationConverter` validates the signature, extracts `realm_access.roles` and `resource_access.<client-id>.roles`, and maps them to `ROLE_*` authorities.
5. The `SecurityFilterChain` either permits or rejects the request based on the required role.

---

## Technology Stack

| Layer | Technology |
|---|---|
| Runtime | Java 21 (Amazon Corretto) |
| Framework | Spring Boot 3.2.3 |
| Security | Spring Security 6 + OAuth2 Resource Server |
| Token format | JWT (RS256, signed by Keycloak) |
| IDP | Keycloak 24.0.1 |
| Build | Maven 3.8 |
| Containerisation | Docker Compose (Keycloak only) |

---

## Project Structure

```
auth-service/
├── docker-compose.yml                          # Keycloak dev server
├── pom.xml
├── auth-service.postman_collection.json        # Postman collection (18 requests)
└── src/
    ├── main/
    │   ├── java/com/example/authservice/
    │   │   ├── AuthServiceApplication.java
    │   │   ├── config/
    │   │   │   ├── SecurityConfig.java                      # Filter chain, CORS, session policy
    │   │   │   └── KeycloakJwtAuthenticationConverter.java  # Extracts Keycloak roles → ROLE_*
    │   │   ├── controller/
    │   │   │   ├── PublicController.java    # /api/public/**       — unauthenticated
    │   │   │   ├── AuthController.java      # /api/auth/**         — any valid token
    │   │   │   ├── TokenController.java     # /api/auth/refresh    — unauthenticated
    │   │   │   ├── UserController.java      # /api/user/**         — any valid token
    │   │   │   └── AdminController.java     # /api/admin/**        — ROLE_ADMIN only
    │   │   ├── exception/
    │   │   │   └── GlobalExceptionHandler.java  # 401 / 403 / Keycloak errors → structured JSON
    │   │   ├── model/
    │   │   │   ├── UserInfo.java            # Record DTO returned by /api/auth/me
    │   │   │   ├── RefreshTokenRequest.java # Request body for /api/auth/refresh
    │   │   │   └── TokenResponse.java       # Response body for /api/auth/refresh
    │   │   └── service/
    │   │       └── KeycloakTokenService.java  # Calls Keycloak /token endpoint via RestClient
    │   └── resources/
    │       └── application.yml
    └── test/
        └── java/com/example/authservice/controller/
            ├── PublicControllerTest.java
            ├── AuthControllerTest.java
            ├── AdminControllerTest.java
            └── TokenControllerTest.java
```

---

## Configuration (`application.yml`)

```yaml
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: http://localhost:8180/realms/demo-realm   # OIDC discovery
          jwk-set-uri: http://localhost:8180/realms/demo-realm/protocol/openid-connect/certs

app:
  keycloak:
    realm: demo-realm
    auth-server-url: http://localhost:8180
    client-id: spring-boot-app   # used to extract resource_access roles
```

Change `issuer-uri`, `jwk-set-uri`, and `client-id` to match your Keycloak setup.

---

## Security Rules

| Path | Rule |
|---|---|
| `GET /api/public/**` | Permit all (no token required) |
| `GET /actuator/health` | Permit all |
| `GET /actuator/info` | Permit all |
| `POST /api/auth/refresh` | Permit all — access token is expired when refresh is needed |
| `GET /api/admin/**` | `hasRole("ADMIN")` — filter chain + `@PreAuthorize` |
| Everything else | Authenticated (any valid JWT) |

Sessions are stateless (`SessionCreationPolicy.STATELESS`). No cookies.

---

## Role Mapping

Keycloak embeds roles in the JWT under two paths. The `KeycloakJwtAuthenticationConverter` reads both and maps them to Spring `GrantedAuthority` objects:

```
jwt.realm_access.roles[*]                    → ROLE_<UPPERCASE>
jwt.resource_access.<client-id>.roles[*]     → ROLE_<UPPERCASE>
```

Example: a Keycloak realm role `admin` becomes `ROLE_ADMIN` in Spring Security, so `hasRole("ADMIN")` and `@PreAuthorize("hasRole('ADMIN')")` both work without any prefix.

---

## API Endpoints

### Public — no token required

| Method | Path | Description |
|---|---|---|
| GET | `/api/public/health` | Service liveness check |
| GET | `/api/public/info` | Service metadata |

### Token — no token required

| Method | Path | Description |
|---|---|---|
| POST | `/api/auth/refresh` | Exchange a Keycloak refresh token for a new access + refresh token pair |

Request body:
```json
{ "refreshToken": "<keycloak-refresh-token>" }
```

Response:
```json
{
  "access_token": "...",
  "refresh_token": "...",
  "token_type": "Bearer",
  "expires_in": 300,
  "refresh_expires_in": 1800
}
```

| Status | Cause |
|---|---|
| 200 | Valid refresh token — new token pair returned |
| 400 | `refreshToken` field is missing or blank |
| 401 | Keycloak rejected the token (expired, revoked, or invalid) |

### Auth — any valid token

| Method | Path | Description |
|---|---|---|
| GET | `/api/auth/me` | Current user as `UserInfo` (sub, username, email, roles) |
| GET | `/api/auth/token-info` | Raw JWT claims map |
| GET | `/api/auth/principal` | Resolved principal name (`preferred_username`) |

### User — any valid token

| Method | Path | Description |
|---|---|---|
| GET | `/api/user/profile` | Username, email, authority list |
| GET | `/api/user/greet` | Greeting using `preferred_username` |
| GET | `/api/user/restricted` | Requires `ROLE_USER` (`@PreAuthorize`) |

### Admin — `ROLE_ADMIN` required

| Method | Path | Description |
|---|---|---|
| GET | `/api/admin/dashboard` | Admin summary with timestamp |
| GET | `/api/admin/users` | Stub user list |
| GET | `/api/admin/token-audit` | Raw JWT claims for audit |

---

## Error Responses

All 401 / 403 responses return structured JSON via `GlobalExceptionHandler`:

```json
{
  "timestamp": "2026-02-23T17:00:00Z",
  "status": 401,
  "error": "Unauthorized",
  "message": "Authentication failed: ..."
}
```

---

## Local Setup

### 1. Start Keycloak

```bash
docker compose up -d
```

Keycloak admin console: http://localhost:8180 — credentials: `admin / admin`

### 2. Configure Keycloak

1. Create realm: **`demo-realm`**
2. Create client: **`spring-boot-app`**
   - Client authentication: OFF
   - Standard flow: ON
3. Create realm roles: **`user`**, **`admin`**
4. Create a test user, assign roles, set a password

### 3. Obtain a token

```bash
curl -s -X POST \
  http://localhost:8180/realms/demo-realm/protocol/openid-connect/token \
  -d grant_type=password \
  -d client_id=spring-boot-app \
  -d username=alice \
  -d password=secret \
  | jq -r .access_token
```

### 4. Run the service

```bash
mvn spring-boot:run
```

### 5. Call a protected endpoint

```bash
TOKEN=<paste token>
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/auth/me
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/admin/dashboard
```

### 6. Refresh an expired access token

```bash
REFRESH_TOKEN=<paste refresh_token from step 3>
curl -s -X POST http://localhost:8080/api/auth/refresh \
  -H "Content-Type: application/json" \
  -d "{\"refreshToken\": \"$REFRESH_TOKEN\"}" | jq .
```

---

## Running Tests

```bash
mvn test
```

12 unit tests using `@WebMvcTest` + Spring Security Test's `jwt()` mock — no running Keycloak required.

| Test class | Coverage |
|---|---|
| `PublicControllerTest` | Public endpoints return 200 without a token |
| `AuthControllerTest` | 401 without token; 200 with valid JWT mock |
| `AdminControllerTest` | 401 no token; 403 wrong role; 200 with ROLE_ADMIN |
| `TokenControllerTest` | 200 valid refresh; 400 missing/blank token; 401 Keycloak rejection |

---

## Postman Collection

Import `auth-service.postman_collection.json` into Postman.

1. Run **Keycloak → Get Token (Password Grant)** — saves both `accessToken` and `refreshToken` automatically.
2. All other requests inherit Bearer auth from the collection.
3. When the access token expires, run **Auth → Refresh Token** — both variables are rotated automatically.
4. Negative-case requests (401, 403) override auth individually.

Collection variables to configure: `baseUrl`, `keycloakUrl`, `realm`, `clientId`, `username`, `password`.
