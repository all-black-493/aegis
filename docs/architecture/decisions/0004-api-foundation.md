# ADR-0004: API foundation

- **Status:** Accepted
- **Date:** 2026-11-01

## Context

The API is the first component that accepts input from the network (trust boundary B1 in the Phase 1 plan). Everything it receives is untrusted. It needs authentication, uniform errors and input limits before any route does real work, and it must not become a second way to administer identities.

## Decisions

| Area | Decision | Rationale |
|---|---|---|
| Framework | FastAPI 0.162 on Starlette 1.10, served by Uvicorn 0.54. Endpoints are synchronous and use the synchronous SQLAlchemy engine; FastAPI runs them in its thread pool. | One database stack for the API, worker and CLI. |
| Layout | `aegis.apps.api` holds the application factory (`app.py`), shared request dependencies (`deps.py`), request and response models (`schemas/`), the unversioned health routes (`health.py`) and the versioned routes (`v1/router.py`, with one module per area under `v1/endpoints/`). Domain logic stays in AEGIS's own packages, which the worker and CLI also use. Authentication is attached once, on the `/v1` router. Reorganized in Phase 4, with no change in behaviour | FastAPI's bigger-applications pattern, one responsibility per module, and no `/v1` route can forget its token. Since FastAPI 0.162 `include_router` keeps a lazy wrapper, so code that lists routes uses `iter_route_contexts`, not `router.routes`. |
| Binding | `make api` serves on `127.0.0.1` only, on `AEGIS_API_PORT` (default 8000). The host is not configurable in Phase 1. Proxy headers are not trusted and no `Server` header is sent. | There is no TLS and no deployment target yet, so nothing listens beyond loopback. |
| Process secrets | The API loads only the `aegis_app` password and the token pepper, then removes every secret variable from its environment (Increment 11), so neither code that reads the environment nor a child process sees them; `/proc/self/environ` still holds the initial copy. | It never holds owner or bootstrap credentials, even though `make api` passes it the whole `.env`. |
| Routes | Public: `GET /health/live` and `GET /health/ready`. Authenticated: `GET /v1/me` and the task routes (ADR-0011). Every `/v1` route is declared on one router whose dependency authenticates the caller. There are no administration routes. `/docs` and `/openapi.json` exist only when `AEGIS_ENV=development`. | Administration stays CLI-only, and the database grants already prevent it (ADR-0005). |
| Authentication | The token comes from exactly one `Authorization: Bearer` header. Its format is checked before any database access. Valid-looking tokens are verified against the database on every request, with nothing cached, so revocation applies to the next request. Every failure returns the same 401 problem with `WWW-Authenticate: Bearer`. The reason is logged with the request ID and never returned. | Callers cannot tell why a token was refused. |
| `auth.failed` | Audited only when the credential exists: wrong secret, revoked, expired or identity disabled. The event names the credential as its target, carries the reason code and request ID, has outcome `denied` and no actor. Missing, malformed and unknown tokens are only logged. The event is written in its own transaction; if that fails, the request is still refused and a `CRITICAL` log line is written (ADR-0010, N5). | Unauthenticated clients cannot fill the audit table, and failed attempts against real credentials are kept. |
| Errors | RFC 9457 problem details (`application/problem+json`) with `type` (`about:blank`), `title`, `status` and a stable `code`. No detail text or exception message is ever returned. A 422 lists only each error's `type` and `loc`: input values, messages and context are dropped, and unknown keys are not echoed. Unexpected errors return a generic 500 and log the traceback; database errors return 503. | Nothing a client sent, and nothing about the server's internals, is reflected back. |
| Request IDs | The server generates a random UUID (32 hex characters) for every request and returns it in `X-Request-ID`. It is attached to log lines and audit events. Client-supplied IDs are not accepted. | Correlation IDs that clients cannot forge or use to inject log content. |
| Request bodies | At most 64 KiB, checked against `Content-Length` before reading (413) and while streaming (413). A malformed or repeated `Content-Length` gets 400. Any request with a body must be `application/json`, optionally with `charset=utf-8`, or it gets 415. These checks run before routing and authentication. | Bounded memory per request, and no form or plain-text bodies, which browsers can send cross-site without a preflight. |
| Response headers | `Cache-Control: no-store` and `X-Content-Type-Options: nosniff` on every response. | Identity data must not be cached by intermediaries. |
| Logging | Uvicorn's logs go through the redacting JSON handler. Uvicorn's access log is off; instead the API writes one line per request with the request ID, method, path (without the query string), status and duration. Headers are never logged. | Tokens in headers or query strings never reach the logs. |
| Readiness | `/health/ready` returns 200 only when the database answers as `aegis_app` and its schema is at the package's latest revision. Otherwise it returns 503 `not_ready`, and the reason is logged, not returned. `/health/live` never touches the database. | A process that cannot serve requests correctly says so. |
| Test client | `httpx2` (development only), which Starlette 1.10's `TestClient` requires; it deprecates `httpx`. | Avoids building tests on a deprecated path. |

## Consequences and limitations

- There is no rate limiting (out of scope for Phase 1). Well-formed but unknown tokens still cost a database lookup.
- The 401 body and headers are identical for every reason, but response times are not: format errors never reach the database, and known credentials also write an audit record.
- On routes with a body parameter, FastAPI parses JSON before running dependencies, so a malformed body would get 422 before authentication. `POST /v1/tasks` avoids this by reading its body in a dependency that runs after authentication (ADR-0011); new routes with a body should do the same.
- No TLS. Exposing the API beyond loopback needs a TLS-terminating proxy and a deliberate change to the binding.
- In development, the `/docs` page loads Swagger UI assets from a CDN in the browser.
