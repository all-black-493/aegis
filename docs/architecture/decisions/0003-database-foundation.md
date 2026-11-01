# ADR-0003: Database foundation: roles, schema and migrations

- **Status:** Accepted
- **Date:** 2026-11-01

## Context

Phase 1 stores identities, tasks, decisions, jobs and audit events in PostgreSQL. Before any of those tables exist, the project needs:

- database access libraries;
- a migration mechanism;
- a privilege model in which the API and worker cannot change the schema, the roles or, later, the audit trail.

Phase 0 had only the superuser created by the PostgreSQL image.

## Decisions

| Area | Decision | Rationale |
|---|---|---|
| Libraries | SQLAlchemy 2.1.6, used synchronously; Alembic 1.20.1; psycopg 3.3.6 (binary wheel), moved from a development-only to a runtime dependency | A typed ORM and Core, transactional migrations on PostgreSQL, and a driver that supports both sync and async |
| Roles | The **bootstrap superuser** (`AEGIS_POSTGRES_USER`) is used only by `aegis db bootstrap`. **`aegis_owner`** is not a superuser and cannot create roles or databases; it owns the schema and runs migrations (and administration from Increment 5). **`aegis_app`** owns nothing and holds only the privileges each migration grants. Bootstrap re-applies every role attribute on each run. | Least privilege: application processes cannot change the schema or roles, and drift in role attributes is corrected |
| Passwords | Each checkout generates its own role passwords. They reach PostgreSQL only as SCRAM-SHA-256 verifiers computed on the client by libpq (`PQencryptPasswordConn`, through psycopg), so the plaintext never reaches the server or its logs. Settings hold them in a `Secret` type that is redacted in `repr`, `str` and logs. | No shared passwords; no plaintext in server logs, even when a statement fails |
| Per-process credentials | `load_database_settings(environ, role)` reads only the requested role's credentials. `aegis db migrate` needs only the owner's; the future API and worker need only the application role's. | A process cannot leak credentials it never loaded |
| Schema | All objects live in the `aegis` schema, owned by `aegis_owner`. `PUBLIC` loses `CONNECT` and `TEMPORARY` on the database and all access to the `public` and `aegis` schemas. Each role's `search_path` is pinned to `aegis` in this database, and models name the schema explicitly. | No object creation in `public` and no search-path confusion |
| Migrations | Hand-written Alembic scripts ship in the package (`aegis.db:migrations`), with sequential revision IDs (`0001`, …) and a linear history that includes downgrades. They run only through `aegis db migrate` (via `make migrate`), never when a process starts. All pending migrations run as `aegis_owner` in one transaction, behind a PostgreSQL advisory lock. Every grant to `aegis_app` is explicit, per object, in the migration that creates the object. | Reviewable schema changes; no concurrent migrations; nothing changes the schema implicitly |
| Readiness | `schema_status()` compares the database's revision (in `aegis.alembic_version`, readable by `aegis_app`) with the latest revision in the package. The doctor reads the revision through `psql` inside the PostgreSQL container. | The future readiness endpoint and the doctor can both refuse to report ready while migrations are pending |
| Test database | Integration tests recreate `<AEGIS_POSTGRES_DB>_test` once per session as the superuser, then bootstrap and migrate it. The reset refuses, before connecting, any name not ending in `_test` and the configured database itself. | Tests never touch development data, and the reset cannot target the wrong database |

## Consequences and limitations

- Whoever holds the bootstrap superuser credentials controls the whole PostgreSQL cluster. They are used only for bootstrap and test-database setup.
- `aegis_owner` owns every AEGIS object and can change or drop any of them. Whoever holds the owner credentials is a trusted operator (Phase 1 trust boundary B3).
- Roles are cluster-wide with fixed names. Each PostgreSQL cluster hosts one AEGIS deployment.
- Downgrades exist and are tested. In production the policy should be forward-only, with recovery from backups, which are out of scope for Phase 1.
- The binary psycopg wheel bundles its own libpq. Production builds should revisit this in Phase 11.
- The doctor's migration check imports Alembic to find the latest revision. Its other checks still use only the standard library.
- The development image accepts password logins from any address on the container network. The host port is published on `127.0.0.1` only.
