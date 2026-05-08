# AGENTS.md

## Project
This repository contains an AttackMap analyzer.

AttackMap analyzers live under:
- `github.com/mlaify`

This repo should implement one analyzer cleanly against the AttackMap core contract.

## Analyzer responsibilities
This analyzer should:
- detect whether it applies to a target repository
- emit structured signals
- remain heuristic but explainable

## Scope
Comprehensive Python ecosystem coverage, **additive over the built-in `python-web` analyzer**:

- **Web frameworks**: Django (`path/re_path/url`, gated by `urlpatterns =`), DRF routers (`router.register`, `@api_view`), Starlette (`Route` + `WebSocketRoute`), AIOHTTP (`add_get/post/...` and `web.get/post/...`), Sanic (`@app.get/post`), Litestar / Starlite (top-level `@get/@post` decorators), Flask `add_url_rule`
- **Databases**: SQLAlchemy with dialect-aware kind inference, asyncpg / psycopg2-3 / pymysql / motor / pymongo / redis-py / aioredis / sqlmodel / tortoise; boto3 dynamodb / s3; Django `DATABASES` dict in settings.py
- **Auth**: passlib (CryptContext + argon2/bcrypt/scrypt sub-hashes), bcrypt standalone, argon2-cffi, PyJWT / python-jose, authlib (OAuth/OAuth2Session), fastapi-users (BearerTransport / JWTStrategy), flask-jwt-extended (`@jwt_required`, `create_access_token`), django.contrib.auth (`authenticate`, `make_password`), casbin
- **HTTP clients**: httpx (sync + async), aiohttp.ClientSession, urllib.request.urlopen
- **Secrets**: `os.environ.get("X")` / `os.environ["X"]` (built-in only covers `os.getenv`); pydantic-settings BaseSettings field names with secret-shaped substrings; `dotenv_values(...).get(...)`
- **Service hints**: `[project] name` from pyproject.toml (PEP 621), `[tool.poetry] name`, setup.py `name=`, setup.cfg `[metadata] name`, `manage.py` → `framework:django`, Django `INSTALLED_APPS` (filtering out `django.*` built-ins)

## Out of scope (for now)
- **Tornado** class-based `RequestHandler` routing — requires per-class method extraction (`def get(self):`/`def post(self):` inside a class body).
- **FastAPI APIRouter prefix joining** beyond what the core scanner already handles.
- **Type-annotation–based DI** for FastAPI auth (`Depends(get_current_user)`) — already partially in core via AUTH_PATTERNS.
- **Celery** task definitions as background-worker entrypoints — only framework presence is captured.
- **GraphQL routing** (Strawberry, Graphene, Ariadne) — too narrow.
- **WebSocket consumer routing** in Django Channels — `routing.py` patterns differ from urls.py.

## Coexistence with built-in
The built-in `python-web` analyzer (`priority=20`) ships in AttackMap core and runs on every Python repo — it covers FastAPI + Flask routes, basic auth keyword sweeps, and `os.getenv` secrets via the core scanner. This plugin runs at `priority=15` (slightly higher) so its richer output lands first; AttackMap's overlay deduplication merges the two analyzers' results into a single unified set.

## Confidence policy
- Hash-class auth (passlib argon2/bcrypt/scrypt, argon2-cffi, bcrypt standalone) → 0.9
- Canonical auth library imports (passlib, PyJWT, python-jose, authlib, fastapi-users, flask-jwt-extended, django.contrib.auth, casbin) → 0.85
- Keyword-only matches (`Authorization`, `Bearer`, `api_key`) → 0.6
- Secret extractions (env var, pydantic-settings BaseSettings field) → 0.85

## Testing
Each new framework or extractor needs:
- A positive test (signal fires on representative code).
- A negative test (e.g., `web.get("/x", ...)` without an aiohttp import does NOT fire; `path("/x", ...)` outside a urls.py file does NOT fire; `os.environ.get("HOME")` is NOT a secret).
- The framework-gating logic is the analyzer's primary defense against false positives — every gated extractor needs a "skip when no framework import" test.
