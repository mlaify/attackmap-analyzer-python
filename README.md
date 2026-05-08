# attackmap-analyzer-python

Comprehensive Python ecosystem analyzer for [AttackMap](https://github.com/mlaify/AttackMap).

This plugin is **additive** over AttackMap's built-in `python-web` analyzer. The built-in handles FastAPI / Flask routes via the core scanner; this plugin adds everything else.

- **Web frameworks** —
  - **Django** routing (`path("users/", ...)`, `re_path(r"^api/...$", ...)`, legacy `url(...)`) gated by `urlpatterns =` in the file
  - **Django REST Framework** routers (`router.register(r'users', UserViewSet)`) and `@api_view(['GET', 'POST'])` decorators
  - **Starlette** `Route("/x", endpoint=h, methods=["GET", "POST"])` and `WebSocketRoute("/ws/...")`
  - **AIOHTTP** `app.router.add_get/post/...` and `web.get/post/...` helpers (gated by aiohttp import)
  - **Sanic** `@app.get("/x")`, `@app.post("/x")` (gated by sanic import)
  - **Litestar** (and legacy Starlite) top-level `@get("/x")` / `@post(...)` decorators (gated by litestar/starlite import)
  - **Flask** `app.add_url_rule("/x", view_func=...)` (additive — built-in covers `@app.route`)
- **Databases** —
  - **SQLAlchemy** `create_engine("postgresql://...")` with dialect-aware kind inference (postgresql / mysql / mariadb / sqlite / oracle / sqlserver)
  - **asyncpg** / **psycopg2-3** / **pymysql** / **motor.motor_asyncio** / **pymongo** / **redis.asyncio** / **aioredis** / **sqlmodel** / **tortoise**
  - **boto3 resources/clients** for `dynamodb` and `s3`
  - **Django** `DATABASES` dict in `settings.py` — `ENGINE` value parsed for the kind
- **Auth packages** —
  - **passlib** `CryptContext`, `passlib.hash.argon2/bcrypt/scrypt`
  - **bcrypt** standalone (`bcrypt.hashpw`, `bcrypt.checkpw`)
  - **argon2-cffi** (`from argon2 import PasswordHasher`)
  - **PyJWT** / **python-jose** (`jwt.encode`, `jwt.decode`, `jose.jwt`)
  - **authlib** (`OAuth(...)`, `OAuth2Session(...)`)
  - **fastapi-users** (`BearerTransport`, `JWTStrategy`)
  - **flask-jwt-extended** (`@jwt_required`, `create_access_token`)
  - **django.contrib.auth** (`authenticate`, `make_password`)
  - **casbin** (`Enforcer`)
- **HTTP clients (external calls)** — **httpx** sync + async, **aiohttp.ClientSession**, **urllib.request.urlopen**
- **Secrets** —
  - `os.environ.get("X")` and `os.environ["X"]` with secret-shaped names (built-in only covers `os.getenv`)
  - **pydantic-settings** `BaseSettings` field-name extraction (`jwt_secret: str = ...`)
  - `dotenv_values(...)` accessors with secret-shaped keys
- **Service hints** — `[project] name` from `pyproject.toml`, `[tool.poetry] name`, `name="..."` from `setup.py`, `[metadata] name` from `setup.cfg`, presence of `manage.py` → `framework:django`, Django `INSTALLED_APPS` third-party / local apps

All emissions populate AttackMap's Signal v2 fields (line numbers, evidence snippets, confidence) so downstream insights can cite `path/to/module.py:NN`.

## Install

```bash
pip install git+https://github.com/mlaify/attackmap-analyzer-python.git
```

The analyzer is auto-discovered by AttackMap via the `attackmap.analyzers` entry-point group.

## Usage with AttackMap

```bash
# Auto-discovered when installed:
attackmap analyze /path/to/python/repo

# Or invoke explicitly:
attackmap analyze /path/to/python/repo --module python
```

## Detection

`detect()` returns true when any of the following are present, ignoring `.venv/`, `venv/`, `env/`, `.tox/`, `__pycache__/`, `.pytest_cache/`, `dist/`, `build/`, `node_modules/`, `.git/`, `.mypy_cache/`, `.ruff_cache/`, and `site-packages/`:

- A `pyproject.toml`, `setup.py`, `setup.cfg`, `manage.py`, or `Pipfile` at the root
- Any `.py` file in the tree

## Coverage notes

- **Framework-gated extraction**: route extractors for AIOHTTP, Sanic, Litestar, and Starlette only fire when the file imports the corresponding framework. This prevents mis-attributing generic `@get(...)` / `web.get(...)` / `app.get(...)` calls to a framework when they're really custom decorators or method calls.
- **Django routing requires `urlpatterns =`** to be in the file. A bare `path("/x", ...)` in any other context (e.g., `pathlib.Path("/x")` is well-behaved, but a project that also has `from django.urls import path; path("/x", view)` outside a urls.py won't fire — by design).
- **Django settings extraction**: gated by presence of one of `INSTALLED_APPS`, `DATABASES`, `MIDDLEWARE`, or `ROOT_URLCONF`. Built-in Django apps (`django.*`) are filtered out of the INSTALLED_APPS service hints to keep signal high.
- **DRF `@api_view(['GET', 'POST'])`**: emits framework hints (`drf_api_view:GET`, `drf_api_view:POST`) rather than routes — the actual path is in `urls.py`, which is extracted separately.
- **Tornado** is not yet covered — its class-based `RequestHandler` routing requires per-class method extraction (`def get(self): ...`, `def post(self): ...`).
- **pydantic-settings** field extraction matches any class field whose name contains `secret`, `token`, `key`, `password`, `pass`, or `pwd`. False positives are possible (e.g., a non-secret `signing_key` config). Confidence is the standard 0.85.

## Coexistence with the built-in `python-web` analyzer

AttackMap ships with a `python-web` built-in that handles FastAPI / Flask via the core scanner. When this plugin is installed, both analyzers run on every Python repo. AttackMap's overlay deduplication merges their output so users see a single unified set of findings — no double-counting.

This plugin runs at `priority=15` (slightly higher than the built-in's 20), so its richer output lands first.

## License

MIT
