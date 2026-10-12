# attackmap-analyzer-python

> [!IMPORTANT]
> **Active development, slow pace.** AttackMap is under active development, but
> progress may be slow until more contributors or co-maintainers join. Help is
> very welcome with the core engine, an analyzer, the macOS app, or the docs —
> see [CONTRIBUTING.md](CONTRIBUTING.md) or open an issue on
> [mlaify/AttackMap](https://github.com/mlaify/AttackMap/issues) to say hello.
> Security reports are still welcome at [security@mlaify.io](mailto:security@mlaify.io).

Comprehensive Python ecosystem analyzer for [AttackMap](https://github.com/mlaify/AttackMap).

This plugin is **additive** over AttackMap's built-in `python-web` analyzer. The built-in handles FastAPI / Flask routes via the core scanner; this plugin adds everything else.

- **Web frameworks** —
  - **Django** routing (`path("users/", ...)`, `path("", ...)` → `/`, `re_path(r"^api/...$", ...)`, legacy `url(...)` / `patterns(...)`) gated by `urlpatterns =` in the file, with the **`include()` graph** resolved repo-wide: `include("app.urls")`, `include(module)`, `include((patterns, "app"))`, `include([...])` and local pattern lists join their prefix onto every child route (`path("api/", include("shop.api_urls"))` + `orders/<int:pk>/` → `/api/orders/<int:pk>/`)
  - **Django REST Framework** routers (`router.register(r'users', UserViewSet)`, any `*Router()`), mounted under their `include(router.urls)` / `urlpatterns = router.urls` prefix, and `@api_view(['GET', 'POST'])` decorators
  - **Starlette** `Route("/x", endpoint=h, methods=["GET", "POST"])` and `WebSocketRoute("/ws/...")`
  - **AIOHTTP** `app.router.add_get/post/...`, `add_route("POST", ...)`, `add_view`, `web.get/post/view(...)` helpers and `web.RouteTableDef()` decorators (`@routes.get("/x")`, `@routes.view`, `@routes.route("PATCH", ...)`) (gated by aiohttp import)
  - **Sanic** `@app.get("/x")`, `@app.post("/x")`, `@app.route("/x", methods=[...])`, `@app.websocket("/ws")` (gated by sanic import)
  - **Litestar** (and legacy Starlite) handlers at any indentation (`@get()`, `@post(path="/x")`, `@route(http_method=[...])`, `@websocket`), `Controller` classes (`path = "/users"` joined onto each handler) and `Router(path=..., route_handlers=[...])` prefixes, including nested routers across files (decorators must be imported from litestar/starlite). `guards=[...]` on the handler/controller/router sets the route's auth to `required`; `exclude_from_auth=True` sets it to `anonymous`
  - **Tornado** `Application([(r"/x", Handler), url(r"/y", H)])` URL specs paired with the handler class's `get`/`post`/... methods (a `WebSocketHandler` is `WS`); `@tornado.web.authenticated` on a method sets its auth to `required`
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
- **Django `include()` resolution**: a module reference resolves only to a URLconf inside the repo (tried from each `manage.py` directory, the repo root, then the including file's ancestors). A resolved `include()` line is a prefix, not an endpoint, so it isn't a route. An include that can't be resolved (a third-party app, `include(get_model_urls(...))`) is still emitted as its prefix (`/accounts/`). A pattern list or router nothing mounts keeps the unprefixed emission. A non-literal route (`path(settings.BASE_PATH, include(...))`) joins as an empty prefix. Regex anchors are stripped when joining, so `re_path(r"^users/$")` is `/users/`. A pattern list is the union of everything assigned to it (reassignments, if/else and try/except branches, `urlpatterns = wrap(urlpatterns)`), so no branch's routes are dropped. The resolver is bounded (5k entries per list, 20k per file, 5k registrations per router, 12 include levels, 64 mounts per list, 200k steps including router registrations, 50k routes) and cycles stop.
- **Parsing**: URLconfs, Litestar, Tornado and Sanic files are read with `ast` (never executed). A file `ast` can't parse (Python 2, over 1 MB) falls back to the per-file regex extractors.
- **Not yet**: DRF nested routers' parent prefix, zulip-style custom `rest_path(...)` wrappers, Sanic `Blueprint(url_prefix=...)` joins (core doesn't join them either, so joining here would duplicate routes), and Django route auth decided at the view (`@login_required` on the view function, `LoginRequiredMixin`, DRF `permission_classes`) — see the issue tracker. Auth wrappers applied in the URLconf itself (`login_required(views.x)`, `permission_required("p")(View.as_view())`, `staff_member_required`, `user_passes_test`) do set the route's auth to `required`, and Django 5.1's `login_not_required(...)` sets it to `anonymous`.
- **pydantic-settings** field extraction matches any class field whose name contains `secret`, `token`, `key`, `password`, `pass`, or `pwd`. False positives are possible (e.g., a non-secret `signing_key` config). Confidence is the standard 0.85.

## Coexistence with the built-in `python-web` analyzer

AttackMap ships with a `python-web` built-in that handles FastAPI / Flask via the core scanner. When this plugin is installed, both analyzers run on every Python repo. AttackMap's overlay deduplication merges their output so users see a single unified set of findings — no double-counting.

This plugin runs at `priority=10`. AttackMap runs analyzers in `(priority, name)` order across built-ins and plugins and merges first-seen-wins, so this plugin runs before the built-in (`priority=20`) and its richer output wins where they overlap.

## License

MIT
