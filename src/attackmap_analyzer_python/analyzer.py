"""Comprehensive Python ecosystem analyzer for AttackMap.

This plugin is **additive** over AttackMap's built-in `python-web` analyzer —
the built-in (which uses the core scanner) handles FastAPI / Flask routes,
basic auth keyword sweeps, and standard `os.getenv` / SECRET_PATTERNS. This
plugin adds:

- **Django** routing (path / re_path / include / DRF routers), settings.py
  DATABASES dict parsing, INSTALLED_APPS, manage.py detection
- **Starlette** Route(...) declarations
- **AIOHTTP** (`add_get` / `add_post` / `web.get` / `web.post`)
- **Sanic** decorator routes (`@app.get`, `@app.post`)
- **Litestar** (formerly Starlite) decorator routes
- **SQLAlchemy** (`create_engine("postgresql://...")` with dialect-aware kind)
- **asyncpg / pymysql / motor.motor_asyncio** databases
- **boto3** resource detection (DynamoDB, S3)
- **passlib** (`CryptContext`, `bcrypt`, `argon2`), **python-jose / PyJWT**,
  **authlib**, **fastapi-users**, **flask-jwt-extended**, **bcrypt** standalone,
  **argon2-cffi**, **casbin**
- **httpx** sync + async, **aiohttp** ClientSession, **urllib.request.urlopen**
- **pydantic-settings** BaseSettings field-name secret extraction
- **`os.environ.get(...)` / `os.environ["..."]`** secret patterns (built-in
  only covers `os.getenv`)
- **Service hints** from pyproject.toml `[project] name`, setup.py / setup.cfg

All emissions populate Signal v2 fields (line numbers, evidence snippets,
confidence) so downstream insights can cite `path/to/module.py:NN`.

When this plugin is installed, AttackMap's overlay deduplication merges its
output with the built-in `python-web` analyzer's output — so users see a
single unified set of findings even though both analyzers fire.
"""

from __future__ import annotations

import re
from pathlib import Path

from .contracts import (
    AnalyzerMetadata,
    AuthHint,
    DatabaseHint,
    EntrypointHint,
    ExternalCall,
    FrameworkHint,
    Route,
    ScanResult,
    SecretHint,
    ServiceHint,
)

CODE_SUFFIXES = {".py"}
SKIP_DIRS = {
    ".venv",
    "venv",
    "env",
    ".tox",
    "__pycache__",
    ".pytest_cache",
    "dist",
    "build",
    "node_modules",
    ".git",
    ".mypy_cache",
    ".ruff_cache",
    "site-packages",
}
_SNIPPET_MAX_CHARS = 160


# ---------- Patterns ----------

# Django: path("users/", views.users) / path("users/", views.users, name="users")
DJANGO_PATH_PATTERN = re.compile(
    r'\bpath\s*\(\s*[\'"]([^\'"]+)[\'"]\s*,',
)
# Django: re_path(r"^users/$", views.users)
DJANGO_RE_PATH_PATTERN = re.compile(
    r'\bre_path\s*\(\s*r?[\'"]([^\'"]+)[\'"]\s*,',
)
# Django: url(r"^users/$", views.users)  — legacy <2.0 form
DJANGO_LEGACY_URL_PATTERN = re.compile(
    r'\burl\s*\(\s*r?[\'"]([^\'"]+)[\'"]\s*,',
)
# Django REST Framework: router.register(r'users', UserViewSet)
DRF_ROUTER_PATTERN = re.compile(
    r'\brouter\.register\s*\(\s*r?[\'"]([^\'"]+)[\'"]\s*,',
)
# Django @api_view(['GET', 'POST'])
DJANGO_API_VIEW_PATTERN = re.compile(
    r'@api_view\s*\(\s*\[([^\]]+)\]\s*\)',
)

# Starlette: Route("/x", endpoint=h, methods=["GET", "POST"])
STARLETTE_ROUTE_PATTERN = re.compile(
    r'\bRoute\s*\(\s*[\'"]([^\'"]+)[\'"]\s*,(?P<rest>[^)]*?)\)',
    re.DOTALL,
)
# Starlette WebSocketRoute("/ws", endpoint=h)
STARLETTE_WS_PATTERN = re.compile(
    r'\bWebSocketRoute\s*\(\s*[\'"]([^\'"]+)[\'"]',
)

# AIOHTTP: app.router.add_get("/x", h), app.router.add_post(...)
# also app.add_routes([web.get("/x", h)])
AIOHTTP_ADD_PATTERN = re.compile(
    r'\b(?:app|router)\.(?:router\.)?add_(get|post|put|delete|patch|head|options)\s*\(\s*[\'"]([^\'"]+)[\'"]',
    re.IGNORECASE,
)
AIOHTTP_WEB_HELPER_PATTERN = re.compile(
    r'\bweb\.(get|post|put|delete|patch|head|options)\s*\(\s*[\'"]([^\'"]+)[\'"]',
    re.IGNORECASE,
)

# Sanic: @app.get("/x"), @bp.post("/x")
SANIC_DECORATOR_PATTERN = re.compile(
    r'@(?:app|bp|blueprint)\.(get|post|put|delete|patch|head|options)\s*\(\s*[\'"]([^\'"]+)[\'"]',
    re.IGNORECASE,
)

# Litestar (and legacy Starlite): @get("/x"), @post("/x") top-level decorators
# Only fire when the file imports from litestar/starlite to avoid mis-firing on
# generic identifiers named `get` or `post`.
LITESTAR_DECORATOR_PATTERN = re.compile(
    r'^@(get|post|put|delete|patch|head|options)\s*\(\s*[\'"]([^\'"]+)[\'"]',
    re.MULTILINE,
)

# Flask add_url_rule (less common but valid)
FLASK_ADD_URL_RULE_PATTERN = re.compile(
    r'\b\w+\.add_url_rule\s*\(\s*[\'"]([^\'"]+)[\'"]',
)


# External HTTP clients (additive over built-in scanner which covers `requests.*`)
OUTBOUND_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r'\bhttpx\.(?:get|post|put|delete|patch|head)\s*\(\s*[\'"](https?://[^\'"]+)[\'"]', re.IGNORECASE),
    re.compile(r'\bhttpx\.(?:Async)?Client\(\s*\)\.\w+\s*\(\s*[\'"](https?://[^\'"]+)[\'"]', re.IGNORECASE),
    re.compile(r'\baiohttp\.ClientSession\(\s*\)\.\w+\s*\(\s*[\'"](https?://[^\'"]+)[\'"]', re.IGNORECASE),
    re.compile(r'\bsession\.(?:get|post|put|delete|patch|head)\s*\(\s*[\'"](https?://[^\'"]+)[\'"]', re.IGNORECASE),
    re.compile(r'\burllib\.request\.urlopen\s*\(\s*[\'"](https?://[^\'"]+)[\'"]'),
    re.compile(r'\burlopen\s*\(\s*[\'"](https?://[^\'"]+)[\'"]'),
]


# Databases — SQLAlchemy with dialect inference
SQLALCHEMY_ENGINE_PATTERN = re.compile(
    r'\bcreate_engine\s*\(\s*[\'"]([a-z]+)(?:\+[a-z0-9_]+)?://',
    re.IGNORECASE,
)
DB_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r'\basyncpg\.connect\s*\(|\basyncpg\.create_pool\s*\('), "postgresql"),
    (re.compile(r'\bpsycopg(?:2|3)?\.connect\s*\(|\bpsycopg_pool\b'), "postgresql"),
    (re.compile(r'\bpymysql\.connect\s*\('), "mysql"),
    (re.compile(r'\bmotor\.motor_asyncio\.AsyncIOMotorClient\s*\(|\bAsyncIOMotorClient\s*\('), "mongodb"),
    (re.compile(r'\bpymongo\.MongoClient\s*\(|\bMongoClient\s*\('), "mongodb"),
    (re.compile(r'\baioredis\b|\bredis\.asyncio\b'), "redis"),
    (re.compile(r'\bboto3\.(?:resource|client)\s*\(\s*[\'"]dynamodb[\'"]'), "dynamodb"),
    (re.compile(r'\bboto3\.(?:resource|client)\s*\(\s*[\'"]s3[\'"]'), "object_storage"),
    (re.compile(r'\bsqlmodel\b|\bSQLModel\b'), "sql"),
    (re.compile(r'\btortoise\.\w+|\bfrom\s+tortoise\s+import\b'), "sql"),
]
# Django settings.py DATABASES dict
DJANGO_DATABASES_PATTERN = re.compile(
    r'DATABASES\s*=\s*\{(?P<body>.*?)\}\s*\n\s*(?:\n|[A-Z_]+\s*=)',
    re.DOTALL,
)
DJANGO_ENGINE_PATTERN = re.compile(
    r'[\'"]ENGINE[\'"]\s*:\s*[\'"]django\.db\.backends\.([a-z0-9_]+)[\'"]',
)


# Auth libraries
AUTH_PATTERNS: list[tuple[re.Pattern[str], str, float]] = [
    (re.compile(r'\bpasslib\.\w+|\bCryptContext\s*\('), "passlib", 0.85),
    (re.compile(r'\bpasslib\.hash\.argon2\b|\bargon2\.PasswordHasher\b|\bfrom\s+argon2\s+import'), "argon2", 0.9),
    (re.compile(r'\bpasslib\.hash\.bcrypt\b|\bbcrypt\.hashpw\s*\(|\bbcrypt\.checkpw\s*\(|\bimport\s+bcrypt\b'), "bcrypt", 0.9),
    (re.compile(r'\bpasslib\.hash\.scrypt\b'), "scrypt", 0.9),
    (re.compile(r'\bjwt\.(?:encode|decode)\s*\(|\bfrom\s+jose\s+import\s+jwt\b|\bjose\.jwt\b'), "jwt", 0.85),
    (re.compile(r'\bauthlib\.\w+|\bOAuth\(\s*\)|\bOAuth2Session\s*\('), "oauth", 0.85),
    (re.compile(r'\bfastapi_users\.\w+|\bBearerTransport\s*\(|\bJWTStrategy\s*\('), "fastapi_users", 0.85),
    (re.compile(r'@jwt_required\b|\bcreate_access_token\s*\(|\bflask_jwt_extended\b'), "flask_jwt_extended", 0.85),
    (re.compile(r'\bdjango\.contrib\.auth\b|\bauthenticate\s*\(\s*request\b|\bmake_password\s*\('), "django_auth", 0.85),
    (re.compile(r'\bcasbin\.Enforcer\s*\(|\bfrom\s+casbin\b'), "casbin", 0.9),
    (re.compile(r'\bAuthorization\b'), "authorization_header", 0.6),
    (re.compile(r'\bBearer\b'), "bearer_token", 0.6),
    (re.compile(r'\bapi[_-]?key\b', re.IGNORECASE), "api_key", 0.6),
]


# Frameworks
FRAMEWORK_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r'\bfrom\s+django\b|\bimport\s+django\b'), "django"),
    (re.compile(r'\bfrom\s+rest_framework\b|\bimport\s+rest_framework\b'), "django-rest-framework"),
    (re.compile(r'\bfrom\s+starlette\b|\bimport\s+starlette\b'), "starlette"),
    (re.compile(r'\bfrom\s+aiohttp\b|\bimport\s+aiohttp\b'), "aiohttp"),
    (re.compile(r'\bfrom\s+sanic\b|\bimport\s+sanic\b'), "sanic"),
    (re.compile(r'\bfrom\s+litestar\b|\bfrom\s+starlite\b'), "litestar"),
    (re.compile(r'\bfrom\s+tornado\b|\bimport\s+tornado\b'), "tornado"),
    (re.compile(r'\bfrom\s+flask\b|\bimport\s+flask\b'), "flask"),
    (re.compile(r'\bfrom\s+fastapi\b|\bimport\s+fastapi\b'), "fastapi"),
    (re.compile(r'\bfrom\s+sqlalchemy\b|\bimport\s+sqlalchemy\b'), "sqlalchemy"),
    (re.compile(r'\bfrom\s+celery\b|\bimport\s+celery\b'), "celery"),
    (re.compile(r'\bfrom\s+uvicorn\b|\bimport\s+uvicorn\b'), "uvicorn"),
    (re.compile(r'\bfrom\s+gunicorn\b|\bimport\s+gunicorn\b'), "gunicorn"),
]


# Entrypoints
ENTRYPOINT_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r'\buvicorn\.run\s*\('), "uvicorn_run"),
    (re.compile(r'\bweb\.run_app\s*\('), "aiohttp_run_app"),
    (re.compile(r'\bapp\.run\s*\('), "wsgi_app_run"),  # Flask, Sanic, AIOHTTP variants
    (re.compile(r'\btornado\.ioloop\.IOLoop\.current\(\)\.start\s*\('), "tornado_ioloop_start"),
    (re.compile(r'\bif\s+__name__\s*==\s*[\'"]__main__[\'"]\s*:'), "main_guard"),
    (re.compile(r'\bSparkSession\.builder\b'), "spark_session"),  # data plane
]


# Secrets — additive over built-in (which covers os.getenv).
SECRET_PATTERNS: list[re.Pattern[str]] = [
    re.compile(
        r'\bos\.environ\.get\s*\(\s*[\'"]([A-Z0-9_]*(?:SECRET|TOKEN|KEY|PASSWORD|PASS|PWD)[A-Z0-9_]*)[\'"]',
    ),
    re.compile(
        r'\bos\.environ\s*\[\s*[\'"]([A-Z0-9_]*(?:SECRET|TOKEN|KEY|PASSWORD|PASS|PWD)[A-Z0-9_]*)[\'"]\s*\]',
    ),
    re.compile(
        r'\bdotenv_values\s*\(.*?\)\s*\.get\s*\(\s*[\'"]([A-Z0-9_]*(?:SECRET|TOKEN|KEY|PASSWORD|PASS|PWD)[A-Z0-9_]*)[\'"]',
        re.DOTALL,
    ),
]


def _line_of(content: str, offset: int) -> int:
    if offset <= 0:
        return 1
    return content.count("\n", 0, offset) + 1


def _line_snippet(content: str, offset: int, *, max_chars: int = _SNIPPET_MAX_CHARS) -> str:
    line_start = content.rfind("\n", 0, offset) + 1
    line_end = content.find("\n", offset)
    if line_end == -1:
        line_end = len(content)
    line = content[line_start:line_end].strip()
    if len(line) > max_chars:
        line = line[: max_chars - 1] + "…"
    return line


def _name_from_pyproject(pyproject_path: Path) -> str | None:
    if not pyproject_path.exists():
        return None
    try:
        text = pyproject_path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return None
    # Try [project] name = "..." (PEP 621)
    match = re.search(r'\[project\][^\[]*?name\s*=\s*["\']([^"\']+)["\']', text, re.DOTALL)
    if match:
        return match.group(1).strip()
    # Fall back to [tool.poetry] name = "..."
    match = re.search(r'\[tool\.poetry\][^\[]*?name\s*=\s*["\']([^"\']+)["\']', text, re.DOTALL)
    if match:
        return match.group(1).strip()
    return None


def _name_from_setup_py(setup_path: Path) -> str | None:
    if not setup_path.exists():
        return None
    try:
        text = setup_path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return None
    match = re.search(r'\bname\s*=\s*["\']([^"\']+)["\']', text)
    if match:
        return match.group(1).strip()
    return None


def _name_from_setup_cfg(setup_cfg_path: Path) -> str | None:
    if not setup_cfg_path.exists():
        return None
    try:
        text = setup_cfg_path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return None
    match = re.search(r'\[metadata\][^\[]*?name\s*=\s*([^\s\n]+)', text, re.DOTALL)
    if match:
        return match.group(1).strip()
    return None


def _is_django_settings(content: str) -> bool:
    return bool(re.search(r'\b(INSTALLED_APPS|DATABASES|MIDDLEWARE|ROOT_URLCONF)\s*=', content))


def _is_django_urls(content: str) -> bool:
    return bool(re.search(r'\burlpatterns\s*=', content))


def _has_litestar_or_starlite_import(content: str) -> bool:
    return "litestar" in content or "starlite" in content


def _has_aiohttp_import(content: str) -> bool:
    return "aiohttp" in content or re.search(r'\bweb\.Application\s*\(', content) is not None


def _has_starlette_import(content: str) -> bool:
    return "starlette" in content


def _has_sanic_import(content: str) -> bool:
    return "sanic" in content


def _has_django_import(content: str) -> bool:
    return "django" in content or _is_django_urls(content) or _is_django_settings(content)


def _has_drf_import(content: str) -> bool:
    return "rest_framework" in content


class PythonAnalyzer:
    metadata = AnalyzerMetadata(
        name="python",
        display_name="Python Comprehensive Analyzer",
        version="0.1.0",
        description="Comprehensive Python analyzer for Django, Starlette, AIOHTTP, Sanic, Litestar, DRF; SQLAlchemy/asyncpg/motor; passlib/PyJWT/authlib; httpx/aiohttp.",
        scope="Python projects (pyproject.toml, setup.py, manage.py, or any *.py tree). Additive over the built-in python-web analyzer.",
        targets=["python", "django", "starlette", "aiohttp", "sanic", "litestar"],
        languages=["python"],
        priority=15,  # Slightly higher priority than the built-in (20) — runs first; dedup handles overlap.
        experimental=False,
        enabled_by_default=True,
    )

    @property
    def name(self) -> str:
        return self.metadata.name

    # ---------- Public entry points ----------

    def detect(self, repo_path: str | Path) -> bool:
        root = Path(repo_path).resolve()
        if not root.exists() or not root.is_dir():
            return False
        for marker in ("pyproject.toml", "setup.py", "setup.cfg", "manage.py", "Pipfile"):
            if (root / marker).exists():
                return True
        for path in root.rglob("*.py"):
            if any(part in SKIP_DIRS for part in path.parts):
                continue
            return True
        return False

    def analyze(self, repo_path: str | Path) -> ScanResult:
        root = Path(repo_path).resolve()
        result = ScanResult(root=str(root))
        if not root.exists() or not root.is_dir():
            return result

        # Service-name hints from project metadata
        for name_provider, marker in (
            (_name_from_pyproject, "pyproject.toml"),
            (_name_from_setup_py, "setup.py"),
            (_name_from_setup_cfg, "setup.cfg"),
        ):
            project_name = name_provider(root / marker)
            if project_name:
                self._append_unique_service(result, f"package:{project_name}", marker)
                break

        if (root / "manage.py").exists():
            self._append_unique_service(result, "framework:django", "manage.py")

        for file_path in root.rglob("*.py"):
            if not file_path.is_file():
                continue
            if any(part in SKIP_DIRS for part in file_path.parts):
                continue

            result.files_scanned += 1
            if "python" not in result.languages:
                result.languages.append("python")

            try:
                content = file_path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue

            relative = str(file_path.relative_to(root))
            self._extract_routes(content, relative, result)
            self._extract_databases(content, relative, result)
            self._extract_django_settings(content, relative, result)
            self._extract_auth(content, relative, result)
            self._extract_secrets(content, relative, result)
            self._extract_external_calls(content, relative, result)
            self._extract_frameworks(content, relative, result)
            self._extract_entrypoints(content, relative, result)

        result.languages.sort()
        return result

    # ---------- Extractors ----------

    def _extract_routes(self, content: str, relative: str, result: ScanResult) -> None:
        # Django routing only fires inside files that look like urls.py
        if _has_django_import(content) and _is_django_urls(content):
            for match in DJANGO_PATH_PATTERN.finditer(content):
                path = "/" + match.group(1).lstrip("/")
                self._append_unique_route(result, path, "ANY", relative, _line_of(content, match.start()))
            for match in DJANGO_RE_PATH_PATTERN.finditer(content):
                path = match.group(1)
                self._append_unique_route(result, path, "ANY", relative, _line_of(content, match.start()))
            for match in DJANGO_LEGACY_URL_PATTERN.finditer(content):
                path = match.group(1)
                self._append_unique_route(result, path, "ANY", relative, _line_of(content, match.start()))

        # Django REST Framework routers
        if _has_drf_import(content):
            for match in DRF_ROUTER_PATTERN.finditer(content):
                path = "/" + match.group(1).lstrip("/")
                self._append_unique_route(result, path, "ANY", relative, _line_of(content, match.start()))
            for match in DJANGO_API_VIEW_PATTERN.finditer(content):
                methods = re.findall(r'[\'"]([A-Z]+)[\'"]', match.group(1))
                # No path on @api_view alone — caller must pair with path() in urls.py.
                # We emit the methods as a low-signal hint via framework_hint to capture intent.
                line = _line_of(content, match.start())
                for method in methods:
                    self._append_unique_framework(
                        result, f"drf_api_view:{method}", relative, line,
                        _line_snippet(content, match.start()),
                    )

        # Starlette
        if _has_starlette_import(content):
            for match in STARLETTE_ROUTE_PATTERN.finditer(content):
                path = match.group(1)
                rest = match.group("rest") or ""
                methods_match = re.search(r'methods\s*=\s*\[([^\]]+)\]', rest)
                line = _line_of(content, match.start())
                if methods_match:
                    methods = [m.upper() for m in re.findall(r'[\'"]([A-Z]+)[\'"]', methods_match.group(1))]
                else:
                    methods = ["ANY"]
                for method in methods:
                    self._append_unique_route(result, path, method, relative, line)
            for match in STARLETTE_WS_PATTERN.finditer(content):
                path = match.group(1)
                self._append_unique_route(result, path, "WS", relative, _line_of(content, match.start()))

        # AIOHTTP — gated by import presence so generic `add_get`/`web.get` doesn't fire.
        if _has_aiohttp_import(content):
            for match in AIOHTTP_ADD_PATTERN.finditer(content):
                method, path = match.group(1).upper(), match.group(2)
                self._append_unique_route(result, path, method, relative, _line_of(content, match.start()))
            for match in AIOHTTP_WEB_HELPER_PATTERN.finditer(content):
                method, path = match.group(1).upper(), match.group(2)
                self._append_unique_route(result, path, method, relative, _line_of(content, match.start()))

        # Sanic — gated by sanic import
        if _has_sanic_import(content):
            for match in SANIC_DECORATOR_PATTERN.finditer(content):
                method, path = match.group(1).upper(), match.group(2)
                self._append_unique_route(result, path, method, relative, _line_of(content, match.start()))

        # Litestar / Starlite — gated to avoid false positives on generic `@get(...)` decorators.
        if _has_litestar_or_starlite_import(content):
            for match in LITESTAR_DECORATOR_PATTERN.finditer(content):
                method, path = match.group(1).upper(), match.group(2)
                self._append_unique_route(result, path, method, relative, _line_of(content, match.start()))

        # Flask add_url_rule (additive — built-in covers @app.route)
        if "flask" in content.lower() or "Blueprint(" in content:
            for match in FLASK_ADD_URL_RULE_PATTERN.finditer(content):
                path = match.group(1)
                self._append_unique_route(result, path, "ANY", relative, _line_of(content, match.start()))

    def _extract_databases(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern, kind in DB_PATTERNS:
            match = pattern.search(content)
            if match is None:
                continue
            self._append_unique_database(
                result, kind, relative,
                _line_of(content, match.start()),
                _line_snippet(content, match.start()),
            )

        # SQLAlchemy with dialect inference
        for match in SQLALCHEMY_ENGINE_PATTERN.finditer(content):
            dialect = match.group(1).lower()
            kind = {
                "postgresql": "postgresql",
                "postgres": "postgresql",
                "mysql": "mysql",
                "mariadb": "mariadb",
                "sqlite": "sqlite",
                "oracle": "oracle",
                "mssql": "sqlserver",
            }.get(dialect, "sql")
            self._append_unique_database(
                result, kind, relative,
                _line_of(content, match.start()),
                _line_snippet(content, match.start()),
            )

    def _extract_django_settings(self, content: str, relative: str, result: ScanResult) -> None:
        if not _is_django_settings(content):
            return
        # DATABASES dict — extract ENGINE values
        for match in DJANGO_ENGINE_PATTERN.finditer(content):
            engine_short = match.group(1).lower()
            kind = {
                "postgresql": "postgresql",
                "postgresql_psycopg2": "postgresql",
                "mysql": "mysql",
                "sqlite3": "sqlite",
                "oracle": "oracle",
            }.get(engine_short, "sql")
            self._append_unique_database(
                result, kind, relative,
                _line_of(content, match.start()),
                _line_snippet(content, match.start()),
            )
        # INSTALLED_APPS — extract third-party / local apps as service hints
        installed_match = re.search(r'INSTALLED_APPS\s*=\s*\[(?P<body>.*?)\]', content, re.DOTALL)
        if installed_match:
            for app_match in re.finditer(r'[\'"]([a-zA-Z][\w.]*)[\'"]', installed_match.group("body")):
                app_name = app_match.group(1)
                # Skip Django built-ins to keep signal high.
                if app_name.startswith("django.") or app_name in {"django"}:
                    continue
                self._append_unique_service(result, f"django_app:{app_name}", relative)

    def _extract_auth(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern, hint, confidence in AUTH_PATTERNS:
            match = pattern.search(content)
            if match is None:
                continue
            self._append_unique_auth(
                result, hint, relative,
                _line_of(content, match.start()),
                _line_snippet(content, match.start()),
                confidence,
            )

    def _extract_secrets(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern in SECRET_PATTERNS:
            for match in pattern.finditer(content):
                name = match.group(1)
                self._append_unique_secret(
                    result, name, relative,
                    _line_of(content, match.start()),
                    _line_snippet(content, match.start()),
                )
        # pydantic-settings BaseSettings: class Settings(BaseSettings): jwt_secret: str = ...
        if "BaseSettings" in content:
            for match in re.finditer(
                r'^\s+([a-zA-Z_][a-zA-Z0-9_]*(?:secret|token|key|password|pass|pwd)[a-zA-Z0-9_]*)\s*:\s*\w',
                content,
                re.MULTILINE | re.IGNORECASE,
            ):
                name = match.group(1)
                self._append_unique_secret(
                    result, name, relative,
                    _line_of(content, match.start()),
                    _line_snippet(content, match.start()),
                )

    def _extract_external_calls(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern in OUTBOUND_PATTERNS:
            for match in pattern.finditer(content):
                target = match.group(1)
                if not (target.startswith("http://") or target.startswith("https://")):
                    continue
                self._append_unique_external(
                    result, target, relative,
                    _line_of(content, match.start()),
                    _line_snippet(content, match.start()),
                )

    def _extract_frameworks(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern, name in FRAMEWORK_PATTERNS:
            match = pattern.search(content)
            if match is None:
                continue
            self._append_unique_framework(
                result, name, relative,
                _line_of(content, match.start()),
                _line_snippet(content, match.start()),
            )

    def _extract_entrypoints(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern, hint in ENTRYPOINT_PATTERNS:
            match = pattern.search(content)
            if match is None:
                continue
            self._append_unique_entrypoint(
                result, hint, relative,
                _line_of(content, match.start()),
                _line_snippet(content, match.start()),
            )

    # ---------- Append helpers ----------

    @staticmethod
    def _append_unique_route(result: ScanResult, path: str, method: str, file: str, line: int | None) -> None:
        key = (path, method, file)
        if any((item.path, item.method, item.file) == key for item in result.routes):
            return
        result.routes.append(Route(path=path, method=method, file=file, line=line))

    @staticmethod
    def _append_unique_database(result: ScanResult, kind: str, file: str, line: int | None, evidence: str | None) -> None:
        key = (kind, file)
        if any((item.kind, item.file) == key for item in result.databases):
            return
        result.databases.append(DatabaseHint(kind=kind, file=file, line=line, evidence_text=evidence))

    @staticmethod
    def _append_unique_auth(result: ScanResult, hint: str, file: str, line: int | None, evidence: str | None, confidence: float) -> None:
        key = (hint, file)
        if any((item.hint, item.file) == key for item in result.auth_hints):
            return
        result.auth_hints.append(AuthHint(hint=hint, file=file, line=line, evidence_text=evidence, confidence=confidence))

    @staticmethod
    def _append_unique_secret(result: ScanResult, name: str, file: str, line: int | None, evidence: str | None) -> None:
        key = (name, file)
        if any((item.name, item.file) == key for item in result.secret_hints):
            return
        result.secret_hints.append(SecretHint(name=name, file=file, line=line, evidence_text=evidence, confidence=0.85))

    @staticmethod
    def _append_unique_external(result: ScanResult, target: str, file: str, line: int | None, evidence: str | None) -> None:
        key = (target, file)
        if any((item.target, item.file) == key for item in result.external_calls):
            return
        result.external_calls.append(ExternalCall(target=target, file=file, line=line, evidence_text=evidence))

    @staticmethod
    def _append_unique_framework(result: ScanResult, hint: str, file: str, line: int | None, evidence: str | None) -> None:
        key = (hint, file)
        if any((item.hint, item.file) == key for item in result.framework_hints):
            return
        result.framework_hints.append(FrameworkHint(hint=hint, file=file, line=line, evidence_text=evidence))

    @staticmethod
    def _append_unique_entrypoint(result: ScanResult, hint: str, file: str, line: int | None, evidence: str | None) -> None:
        key = (hint, file)
        if any((item.hint, item.file) == key for item in result.entrypoint_hints):
            return
        result.entrypoint_hints.append(EntrypointHint(hint=hint, file=file, line=line, evidence_text=evidence))

    @staticmethod
    def _append_unique_service(result: ScanResult, hint: str, file: str) -> None:
        key = (hint, file)
        if any((item.hint, item.file) == key for item in result.service_hints):
            return
        result.service_hints.append(ServiceHint(hint=hint, file=file))


__all__ = ["PythonAnalyzer"]
