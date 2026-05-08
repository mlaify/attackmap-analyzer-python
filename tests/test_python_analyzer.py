"""Tests for the PythonAnalyzer plugin."""

from __future__ import annotations

from pathlib import Path

import pytest

from attackmap_analyzer_python import PythonAnalyzer


# ---------- detect() ----------


def test_detect_picks_up_pyproject(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "demo"\n', encoding="utf-8")
    assert PythonAnalyzer().detect(tmp_path) is True


def test_detect_picks_up_manage_py(tmp_path: Path) -> None:
    (tmp_path / "manage.py").write_text("# django\n", encoding="utf-8")
    assert PythonAnalyzer().detect(tmp_path) is True


def test_detect_picks_up_bare_py(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text("print('hi')\n", encoding="utf-8")
    assert PythonAnalyzer().detect(tmp_path) is True


def test_detect_skips_venv(tmp_path: Path) -> None:
    (tmp_path / ".venv" / "lib").mkdir(parents=True)
    (tmp_path / ".venv" / "lib" / "stale.py").write_text("# venv leftover\n", encoding="utf-8")
    assert PythonAnalyzer().detect(tmp_path) is False


def test_detect_returns_false_for_empty(tmp_path: Path) -> None:
    assert PythonAnalyzer().detect(tmp_path) is False


# ---------- Django routes ----------


def test_django_path_extracts_routes(tmp_path: Path) -> None:
    src = tmp_path / "app" / "urls.py"
    src.parent.mkdir(parents=True)
    src.write_text(
        "from django.urls import path\n"
        "from . import views\n"
        "\n"
        "urlpatterns = [\n"
        "    path('users/', views.users, name='users'),\n"
        "    path('users/<int:id>/', views.user_detail, name='user-detail'),\n"
        "    path('admin/refund/', views.refund, name='refund'),\n"
        "]\n",
        encoding="utf-8",
    )
    result = PythonAnalyzer().analyze(tmp_path)
    paths = {r.path for r in result.routes}
    assert "/users/" in paths
    assert "/users/<int:id>/" in paths
    assert "/admin/refund/" in paths


def test_django_re_path_extracts_routes(tmp_path: Path) -> None:
    (tmp_path / "urls.py").write_text(
        "from django.urls import re_path\n"
        "from . import views\n"
        "urlpatterns = [\n"
        "    re_path(r'^api/v1/users/$', views.users),\n"
        "    re_path(r'^api/v1/users/(?P<pk>\\d+)/$', views.user_detail),\n"
        "]\n",
        encoding="utf-8",
    )
    result = PythonAnalyzer().analyze(tmp_path)
    paths = {r.path for r in result.routes}
    assert "^api/v1/users/$" in paths


def test_drf_router_register_extracts_routes(tmp_path: Path) -> None:
    (tmp_path / "urls.py").write_text(
        "from django.urls import path, include\n"
        "from rest_framework import routers\n"
        "from .views import UserViewSet\n"
        "\n"
        "router = routers.DefaultRouter()\n"
        "router.register(r'users', UserViewSet)\n"
        "router.register(r'orders', OrderViewSet)\n"
        "\n"
        "urlpatterns = [path('api/', include(router.urls))]\n",
        encoding="utf-8",
    )
    result = PythonAnalyzer().analyze(tmp_path)
    paths = {r.path for r in result.routes}
    assert "/users" in paths
    assert "/orders" in paths


def test_drf_api_view_methods_emit_framework_hints(tmp_path: Path) -> None:
    (tmp_path / "views.py").write_text(
        "from rest_framework.decorators import api_view\n"
        "from rest_framework.response import Response\n"
        "\n"
        "@api_view(['GET', 'POST'])\n"
        "def items(request):\n"
        "    return Response({})\n",
        encoding="utf-8",
    )
    result = PythonAnalyzer().analyze(tmp_path)
    hints = {f.hint for f in result.framework_hints}
    assert "drf_api_view:GET" in hints
    assert "drf_api_view:POST" in hints


def test_django_routes_skip_when_no_django_import(tmp_path: Path) -> None:
    """A bare path("/x", ...) call without Django context must NOT fire."""
    (tmp_path / "fake.py").write_text(
        "from pathlib import Path\n"
        "p = Path('/users/')\n"
        "# Nothing django-y here.\n",
        encoding="utf-8",
    )
    result = PythonAnalyzer().analyze(tmp_path)
    assert result.routes == []


# ---------- Starlette ----------


def test_starlette_route_with_methods(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from starlette.applications import Starlette\n"
        "from starlette.routing import Route\n"
        "\n"
        "async def homepage(request): pass\n"
        "async def login(request): pass\n"
        "\n"
        "routes = [\n"
        "    Route('/', endpoint=homepage),\n"
        "    Route('/login', endpoint=login, methods=['GET', 'POST']),\n"
        "    Route('/admin/refund', endpoint=refund, methods=['POST']),\n"
        "]\n"
        "\n"
        "app = Starlette(routes=routes)\n",
        encoding="utf-8",
    )
    result = PythonAnalyzer().analyze(tmp_path)
    pairs = sorted({(r.path, r.method) for r in result.routes})
    assert ("/", "ANY") in pairs
    assert ("/login", "GET") in pairs
    assert ("/login", "POST") in pairs
    assert ("/admin/refund", "POST") in pairs


def test_starlette_websocket_route(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from starlette.routing import WebSocketRoute\n"
        "routes = [WebSocketRoute('/ws/notifications', endpoint=ws_handler)]\n",
        encoding="utf-8",
    )
    result = PythonAnalyzer().analyze(tmp_path)
    assert any(r.path == "/ws/notifications" and r.method == "WS" for r in result.routes)


# ---------- AIOHTTP ----------


def test_aiohttp_add_routes(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from aiohttp import web\n"
        "\n"
        "async def health(request): return web.Response(text='ok')\n"
        "async def login(request): return web.Response()\n"
        "\n"
        "app = web.Application()\n"
        "app.router.add_get('/health', health)\n"
        "app.router.add_post('/login', login)\n"
        "app.router.add_delete('/users/{id}', delete_user)\n",
        encoding="utf-8",
    )
    result = PythonAnalyzer().analyze(tmp_path)
    pairs = {(r.path, r.method) for r in result.routes}
    assert ("/health", "GET") in pairs
    assert ("/login", "POST") in pairs
    assert ("/users/{id}", "DELETE") in pairs


def test_aiohttp_web_helper_routes(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from aiohttp import web\n"
        "app = web.Application()\n"
        "app.add_routes([\n"
        "    web.get('/api/users', list_users),\n"
        "    web.post('/api/users', create_user),\n"
        "])\n",
        encoding="utf-8",
    )
    result = PythonAnalyzer().analyze(tmp_path)
    pairs = {(r.path, r.method) for r in result.routes}
    assert ("/api/users", "GET") in pairs
    assert ("/api/users", "POST") in pairs


def test_aiohttp_routes_skip_when_no_aiohttp_import(tmp_path: Path) -> None:
    """`web.get(...)` without an aiohttp import must NOT fire (could be any module)."""
    (tmp_path / "fake.py").write_text(
        "class Web:\n"
        "    def get(self, *a): pass\n"
        "web = Web()\n"
        "web.get('/api/users', None)\n",
        encoding="utf-8",
    )
    result = PythonAnalyzer().analyze(tmp_path)
    assert result.routes == []


# ---------- Sanic ----------


def test_sanic_decorator_routes(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from sanic import Sanic, response\n"
        "\n"
        "app = Sanic('demo')\n"
        "\n"
        "@app.get('/health')\n"
        "async def health(request):\n"
        "    return response.text('ok')\n"
        "\n"
        "@app.post('/login')\n"
        "async def login(request):\n"
        "    return response.json({})\n",
        encoding="utf-8",
    )
    result = PythonAnalyzer().analyze(tmp_path)
    pairs = {(r.path, r.method) for r in result.routes}
    assert ("/health", "GET") in pairs
    assert ("/login", "POST") in pairs


# ---------- Litestar ----------


def test_litestar_decorator_routes(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from litestar import Litestar, get, post\n"
        "\n"
        "@get('/users')\n"
        "async def list_users(): pass\n"
        "\n"
        "@post('/users')\n"
        "async def create_user(): pass\n"
        "\n"
        "app = Litestar(route_handlers=[list_users, create_user])\n",
        encoding="utf-8",
    )
    result = PythonAnalyzer().analyze(tmp_path)
    pairs = {(r.path, r.method) for r in result.routes}
    assert ("/users", "GET") in pairs
    assert ("/users", "POST") in pairs


def test_litestar_routes_skip_without_import(tmp_path: Path) -> None:
    """A bare `@get('/x')` decorator without litestar import must NOT fire."""
    (tmp_path / "fake.py").write_text(
        "from functools import wraps\n"
        "def get(path):\n"
        "    def decorator(fn): return fn\n"
        "    return decorator\n"
        "\n"
        "@get('/users')\n"
        "def my_handler(): pass\n",
        encoding="utf-8",
    )
    result = PythonAnalyzer().analyze(tmp_path)
    assert result.routes == []


# ---------- Flask add_url_rule ----------


def test_flask_add_url_rule(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        "app.add_url_rule('/api/health', view_func=health_handler)\n",
        encoding="utf-8",
    )
    result = PythonAnalyzer().analyze(tmp_path)
    assert any(r.path == "/api/health" for r in result.routes)


# ---------- SQLAlchemy ----------


def test_sqlalchemy_postgres_engine_dialect_inferred(tmp_path: Path) -> None:
    (tmp_path / "db.py").write_text(
        "from sqlalchemy import create_engine\n"
        "engine = create_engine('postgresql+psycopg://user:pass@localhost/app')\n",
        encoding="utf-8",
    )
    result = PythonAnalyzer().analyze(tmp_path)
    assert any(d.kind == "postgresql" for d in result.databases)


def test_sqlalchemy_sqlite_dialect_inferred(tmp_path: Path) -> None:
    (tmp_path / "db.py").write_text(
        "from sqlalchemy import create_engine\n"
        "engine = create_engine('sqlite:///app.db')\n",
        encoding="utf-8",
    )
    result = PythonAnalyzer().analyze(tmp_path)
    assert any(d.kind == "sqlite" for d in result.databases)


def test_asyncpg_pymysql_motor_emit_distinct_kinds(tmp_path: Path) -> None:
    (tmp_path / "pg.py").write_text("import asyncpg\nasync def x(): conn = await asyncpg.connect('postgresql://x')\n", encoding="utf-8")
    (tmp_path / "my.py").write_text("import pymysql\ndb = pymysql.connect(host='x')\n", encoding="utf-8")
    (tmp_path / "mongo.py").write_text(
        "from motor.motor_asyncio import AsyncIOMotorClient\n"
        "client = AsyncIOMotorClient('mongodb://x')\n",
        encoding="utf-8",
    )
    result = PythonAnalyzer().analyze(tmp_path)
    kinds = {d.kind for d in result.databases}
    assert "postgresql" in kinds
    assert "mysql" in kinds
    assert "mongodb" in kinds


def test_boto3_dynamodb_and_s3(tmp_path: Path) -> None:
    (tmp_path / "aws.py").write_text(
        "import boto3\n"
        "ddb = boto3.resource('dynamodb')\n"
        "s3 = boto3.client('s3')\n",
        encoding="utf-8",
    )
    result = PythonAnalyzer().analyze(tmp_path)
    kinds = {d.kind for d in result.databases}
    assert "dynamodb" in kinds
    assert "object_storage" in kinds


# ---------- Django settings ----------


def test_django_settings_extracts_databases_engine(tmp_path: Path) -> None:
    (tmp_path / "settings.py").write_text(
        "DATABASES = {\n"
        "    'default': {\n"
        "        'ENGINE': 'django.db.backends.postgresql',\n"
        "        'NAME': 'app',\n"
        "    }\n"
        "}\n"
        "\n"
        "INSTALLED_APPS = [\n"
        "    'django.contrib.admin',\n"
        "    'rest_framework',\n"
        "    'apps.users',\n"
        "    'apps.orders',\n"
        "]\n",
        encoding="utf-8",
    )
    result = PythonAnalyzer().analyze(tmp_path)
    assert any(d.kind == "postgresql" for d in result.databases)
    services = {h.hint for h in result.service_hints}
    assert "django_app:rest_framework" in services
    assert "django_app:apps.users" in services
    assert "django_app:apps.orders" in services
    # Django built-ins should be filtered out:
    assert not any(h.hint == "django_app:django.contrib.admin" for h in result.service_hints)


# ---------- Auth ----------


def test_passlib_argon2_bcrypt_high_confidence(tmp_path: Path) -> None:
    (tmp_path / "auth.py").write_text(
        "from passlib.context import CryptContext\n"
        "from argon2 import PasswordHasher\n"
        "import bcrypt\n"
        "\n"
        "pwd_context = CryptContext(schemes=['argon2'], deprecated='auto')\n"
        "ph = PasswordHasher()\n"
        "\n"
        "def hash_old(pw):\n"
        "    return bcrypt.hashpw(pw, bcrypt.gensalt())\n",
        encoding="utf-8",
    )
    result = PythonAnalyzer().analyze(tmp_path)
    by_hint = {h.hint: h for h in result.auth_hints}
    assert "passlib" in by_hint
    assert "argon2" in by_hint
    assert "bcrypt" in by_hint
    assert by_hint["argon2"].confidence == 0.9
    assert by_hint["bcrypt"].confidence == 0.9


def test_pyjwt_jose_jwt_emit_jwt_hint(tmp_path: Path) -> None:
    (tmp_path / "auth1.py").write_text(
        "import jwt\ntoken = jwt.encode({'sub': 'x'}, 'secret')\n",
        encoding="utf-8",
    )
    (tmp_path / "auth2.py").write_text(
        "from jose import jwt\nclaims = jwt.decode(token, 'secret')\n",
        encoding="utf-8",
    )
    result = PythonAnalyzer().analyze(tmp_path)
    assert any(h.hint == "jwt" for h in result.auth_hints)


def test_django_auth_signal(tmp_path: Path) -> None:
    (tmp_path / "views.py").write_text(
        "from django.contrib.auth import authenticate\n"
        "user = authenticate(request, username=u, password=p)\n",
        encoding="utf-8",
    )
    result = PythonAnalyzer().analyze(tmp_path)
    assert any(h.hint == "django_auth" for h in result.auth_hints)


def test_authlib_oauth_signal(tmp_path: Path) -> None:
    (tmp_path / "auth.py").write_text(
        "from authlib.integrations.flask_client import OAuth\n"
        "oauth = OAuth(app)\n",
        encoding="utf-8",
    )
    result = PythonAnalyzer().analyze(tmp_path)
    assert any(h.hint == "oauth" for h in result.auth_hints)


# ---------- Secrets ----------


def test_os_environ_get_secrets(tmp_path: Path) -> None:
    (tmp_path / "config.py").write_text(
        "import os\n"
        "JWT_SECRET = os.environ.get('JWT_SECRET')\n"
        "DB_PASS = os.environ['DATABASE_PASSWORD']\n"
        "API = os.environ.get('STRIPE_API_KEY')\n",
        encoding="utf-8",
    )
    result = PythonAnalyzer().analyze(tmp_path)
    names = {s.name for s in result.secret_hints}
    assert "JWT_SECRET" in names
    assert "DATABASE_PASSWORD" in names
    assert "STRIPE_API_KEY" in names

    jwt = next(s for s in result.secret_hints if s.name == "JWT_SECRET")
    assert jwt.line == 2


def test_pydantic_settings_secret_field_extracted(tmp_path: Path) -> None:
    (tmp_path / "settings.py").write_text(
        "from pydantic_settings import BaseSettings\n"
        "\n"
        "class Settings(BaseSettings):\n"
        "    database_url: str = ''\n"
        "    jwt_secret: str = ''\n"
        "    stripe_api_key: str = ''\n",
        encoding="utf-8",
    )
    result = PythonAnalyzer().analyze(tmp_path)
    names_lower = {s.name.lower() for s in result.secret_hints}
    assert "jwt_secret" in names_lower
    assert "stripe_api_key" in names_lower
    # `database_url` doesn't contain a secret keyword; should NOT be extracted.
    assert "database_url" not in names_lower


def test_os_environ_with_non_secret_name_skipped(tmp_path: Path) -> None:
    (tmp_path / "config.py").write_text(
        "import os\n"
        "HOME = os.environ.get('HOME')\n"
        "PATH = os.environ['PATH']\n",
        encoding="utf-8",
    )
    result = PythonAnalyzer().analyze(tmp_path)
    assert result.secret_hints == []


# ---------- External calls ----------


def test_httpx_get_extracted(tmp_path: Path) -> None:
    (tmp_path / "client.py").write_text(
        "import httpx\n"
        "resp = httpx.get('https://api.stripe.com/v1/charges')\n",
        encoding="utf-8",
    )
    result = PythonAnalyzer().analyze(tmp_path)
    targets = {e.target for e in result.external_calls}
    assert "https://api.stripe.com/v1/charges" in targets


def test_aiohttp_clientsession_extracted(tmp_path: Path) -> None:
    (tmp_path / "client.py").write_text(
        "import aiohttp\n"
        "async def fetch():\n"
        "    async with aiohttp.ClientSession() as session:\n"
        "        async with session.get('https://api.example.com/v2/data') as r:\n"
        "            return await r.json()\n",
        encoding="utf-8",
    )
    result = PythonAnalyzer().analyze(tmp_path)
    targets = {e.target for e in result.external_calls}
    assert "https://api.example.com/v2/data" in targets


def test_urllib_urlopen_extracted(tmp_path: Path) -> None:
    (tmp_path / "client.py").write_text(
        "import urllib.request\n"
        "with urllib.request.urlopen('https://example.com/data.json') as r:\n"
        "    data = r.read()\n",
        encoding="utf-8",
    )
    result = PythonAnalyzer().analyze(tmp_path)
    targets = {e.target for e in result.external_calls}
    assert "https://example.com/data.json" in targets


# ---------- Frameworks + entrypoints ----------


def test_uvicorn_run_entrypoint(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "import uvicorn\n"
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "if __name__ == '__main__':\n"
        "    uvicorn.run(app, host='0.0.0.0', port=8000)\n",
        encoding="utf-8",
    )
    result = PythonAnalyzer().analyze(tmp_path)
    fw = {f.hint for f in result.framework_hints}
    assert "fastapi" in fw
    assert "uvicorn" in fw
    ep = {e.hint for e in result.entrypoint_hints}
    assert "uvicorn_run" in ep


def test_aiohttp_run_app_entrypoint(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from aiohttp import web\n"
        "app = web.Application()\n"
        "web.run_app(app, host='0.0.0.0', port=8080)\n",
        encoding="utf-8",
    )
    result = PythonAnalyzer().analyze(tmp_path)
    ep = {e.hint for e in result.entrypoint_hints}
    assert "aiohttp_run_app" in ep


# ---------- Project metadata → service hints ----------


def test_pyproject_name_picked_up(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        "[project]\nname = \"orders-api\"\nversion = \"0.1.0\"\n",
        encoding="utf-8",
    )
    (tmp_path / "main.py").write_text("# noop\n", encoding="utf-8")
    result = PythonAnalyzer().analyze(tmp_path)
    assert any(h.hint == "package:orders-api" for h in result.service_hints)


def test_setup_py_name_picked_up(tmp_path: Path) -> None:
    (tmp_path / "setup.py").write_text(
        "from setuptools import setup\n"
        "setup(name='legacy-svc', version='0.1.0')\n",
        encoding="utf-8",
    )
    (tmp_path / "main.py").write_text("# noop\n", encoding="utf-8")
    result = PythonAnalyzer().analyze(tmp_path)
    assert any(h.hint == "package:legacy-svc" for h in result.service_hints)


def test_manage_py_marks_django(tmp_path: Path) -> None:
    (tmp_path / "manage.py").write_text("# Django manage.py\n", encoding="utf-8")
    (tmp_path / "main.py").write_text("# noop\n", encoding="utf-8")
    result = PythonAnalyzer().analyze(tmp_path)
    assert any(h.hint == "framework:django" for h in result.service_hints)


# ---------- End-to-end ----------


def test_full_django_drf_signal_set(tmp_path: Path) -> None:
    (tmp_path / "manage.py").write_text("# django\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        "[project]\nname = \"billing\"\n",
        encoding="utf-8",
    )

    settings = tmp_path / "billing" / "settings.py"
    settings.parent.mkdir()
    settings.write_text(
        "DATABASES = {\n"
        "    'default': {\n"
        "        'ENGINE': 'django.db.backends.postgresql',\n"
        "        'NAME': 'billing',\n"
        "    }\n"
        "}\n"
        "INSTALLED_APPS = [\n"
        "    'django.contrib.admin',\n"
        "    'rest_framework',\n"
        "    'billing.charges',\n"
        "]\n"
        "\n"
        "import os\n"
        "SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY')\n"
        "STRIPE_KEY = os.environ['STRIPE_SECRET_KEY']\n",
        encoding="utf-8",
    )

    urls = tmp_path / "billing" / "urls.py"
    urls.write_text(
        "from django.urls import path, include\n"
        "from rest_framework import routers\n"
        "from .views import ChargeViewSet, refund\n"
        "\n"
        "router = routers.DefaultRouter()\n"
        "router.register(r'charges', ChargeViewSet)\n"
        "\n"
        "urlpatterns = [\n"
        "    path('api/', include(router.urls)),\n"
        "    path('api/admin/refund/', refund, name='refund'),\n"
        "]\n",
        encoding="utf-8",
    )

    views = tmp_path / "billing" / "views.py"
    views.write_text(
        "import bcrypt\n"
        "import jwt\n"
        "import httpx\n"
        "from django.contrib.auth import authenticate\n"
        "from rest_framework.decorators import api_view\n"
        "\n"
        "@api_view(['POST'])\n"
        "def refund(request):\n"
        "    user = authenticate(request, username=request.data['u'], password=request.data['p'])\n"
        "    token = jwt.encode({'sub': user.id}, 'k')\n"
        "    httpx.post('https://api.stripe.com/v1/refunds')\n"
        "    return None\n",
        encoding="utf-8",
    )

    result = PythonAnalyzer().analyze(tmp_path)

    # Routes
    paths = {r.path for r in result.routes}
    assert "/charges" in paths
    assert "/api/" in paths
    assert "/api/admin/refund/" in paths

    # Database
    assert any(d.kind == "postgresql" for d in result.databases)

    # Frameworks
    fw = {f.hint for f in result.framework_hints}
    assert "django" in fw
    assert "django-rest-framework" in fw

    # Auth
    auth_hints = {h.hint for h in result.auth_hints}
    assert "jwt" in auth_hints
    assert "bcrypt" in auth_hints
    assert "django_auth" in auth_hints

    # Secrets
    secrets = {s.name for s in result.secret_hints}
    assert "DJANGO_SECRET_KEY" in secrets
    assert "STRIPE_SECRET_KEY" in secrets

    # External calls
    assert any(e.target == "https://api.stripe.com/v1/refunds" for e in result.external_calls)

    # Service hints
    services = {h.hint for h in result.service_hints}
    assert "package:billing" in services
    assert "framework:django" in services
    assert "django_app:rest_framework" in services
    assert "django_app:billing.charges" in services

    # Line numbers populated on routes
    assert all(r.line is not None for r in result.routes)
