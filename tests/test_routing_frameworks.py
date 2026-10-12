"""Routing coverage from mlaify/attackmap-analyzer-python#2: the Django
include() graph, aiohttp RouteTableDef, Litestar controllers/routers, Tornado
URLSpecs and Sanic @route(methods=...)."""

from __future__ import annotations

import random
import time
from pathlib import Path

import pytest

from attackmap_analyzer_python import PythonAnalyzer
from attackmap_analyzer_python import django_urls
from attackmap_analyzer_python._pyast import MAX_PARSE_CHARS


def _write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _routes(root: Path) -> set[tuple[str, str]]:
    return {(r.path, r.method) for r in PythonAnalyzer().analyze(root).routes}


def _paths(root: Path) -> set[str]:
    return {r.path for r in PythonAnalyzer().analyze(root).routes}


# ---------- Django: root path and include() prefixes ----------


def test_django_empty_path_is_site_root(tmp_path: Path) -> None:
    _write(tmp_path, "urls.py", (
        "from django.urls import path\n"
        "from . import views\n"
        "urlpatterns = [path('', views.home), path('about/', views.about)]\n"
    ))
    assert _paths(tmp_path) == {"/", "/about/"}


def test_django_issue_repro_include_prefix_and_no_include_route(tmp_path: Path) -> None:
    """The fixture from the issue: root path, an include()d child and the
    include line itself."""
    _write(tmp_path, "manage.py", "")
    _write(tmp_path, "shop/urls.py", (
        "from django.urls import include, path\n"
        "from . import views\n"
        "urlpatterns = [\n"
        "    path('', views.home),\n"
        "    path('api/', include('shop.api_urls')),\n"
        "]\n"
    ))
    _write(tmp_path, "shop/api_urls.py", (
        "from django.urls import path\n"
        "from . import views\n"
        "urlpatterns = [path('orders/<int:pk>/', views.order)]\n"
    ))
    result = PythonAnalyzer().analyze(tmp_path)
    by_path = {r.path: r for r in result.routes}
    assert set(by_path) == {"/", "/api/orders/<int:pk>/"}
    # The child route still points at the child URLconf line (core's view hop).
    assert by_path["/api/orders/<int:pk>/"].file == "shop/api_urls.py"
    assert by_path["/api/orders/<int:pk>/"].line == 3


def test_django_include_of_imported_module(tmp_path: Path) -> None:
    _write(tmp_path, "proj/urls.py", (
        "from django.urls import include, path\n"
        "from . import api_urls\n"
        "from .billing import urls as billing_urls\n"
        "urlpatterns = [\n"
        "    path('api/', include(api_urls)),\n"
        "    path('billing/', include(billing_urls)),\n"
        "]\n"
    ))
    _write(tmp_path, "proj/api_urls.py", (
        "from django.urls import path\n"
        "urlpatterns = [path('users/', v)]\n"
    ))
    _write(tmp_path, "proj/billing/urls.py", (
        "from django.urls import path\n"
        "urlpatterns = [path('refund/', v)]\n"
    ))
    assert _paths(tmp_path) == {"/api/users/", "/billing/refund/"}


def test_django_include_tuple_inline_and_local_list(tmp_path: Path) -> None:
    _write(tmp_path, "urls.py", (
        "from django.urls import include, path\n"
        "api_patterns = [path('me/', v), path('keys/', v)]\n"
        "admin_patterns = ([path('users/', v)], 'admin')\n"
        "urlpatterns = [\n"
        "    path('api/v1/', include(api_patterns)),\n"
        "    path('json/', include(api_patterns)),\n"
        "    path('staff/', include(admin_patterns)),\n"
        "    path('legacy/', include(([path('old/', v)], 'legacy'), namespace='legacy')),\n"
        "    path('inline/', include([path('a/', v), path('b/', include([path('c/', v)]))])),\n"
        "]\n"
    ))
    assert _paths(tmp_path) == {
        "/api/v1/me/", "/api/v1/keys/", "/json/me/", "/json/keys/",
        "/staff/users/", "/legacy/old/", "/inline/a/", "/inline/b/c/",
    }


def test_django_re_path_and_url_segments_join(tmp_path: Path) -> None:
    _write(tmp_path, "urls.py", (
        "from django.urls import include, re_path\n"
        "from django.conf.urls import url\n"
        "urlpatterns = [\n"
        "    re_path(r'^api/', include('child_urls')),\n"
        "    url(r'^$', v),\n"
        "]\n"
    ))
    _write(tmp_path, "child_urls.py", (
        "from django.urls import path, re_path\n"
        "urlpatterns = [\n"
        "    re_path(r'^users/(?P<pk>\\d+)/$', v),\n"
        "    path('me/', v),\n"
        "]\n"
    ))
    assert _paths(tmp_path) == {"/", "/api/users/(?P<pk>\\d+)/", "/api/me/"}


def test_django_three_level_include_under_project_dir(tmp_path: Path) -> None:
    """netbox layout: manage.py in a subdirectory is the sys.path root, and
    app URLconfs include each other by dotted path from there."""
    _write(tmp_path, "src/manage.py", "")
    _write(tmp_path, "src/proj/urls.py", (
        "from django.urls import include, path\n"
        "urlpatterns = [path('api/', include('dcim.api.urls'))]\n"
    ))
    _write(tmp_path, "src/dcim/api/urls.py", (
        "from django.urls import include, path\n"
        "urlpatterns = [path('v2/', include('dcim.api.v2_urls'))]\n"
    ))
    _write(tmp_path, "src/dcim/api/v2_urls.py", (
        "from django.urls import path\n"
        "urlpatterns = [path('sites/<int:pk>/', v)]\n"
    ))
    assert _paths(tmp_path) == {"/api/v2/sites/<int:pk>/"}


def test_django_unresolvable_include_keeps_its_prefix(tmp_path: Path) -> None:
    _write(tmp_path, "urls.py", (
        "from django.urls import include, path\n"
        "from django.contrib import admin\n"
        "urlpatterns = [\n"
        "    path('accounts/', include('allauth.urls')),\n"
        "    path('admin/', admin.site.urls),\n"
        "    path('dyn/', include(get_model_urls('dcim', 'site'))),\n"
        "    path('', include('django_prometheus.urls')),\n"
        "]\n"
    ))
    # Third-party mounts stay visible as their prefix; an empty one would claim "/".
    assert _paths(tmp_path) == {"/accounts/", "/admin/", "/dyn/"}


def test_django_drf_router_in_another_module_is_mounted(tmp_path: Path) -> None:
    """taiga layout: the router lives in routers.py (no rest_framework import)
    and urls.py mounts it with include(router.urls)."""
    _write(tmp_path, "app/routers.py", (
        "from app.base import routers\n"
        "router = routers.DefaultRouter(trailing_slash=False)\n"
        "router.register(r'projects', ProjectViewSet)\n"
        "router.register(r'users', UsersViewSet, base_name='users')\n"
    ))
    _write(tmp_path, "app/urls.py", (
        "from django.urls import include, path\n"
        "from .routers import router\n"
        "urlpatterns = [path('api/v1/', include(router.urls))]\n"
    ))
    result = PythonAnalyzer().analyze(tmp_path)
    assert {(r.path, r.file) for r in result.routes} == {
        ("/api/v1/projects", "app/routers.py"),
        ("/api/v1/users", "app/routers.py"),
    }


def test_django_urlpatterns_is_router_urls(tmp_path: Path) -> None:
    """netbox layout: an app's api/urls.py is `urlpatterns = router.urls`."""
    _write(tmp_path, "proj/urls.py", (
        "from django.urls import include, path\n"
        "urlpatterns = [path('api/dcim/', include('dcim.api.urls'))]\n"
    ))
    _write(tmp_path, "dcim/api/urls.py", (
        "from netbox.api.routers import NetBoxRouter\n"
        "from django.urls import path\n"
        "router = NetBoxRouter()\n"
        "router.register('sites', views.SiteViewSet)\n"
        "urlpatterns = [path('sites/<int:pk>/available/', v)]\n"
        "urlpatterns += router.urls\n"
    ))
    assert _paths(tmp_path) == {"/api/dcim/sites", "/api/dcim/sites/<int:pk>/available/"}


def test_django_unmounted_router_keeps_unprefixed_emission(tmp_path: Path) -> None:
    _write(tmp_path, "api.py", (
        "from rest_framework import routers\n"
        "router = routers.SimpleRouter()\n"
        "router.register(r'things', ThingViewSet)\n"
    ))
    assert _paths(tmp_path) == {"/things"}


def test_django_router_without_drf_or_django_mount_is_ignored(tmp_path: Path) -> None:
    """`X = SomeRouter(); X.register("...")` alone is not proof of a URL."""
    _write(tmp_path, "events.py", (
        "bus_router = EventRouter()\n"
        "bus_router.register('order.created', handle_order)\n"
    ))
    assert _paths(tmp_path) == set()


def test_django_list_mutations_debug_block_and_dynamic_prefix(tmp_path: Path) -> None:
    _write(tmp_path, "urls.py", (
        "from django.conf import settings\n"
        "from django.urls import include, path\n"
        "_patterns = [path('', home)]\n"
        "_patterns.append(path('search/', search))\n"
        "_patterns.extend([path('login/', login)])\n"
        "if settings.DEBUG:\n"
        "    _patterns += [path('__debug__/', include('debug_toolbar.urls'))]\n"
        "urlpatterns = [path(settings.BASE_PATH, include(_patterns))]\n"
        "urlpatterns = format_suffix_patterns(urlpatterns)\n"
    ))
    assert _paths(tmp_path) == {"/", "/search/", "/login/", "/__debug__/"}


def test_django_legacy_patterns_function(tmp_path: Path) -> None:
    _write(tmp_path, "site/urls.py", (
        "from django.conf.urls import patterns, include, url\n"
        "urlpatterns = patterns('',\n"
        "    url(r'^$', 'site.views.index'),\n"
        "    url(r'^tasks/', include('site.task_urls', namespace='tasks')),\n"
        ")\n"
    ))
    _write(tmp_path, "site/task_urls.py", (
        "from django.conf.urls import patterns, url\n"
        "urlpatterns = patterns('', url(r'^(?P<id>\\d+)/$', 'site.views.task'))\n"
    ))
    assert _paths(tmp_path) == {"/", "/tasks/(?P<id>\\d+)/"}


def test_django_i18n_patterns_and_star_args(tmp_path: Path) -> None:
    _write(tmp_path, "urls.py", (
        "from django.conf.urls.i18n import i18n_patterns\n"
        "from django.urls import path\n"
        "i18n_urls = [path('about/', about)]\n"
        "urls = [path('health', health)]\n"
        "urlpatterns = i18n_patterns(*i18n_urls) + urls\n"
    ))
    assert _paths(tmp_path) == {"/about/", "/health"}


def test_django_commented_out_paths_are_not_routes(tmp_path: Path) -> None:
    _write(tmp_path, "urls.py", (
        "from django.urls import path\n"
        "urlpatterns = [\n"
        "    path('live/', v),\n"
        "    # path('settings/', views.user_settings),\n"
        "]\n"
    ))
    assert _paths(tmp_path) == {"/live/"}


def test_django_paths_outside_lists_are_still_emitted(tmp_path: Path) -> None:
    """A path() inside a function (AppConfig.get_urls style) keeps the
    pre-#2 unprefixed emission; an empty one there isn't claimed as "/"."""
    _write(tmp_path, "apps.py", (
        "from django.urls import path\n"
        "class Config:\n"
        "    def get_urls(self):\n"
        "        urlpatterns = [path('', self.index), path('band/', self.band)]\n"
        "        return urlpatterns\n"
    ))
    assert _paths(tmp_path) == {"/band/"}


def test_django_include_cycle_terminates_and_keeps_routes(tmp_path: Path) -> None:
    _write(tmp_path, "a/urls.py", (
        "from django.urls import include, path\n"
        "urlpatterns = [path('b/', include('b.urls')), path('x/', v)]\n"
    ))
    _write(tmp_path, "b/urls.py", (
        "from django.urls import include, path\n"
        "urlpatterns = [path('a/', include('a.urls')), path('y/', v)]\n"
    ))
    paths = _paths(tmp_path)
    assert "/x/" in paths and "/b/y/" in paths
    assert len(paths) < 10


def test_django_unparseable_urlconf_falls_back_to_regex(tmp_path: Path) -> None:
    _write(tmp_path, "urls.py", (
        "from django.conf.urls import url, include\n"
        "print 'python 2'\n"
        "urlpatterns = [\n"
        "    url(r'^$', index),\n"
        "    url(r'^api/', include('api.urls')),\n"
        "]\n"
    ))
    assert _paths(tmp_path) == {"/", "/api/"}


def test_django_routes_skip_without_urlpatterns(tmp_path: Path) -> None:
    _write(tmp_path, "views.py", (
        "from django.urls import path, include\n"
        "x = [path('nope/', v), path('api/', include('a.urls'))]\n"
    ))
    assert _paths(tmp_path) == set()


# ---------- Django include resolver: bounds and fuzz ----------


_FUZZ_TOKENS = [
    "path('a/', v)", "path('', v)", "re_path(r'^r/$', v)", "url(r'^u/', v)",
    "path('i/', include('m{n}.urls'))", "path('', include('m{n}.urls'))",
    "path('t/', include(('m{n}.urls', 'ns')))", "path('l/', include(local))",
    "path('n/', include([path('in/', v), path('deep/', include('m{n}.urls'))]))",
    "path('r/', include(router.urls))", "path(settings.X, include('m{n}.urls'))",
    "path('missing/', include('nowhere.urls'))", "*local", "local", "router.urls",
    "path('z/', include(get_urls()))", "path()", "path('only')", "include('m{n}.urls')",
]


def _fuzz_urlconf(rng: random.Random, files: int) -> str:
    body = []
    for _ in range(rng.randint(0, 8)):
        token = rng.choice(_FUZZ_TOKENS).replace("{n}", str(rng.randrange(files)))
        body.append(token)
    lines = [
        "from django.urls import include, path, re_path",
        "router = routers.DefaultRouter()",
        f"router.register('r{rng.randrange(9)}', V)",
        "local = [" + ", ".join(rng.sample(body, k=len(body) // 2)) + "]",
        "urlpatterns = [" + ", ".join(body) + "]",
    ]
    if rng.random() < 0.3:
        lines.append("urlpatterns += local + router.urls")
    if rng.random() < 0.3:
        lines.append("local.append(path('late/', include('m0.urls')))")
    return "\n".join(lines) + "\n"


@pytest.mark.parametrize("seed", range(40))
def test_django_include_graph_fuzz_never_raises(tmp_path: Path, seed: int) -> None:
    """Random include graphs (cycles, self-includes, missing modules, garbage
    calls), plus a truncated copy of each file, must analyze without raising."""
    rng = random.Random(seed)
    files = rng.randint(1, 6)
    for n in range(files):
        text = _fuzz_urlconf(rng, files)
        if rng.random() < 0.3:
            text = text[: rng.randrange(len(text))]
        _write(tmp_path, f"m{n}/urls.py", text)
    result = PythonAnalyzer().analyze(tmp_path)
    assert len(result.routes) <= django_urls.MAX_ROUTES
    assert all(r.path.startswith("/") for r in result.routes)


@pytest.mark.parametrize("seed", range(20))
def test_django_urlconf_garbage_never_raises(tmp_path: Path, seed: int) -> None:
    rng = random.Random(1000 + seed)
    alphabet = "urlpatterns=[](){}'\",.:+*\n path include re_path url router.urls \\^$"
    text = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 400)))
    _write(tmp_path, "urls.py", "from django.urls import path\nurlpatterns = []\n" + text)
    PythonAnalyzer().analyze(tmp_path)  # must not raise


def test_django_include_fanout_is_bounded(tmp_path: Path) -> None:
    """Each level includes the next one 30 times: 30**8 paths unbounded. The
    resolver must stop at its prefix/step budgets and finish quickly."""
    levels = 8
    for n in range(levels):
        nxt = f"path('p{{i}}/', include('l{n + 1}.urls'))" if n + 1 < levels else "path('leaf{i}/', v)"
        items = ", ".join(nxt.format(i=i) for i in range(30))
        _write(tmp_path, f"l{n}/urls.py", f"from django.urls import include, path\nurlpatterns = [{items}]\n")
    start = time.monotonic()
    result = PythonAnalyzer().analyze(tmp_path)
    assert time.monotonic() - start < 20
    assert 0 < len(result.routes) <= django_urls.MAX_ROUTES


def test_django_pathological_nesting_never_raises(tmp_path: Path) -> None:
    _write(tmp_path, "a/urls.py", "from django.urls import path\nurlpatterns = " + "[" * 3000 + "]" * 3000 + "\n")
    terms = " + ".join(["extra"] * 3000)
    _write(tmp_path, "b/urls.py", f"from django.urls import path\nextra = [path('e/', v)]\nurlpatterns = {terms}\n")
    PythonAnalyzer().analyze(tmp_path)  # must not raise


def test_django_huge_urlconf_uses_regex_fallback(tmp_path: Path) -> None:
    padding = "# " + "x" * 100 + "\n"
    filler = padding * (MAX_PARSE_CHARS // len(padding) + 1)
    _write(tmp_path, "urls.py", (
        "from django.urls import path\n" + filler +
        "urlpatterns = [path('big/', v)]\n"
    ))
    assert _paths(tmp_path) == {"/big/"}


def test_join_segments_strips_regex_anchors_and_slashes() -> None:
    join = django_urls.join_segments
    assert join([]) == "/"
    assert join([("", False)]) == "/"
    assert join([("^$", True)]) == "/"
    assert join([("api/", False), ("^users/$", True)]) == "/api/users/"
    assert join([("^api/", True), ("v1/", False), ("x\\$", True)]) == "/api/v1/x\\$"
    assert join([("api/", False), ("/x", False)]) == "/api/x"


# ---------- aiohttp ----------


def test_aiohttp_route_table_def(tmp_path: Path) -> None:
    _write(tmp_path, "app.py", (
        "from aiohttp import web\n"
        "routes = web.RouteTableDef()\n"
        "\n"
        "@routes.get('/users')\n"
        "async def list_users(request): ...\n"
        "\n"
        "@routes.post('/users')\n"
        "async def create_user(request): ...\n"
        "\n"
        "@routes.view('/items/{id}')\n"
        "class ItemView(web.View): ...\n"
        "\n"
        "@routes.route('PATCH', '/users/{id}')\n"
        "async def patch_user(request): ...\n"
        "\n"
        "app = web.Application()\n"
        "app.add_routes(routes)\n"
        "app.router.add_route('*', '/any', handler)\n"
        "app.router.add_route('DELETE', '/users/{id}', handler)\n"
    ))
    assert _routes(tmp_path) == {
        ("/users", "GET"), ("/users", "POST"), ("/items/{id}", "ANY"),
        ("/users/{id}", "PATCH"), ("/any", "ANY"), ("/users/{id}", "DELETE"),
    }


def test_aiohttp_decorators_need_a_route_table(tmp_path: Path) -> None:
    """`@cache.get(...)` in an aiohttp file isn't a RouteTableDef route."""
    _write(tmp_path, "app.py", (
        "from aiohttp import web\n"
        "cache = Cache()\n"
        "@cache.get('/users')\n"
        "async def cached(): ...\n"
    ))
    assert _routes(tmp_path) == set()


def test_aiohttp_route_table_skips_without_aiohttp_import(tmp_path: Path) -> None:
    _write(tmp_path, "app.py", (
        "routes = RouteTableDef()\n"
        "@routes.get('/users')\n"
        "async def h(): ...\n"
    ))
    assert _routes(tmp_path) == set()


# ---------- Litestar ----------


def test_litestar_controller_paths_guards_and_exclusions(tmp_path: Path) -> None:
    _write(tmp_path, "app/controllers.py", (
        "from litestar import Controller, get, patch, post\n"
        "\n"
        "class UserController(Controller):\n"
        "    path = '/api/users'\n"
        "    guards = [requires_active_user]\n"
        "\n"
        "    @get()\n"
        "    async def list_users(self): ...\n"
        "\n"
        "    @post(operation_id='CreateUser', guards=[requires_superuser])\n"
        "    async def create_user(self): ...\n"
        "\n"
        "    @patch(path='/{user_id:uuid}')\n"
        "    async def update_user(self): ...\n"
        "\n"
        "class AccessController(Controller):\n"
        "    @post(\n"
        "        operation_id='Login',\n"
        "        path='/api/access/login',\n"
        "        exclude_from_auth=True,\n"
        "    )\n"
        "    async def login(self): ...\n"
        "\n"
        "    @get('/api/me')\n"
        "    async def me(self): ...\n"
    ))
    result = PythonAnalyzer().analyze(tmp_path)
    by = {(r.path, r.method): r for r in result.routes}
    assert set(by) == {
        ("/api/users", "GET"), ("/api/users", "POST"), ("/api/users/{user_id:uuid}", "PATCH"),
        ("/api/access/login", "POST"), ("/api/me", "GET"),
    }
    assert by[("/api/users", "GET")].auth == "required"
    assert by[("/api/users", "GET")].guards == ["requires_active_user"]
    assert by[("/api/users", "POST")].guards == ["requires_active_user", "requires_superuser"]
    assert by[("/api/access/login", "POST")].auth == "anonymous"
    assert by[("/api/me", "GET")].auth == "unknown"
    assert by[("/api/users", "POST")].line == 10


def test_litestar_router_prefixes_across_files(tmp_path: Path) -> None:
    _write(tmp_path, "app/users.py", (
        "from litestar import Controller, get, delete\n"
        "class UserController(Controller):\n"
        "    path = '/users'\n"
        "    @get('/{id:int}')\n"
        "    async def get_user(self): ...\n"
        "    @delete('/{id:int}')\n"
        "    async def delete_user(self): ...\n"
    ))
    _write(tmp_path, "app/health.py", (
        "from litestar import get\n"
        "@get('/health', exclude_from_auth=True)\n"
        "async def health(): ...\n"
    ))
    _write(tmp_path, "app/main.py", (
        "from litestar import Litestar, Router\n"
        "from app.users import UserController\n"
        "from app.health import health\n"
        "v1 = Router(path='/v1', route_handlers=[UserController], guards=[auth_guard])\n"
        "api = Router('/api', route_handlers=[v1])\n"
        "app = Litestar(route_handlers=[api, health])\n"
    ))
    result = PythonAnalyzer().analyze(tmp_path)
    by = {(r.path, r.method): r for r in result.routes}
    assert set(by) == {("/api/v1/users/{id:int}", "GET"), ("/api/v1/users/{id:int}", "DELETE"), ("/health", "GET")}
    assert by[("/api/v1/users/{id:int}", "GET")].auth == "required"
    assert by[("/api/v1/users/{id:int}", "GET")].guards == ["auth_guard"]
    assert by[("/health", "GET")].auth == "anonymous"


def test_litestar_route_and_websocket_decorators(tmp_path: Path) -> None:
    _write(tmp_path, "app.py", (
        "import litestar\n"
        "from litestar import route, websocket\n"
        "from litestar.enums import HttpMethod\n"
        "@route('/multi', http_method=[HttpMethod.GET, 'post'])\n"
        "async def multi(): ...\n"
        "@websocket('/ws')\n"
        "async def ws(socket): ...\n"
        "@litestar.get(['/a', '/b'])\n"
        "async def two(): ...\n"
        "def factory():\n"
        "    @litestar.post('/nested')\n"
        "    async def inner(): ...\n"
        "    return inner\n"
    ))
    assert _routes(tmp_path) == {
        ("/multi", "GET"), ("/multi", "POST"), ("/ws", "WS"),
        ("/a", "GET"), ("/b", "GET"), ("/nested", "POST"),
    }


def test_litestar_mock_patch_is_not_a_route(tmp_path: Path) -> None:
    """A test that mentions litestar but decorates with unittest.mock.patch."""
    _write(tmp_path, "tests/test_x.py", (
        "from unittest.mock import patch\n"
        "from litestar.exceptions import ClientException\n"
        "@patch('app.services.validate_password')\n"
        "def test_it(m): ...\n"
    ))
    assert _routes(tmp_path) == set()


def test_litestar_router_cycle_terminates(tmp_path: Path) -> None:
    _write(tmp_path, "app.py", (
        "from litestar import Router, get\n"
        "@get('/x')\n"
        "async def x(): ...\n"
        "a = Router('/a', route_handlers=[b, x])\n"
        "b = Router('/b', route_handlers=[a])\n"
    ))
    paths = _paths(tmp_path)
    assert any(p.endswith("/a/x") for p in paths)


# ---------- Tornado ----------


def test_tornado_urlspecs_with_handler_methods(tmp_path: Path) -> None:
    _write(tmp_path, "handlers.py", (
        "import tornado.web\n"
        "import tornado.websocket\n"
        "\n"
        "class BaseHandler(tornado.web.RequestHandler):\n"
        "    def get_current_user(self): ...\n"
        "\n"
        "class MainHandler(BaseHandler):\n"
        "    def get(self): ...\n"
        "\n"
        "class UserHandler(BaseHandler):\n"
        "    @tornado.web.authenticated\n"
        "    def get(self, user_id): ...\n"
        "    async def post(self, user_id): ...\n"
        "\n"
        "class ReadOnlyHandler(MainHandler):\n"
        "    pass\n"
        "\n"
        "class EchoSocket(tornado.websocket.WebSocketHandler):\n"
        "    def on_message(self, message): ...\n"
    ))
    _write(tmp_path, "app.py", (
        "import tornado.web\n"
        "from tornado.web import url\n"
        "from handlers import MainHandler, UserHandler, ReadOnlyHandler, EchoSocket\n"
        "\n"
        "def make_app():\n"
        "    return tornado.web.Application([\n"
        "        (r'/', MainHandler),\n"
        "        url(r'/users/([0-9]+)$', UserHandler, name='user'),\n"
        "        (r'/ro', ReadOnlyHandler),\n"
        "        (r'/ws', EchoSocket),\n"
        "        (r'/static/(.*)', tornado.web.StaticFileHandler, {'path': 'static'}),\n"
        "    ])\n"
    ))
    result = PythonAnalyzer().analyze(tmp_path)
    by = {(r.path, r.method): r for r in result.routes}
    assert set(by) == {
        ("/", "GET"), ("/users/([0-9]+)", "GET"), ("/users/([0-9]+)", "POST"),
        ("/ro", "GET"), ("/ws", "WS"), ("/static/(.*)", "ANY"),
    }
    assert by[("/users/([0-9]+)", "GET")].auth == "required"
    assert by[("/users/([0-9]+)", "POST")].auth == "unknown"
    assert by[("/", "GET")].file == "app.py"


def test_tornado_requires_import_and_handler_shaped_target(tmp_path: Path) -> None:
    _write(tmp_path, "not_tornado.py", "routes = [(r'/x', MainHandler)]\n")
    _write(tmp_path, "tornado_app.py", (
        "import tornado.web\n"
        "pairs = [('/config', settings_dict), ('name', MainHandler)]\n"
    ))
    assert _routes(tmp_path) == set()


# ---------- Sanic ----------


def test_sanic_route_methods_and_websocket(tmp_path: Path) -> None:
    _write(tmp_path, "app.py", (
        "from sanic import Sanic, Blueprint\n"
        "app = Sanic('demo')\n"
        "api = Blueprint('api')\n"
        "@app.route('/items', methods=['GET', 'POST'])\n"
        "async def items(request): ...\n"
        "@api.route('/default')\n"
        "async def default(request): ...\n"
        "@app.route('/tuple', methods=('PUT',))\n"
        "async def tup(request): ...\n"
        "@app.websocket('/feed')\n"
        "async def feed(request, ws): ...\n"
    ))
    assert _routes(tmp_path) == {
        ("/items", "GET"), ("/items", "POST"), ("/default", "GET"), ("/tuple", "PUT"), ("/feed", "WS"),
    }


def test_sanic_route_skips_without_sanic_import(tmp_path: Path) -> None:
    _write(tmp_path, "app.py", (
        "@app.websocket('/feed')\n"
        "async def feed(request, ws): ...\n"
    ))
    assert _routes(tmp_path) == set()


# ---------- shared parser robustness ----------


@pytest.mark.parametrize("seed", range(20))
def test_framework_parsers_survive_truncation(tmp_path: Path, seed: int) -> None:
    """Every prefix of the framework fixtures above must analyze cleanly."""
    source = (
        "from litestar import Controller, Router, get\nimport tornado.web\nfrom sanic import Sanic\n"
        "from aiohttp import web\nroutes = web.RouteTableDef()\n"
        "class C(Controller):\n    path = '/c'\n    @get('/x', guards=[g])\n    async def x(self): ...\n"
        "class H(tornado.web.RequestHandler):\n    def get(self): ...\n"
        "app = tornado.web.Application([(r'/h', H)])\nr = Router('/r', route_handlers=[C])\n"
        "@routes.get('/t')\nasync def t(request): ...\n"
    )
    rng = random.Random(seed)
    cut = rng.randrange(len(source) + 1)
    _write(tmp_path, "app.py", source[:cut])
    PythonAnalyzer().analyze(tmp_path)  # must not raise


# ---------- Django route auth (#256): wrappers in the URLconf ----------


def test_django_urlconf_auth_wrappers_set_route_auth(tmp_path: Path) -> None:
    _write(tmp_path, "urls.py", (
        "from django.contrib.auth.decorators import login_required, permission_required\n"
        "from django.contrib.auth.decorators import login_not_required\n"
        "from django.urls import include, path\n"
        "urlpatterns = [\n"
        "    path('me/', login_required(views.me)),\n"
        "    path('refund/', permission_required('billing.refund')(RefundView.as_view())),\n"
        "    path('cached/', cache_page(60)(login_required(views.cached))),\n"
        "    path('health/', login_not_required(views.health)),\n"
        "    path('open/', views.open_view),\n"
        "    path('api/', include([path('nested/', staff_member_required(views.n))])),\n"
        "]\n"
    ))
    by = {r.path: r for r in PythonAnalyzer().analyze(tmp_path).routes}
    assert by["/me/"].auth == "required" and by["/me/"].guards == ["login_required"]
    assert by["/refund/"].guards == ["permission_required"]
    assert by["/cached/"].auth == "required"
    assert by["/api/nested/"].guards == ["staff_member_required"]
    assert by["/health/"].auth == "anonymous" and by["/health/"].guards == []
    assert by["/open/"].auth == "unknown"
    assert "login_required(...) in urls.py:5" == by["/me/"].guard_evidence


def test_django_regex_fallback_skips_empty_include(tmp_path: Path) -> None:
    _write(tmp_path, "urls.py", (
        "from django.urls import include, path\n"
        "exec 'python 2'\n"
        "urlpatterns = [path('', include('other.urls')),\n"
        "    path('', home)]\n"
    ))
    # The "/" comes from the view on line 4, not the include on line 3.
    assert [(r.path, r.line) for r in PythonAnalyzer().analyze(tmp_path).routes] == [("/", 4)]


# ---------- review follow-ups (python#9) ----------


def test_django_self_concatenation_does_not_grow_exponentially(tmp_path: Path) -> None:
    lines = ["from django.urls import path", "urlpatterns = [path('a/', v), path('b/', v)]"]
    lines += ["urlpatterns = urlpatterns + urlpatterns"] * 40
    lines += ["urlpatterns += urlpatterns"] * 40
    lines += ["urlpatterns.extend(urlpatterns)"] * 40
    _write(tmp_path, "urls.py", "\n".join(lines) + "\n")
    start = time.monotonic()
    assert _paths(tmp_path) == {"/a/", "/b/"}
    assert time.monotonic() - start < 5


def test_django_list_and_file_entry_caps(tmp_path: Path) -> None:
    items = ", ".join(f"path('p{i}/', v)" for i in range(django_urls.MAX_LIST_ENTRIES + 500))
    _write(tmp_path, "urls.py", f"from django.urls import path\nurlpatterns = [{items}]\n")
    conf = django_urls.parse_urlconf(
        (tmp_path / "urls.py").read_text(), "urls.py", is_urlconf=True, drf=False
    )
    assert conf is not None and conf.truncated
    assert len(conf.lists["urlpatterns"]) == django_urls.MAX_LIST_ENTRIES


def test_django_router_mounts_are_budgeted_and_deduped(tmp_path: Path) -> None:
    regs = "\n".join(f"router.register('r{i}', V)" for i in range(3000))
    mounts = ", ".join(["router.urls"] * 3000)
    _write(tmp_path, "urls.py", (
        "from django.urls import include, path\n"
        "from rest_framework import routers\n"
        "router = routers.DefaultRouter()\n"
        f"{regs}\n"
        f"urlpatterns = [path('api/', include(router.urls)), {mounts}]\n"
        "urlpatterns += [path('api/', include(router.urls))]\n"
    ))
    start = time.monotonic()
    paths = _paths(tmp_path)
    assert time.monotonic() - start < 10
    assert "/api/r0" in paths and "/r2999" in paths
    assert len(paths) == 6000


def test_django_router_steps_count_against_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(django_urls, "MAX_STEPS", 50)
    conf = django_urls.UrlConf(rel="urls.py", is_urlconf=True, emit_unmounted_routers=True)
    conf.routers["router"] = [(f"r{i}", 1) for i in range(1000)]
    conf.lists["urlpatterns"] = [
        django_urls.Entry("mount", 1, segment="", target=django_urls.Target("attr", "router", "urls"))
    ]
    graph = django_urls.UrlGraph({"urls.py": conf}, [])
    routes = graph.expand()
    assert graph.truncated
    assert len([r for r in routes if r.path.startswith("/r")]) < 1000 + 60


def test_django_include_anchor_lookup_is_indexed(tmp_path: Path) -> None:
    """Many manage.py directories: each lookup walks the file's ancestors,
    not every project dir."""
    graph = django_urls.UrlGraph({}, [f"proj{i}" for i in range(20000)] + ["deep/site"])
    start = time.monotonic()
    for _ in range(2000):
        graph._module_rel("deep/site/app/urls.py", 0, "shop.urls")
    assert time.monotonic() - start < 2
    assert graph._absolute_anchors("deep/site/app/urls.py")[:2] == ["deep/site", ""]


def test_django_alternatives_and_wrappers_keep_routes(tmp_path: Path) -> None:
    _write(tmp_path, "urls.py", (
        "from django.conf import settings\n"
        "from django.urls import path\n"
        "if settings.FEATURE:\n"
        "    urlpatterns = [path('feature/', v)]\n"
        "else:\n"
        "    urlpatterns = [path('fallback/', v)]\n"
        "try:\n"
        "    from extras import x\n"
        "    urlpatterns = urlpatterns + [path('extra/', v)]\n"
        "except ImportError:\n"
        "    urlpatterns = urlpatterns + [path('no-extra/', v)]\n"
        "api = [path('api/me/', v)]\n"
        "urlpatterns = decorate_urlpatterns(urlpatterns, login_required)\n"
        "urlpatterns += decorate_urlpatterns(api, login_required)\n"
        "urlpatterns = [path('replaced/', v)]\n"
    ))
    assert _paths(tmp_path) == {
        "/feature/", "/fallback/", "/extra/", "/no-extra/", "/api/me/", "/replaced/",
    }


def test_sanic_enum_methods_and_slash_normalization(tmp_path: Path) -> None:
    _write(tmp_path, "app.py", (
        "from http import HTTPMethod\n"
        "from sanic import Sanic\n"
        "app = Sanic('x')\n"
        "@app.route('//a//b', methods=[HTTPMethod.DELETE, 'patch'])\n"
        "async def h(request): ...\n"
    ))
    assert _routes(tmp_path) == {("/a/b", "DELETE"), ("/a/b", "PATCH")}


def test_tornado_indirect_request_handler_subclass(tmp_path: Path) -> None:
    _write(tmp_path, "app.py", (
        "import tornado.web\n"
        "class BaseView(tornado.web.RequestHandler):\n"
        "    pass\n"
        "class Middle(BaseView):\n"
        "    pass\n"
        "class Api(Middle):\n"
        "    def post(self): ...\n"
        "class PlainHelper:\n"
        "    def get(self): ...\n"
        "app = tornado.web.Application([(r'/api', Api), (r'/x', PlainHelper)])\n"
    ))
    assert _routes(tmp_path) == {("/api", "POST")}


def test_litestar_conflicting_mount_auth_is_unknown(tmp_path: Path) -> None:
    _write(tmp_path, "app.py", (
        "from litestar import Controller, Litestar, Router, get\n"
        "class C(Controller):\n"
        "    path = '/c'\n"
        "    @get('/x')\n"
        "    async def x(self): ...\n"
        "guarded = Router('/', route_handlers=[C], guards=[admin_only])\n"
        "app = Litestar(route_handlers=[guarded, C])\n"
    ))
    routes = [r for r in PythonAnalyzer().analyze(tmp_path).routes if r.path == "/c/x"]
    assert len(routes) == 1 and routes[0].auth == "unknown" and routes[0].guards == []


def test_django_same_router_mount_is_walked_once(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(django_urls, "MAX_STEPS", 1500)
    conf = django_urls.UrlConf(rel="urls.py", is_urlconf=True, emit_unmounted_routers=True)
    conf.routers["router"] = [(f"r{i}", 1) for i in range(1000)]
    mount = django_urls.Entry("mount", 1, segment="", target=django_urls.Target("attr", "router", "urls"))
    conf.lists["urlpatterns"] = [mount] * 5
    graph = django_urls.UrlGraph({"urls.py": conf}, [])
    assert len(graph.expand()) == 1000
    assert not graph.truncated


def test_django_patterns_with_many_arguments_keep_prefix(tmp_path: Path) -> None:
    urls = ", ".join(f"url(r'^p{i}/$', v)" for i in range(40))
    _write(tmp_path, "urls.py", (
        "from django.conf.urls import patterns, include, url\n"
        "urlpatterns = patterns('', url(r'^tm/', include('tm_urls')))\n"
    ))
    _write(tmp_path, "tm_urls.py", f"from django.conf.urls import patterns, url\nurlpatterns = patterns('', {urls})\n")
    assert _paths(tmp_path) == {f"/tm/p{i}/" for i in range(40)}
