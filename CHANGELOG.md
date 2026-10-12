# Changelog

All notable changes to `attackmap-analyzer-python` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Django `include()` graph ([#2](https://github.com/mlaify/attackmap-analyzer-python/issues/2)):
  URLconfs and DRF router modules are read with `ast` and the include tree is
  walked from the root URLconfs, so child routes carry their full prefix
  (`include("mod.urls")`, `include(module)`, `include((patterns, "app"))`,
  inline/local pattern lists, `re_path`/`url`, `patterns()`, `i18n_patterns`,
  `urlpatterns = router.urls`, `include(router.urls)` with the router imported
  from another module). Bounded (depth, mounts per list, steps, routes); cycles
  stop.
- aiohttp `web.RouteTableDef()` decorators (`@routes.get/post/.../view`,
  `@routes.route("PATCH", ...)`), `add_route("POST"|"*", ...)` and
  `add_view`/`web.view` (#2).
- Litestar controllers and routers (#2): handler decorators at any indentation,
  path-less `@post()` (→ `/`), `path=` / list paths, `@route(http_method=...)`,
  `@websocket`; `Controller.path` and `Router(path=..., route_handlers=[...])`
  prefixes joined, nested routers across files. Route auth (mlaify/AttackMap#256):
  `guards=[...]` on the handler, controller or router → `required`;
  `exclude_from_auth=True` → `anonymous`.
- Tornado (#2): `Application([...])` / `url(...)` URL specs paired with the
  handler class's verb methods (inherited through `*Handler` bases; a
  `WebSocketHandler` is `WS`, no verbs is `ANY`). `@tornado.web.authenticated`
  on a method → route auth `required`.
- Sanic `@app.route("/x", methods=[...])` (default `GET`, matching core) and
  `@app.websocket("/x")` (#2).
- Django route auth (mlaify/AttackMap#256) from wrappers applied in the URLconf:
  `login_required(view)`, `permission_required("p")(view)`,
  `staff_member_required`, `user_passes_test` → `required`;
  `login_not_required(view)` → `anonymous`.

### Changed

- Django `re_path`/`url` routes have their regex anchors stripped and a leading
  `/` (`^api/users/$` → `/api/users/`), so regex and `path()` segments join the
  same way (#2).
- A resolved `include()` line is no longer emitted as a route; an include that
  can't be resolved in the repo is still emitted as its prefix (#2).
- Django URLconfs are parsed with `ast`, so commented-out `path(...)` lines and
  docstring examples are no longer routes. A file `ast` can't parse (Python 2,
  over 1 MB) keeps the regex extraction.
- A file that mentions litestar but imports no handler decorator from it no
  longer yields routes (a `@patch("pkg.mod")` from `unittest.mock` was reported
  as a `PATCH` route).
- Walk and read the repo with the shared `attackmap.sdk.fs` helpers
  (`iter_repo_files`, `read_source`, `rel`, `line_of`) instead of a private
  `rglob` + `SKIP_DIRS` walk ([mlaify/AttackMap#253](https://github.com/mlaify/AttackMap/issues/253)).
  Skip dirs are now `DEFAULT_SKIP_DIRS` plus `env`, `.ruff_cache` and `site-packages`.
- `priority` 15 → 10, so the plugin genuinely runs before the built-in
  `python-web` analyzer (20) now that core orders analyzers by `(priority, name)`
  ([mlaify/AttackMap#221](https://github.com/mlaify/AttackMap/issues/221)).

### Fixed

- Django `path("", view)` (the site root) is now emitted as `/`; the pattern
  required a non-empty route (#2).
- Django `include()` children are emitted under their parent prefix instead of
  bare, and the include line is no longer reported as an endpoint (#2).
- A repo checked out under a directory named like a skip dir (e.g. `/build/...`,
  `.../out/...`, `.../env/...`) was silently skipped entirely; skip dirs are now
  matched only inside the repo.
- Symlinked files pointing outside the repo are no longer analyzed.
- An unreadable file no longer raises out of `analyze()`, and cp1252/latin-1
  sources are analyzed instead of dropped. `files_scanned` counts only files
  that were actually read.
- `detect()` stops at the first `.py` file and prunes skipped directories
  instead of walking all of them.

## [0.1.0] - 2026-06-04

### Added

- Initial public release. Comprehensive Python ecosystem analyzer plugin for AttackMap (Django, Starlette, AIOHTTP, Sanic, Litestar, DRF; SQLAlchemy/asyncpg/motor; passlib/PyJWT/authlib; httpx/aiohttp).
- Registered under the `attackmap.analyzers` entry-point group so the core
  AttackMap CLI auto-discovers this analyzer once installed.
- Emits Signal-v2 records (`file:line` citation, evidence text, and confidence
  score) for every signal.

[Unreleased]: https://github.com/mlaify/attackmap-analyzer-python/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/mlaify/attackmap-analyzer-python/releases/tag/v0.1.0
