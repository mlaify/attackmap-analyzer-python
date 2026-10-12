"""Django URLconf include() graph (mlaify/attackmap-analyzer-python#2).

Django mounts one URLconf inside another with ``include()``; the child's
patterns only exist under the parent's prefix. This module reads every URLconf
(and every DRF router module) with :mod:`ast`, records what each module-level
pattern list contains, and then walks the include graph from the root
URLconfs so each leaf route carries its full prefix:

- ``path("api/", include("shop.api_urls"))`` — a dotted module path
- ``include(api_urls)`` / ``include(views.urlpatterns)`` — an imported module
- ``include(router.urls)`` / ``urlpatterns = router.urls`` — a DRF router
- ``include((patterns, "app"))`` — the ``(patterns, app_name)`` tuple form
- ``include([path(...), ...])`` and ``include(local_list)`` — inline lists
- ``re_path`` / legacy ``url`` regex segments (anchors are stripped on join)

A resolved ``include()`` line is a prefix, not an endpoint, so it is no
longer emitted as a route. An include that can't be resolved inside the repo
(``include("allauth.urls")``, ``include(get_model_urls(...))``) is still
emitted as its prefix so the mounted surface stays visible.

Within the bounds below, no route the regex extractor used to report is
lost:

- A pattern list is the *union* of everything assigned to it. Reassignments,
  if/else and try/except alternatives, and wrappers
  (``urlpatterns = decorate_urlpatterns(urlpatterns, ...)``) all add; nothing
  replaces. A route that every branch replaces is still reported, which trades
  a little precision for recall.
- A list, router or module that is never reached from a root URLconf is still
  emitted, unprefixed (the pre-#2 behaviour), so a dynamic mount the graph
  can't follow keeps its routes.

Everything is bounded: entries per list and per file, registrations per
router, include depth, mounts per list, steps (router registrations included)
and routes. Hitting a bound truncates instead of hanging. Nothing here touches
the filesystem: module references resolve only against the files the analyzer
already read.
"""

from __future__ import annotations

import ast
import posixpath
from dataclasses import dataclass, field

from ._pyast import call_name, dotted, safe_parse, str_const

# name → is the first argument a regex?
_URL_FUNCS = {"path": False, "re_path": True, "url": True}
# Calls that wrap a pattern list and return it (or a superset of it).
# `patterns("view.prefix", url(...), ...)` is the pre-1.10 form.
_PASSTHROUGH_FUNCS = {"i18n_patterns", "format_suffix_patterns", "patterns", "list", "tuple"}

# Auth wrappers applied to a view right in the URLconf (#256):
# `path("x/", login_required(views.x))`, `permission_required("p")(View.as_view())`.
# Django 5.1's `login_not_required` marks a view explicitly public.
_AUTH_WRAPPERS = {"login_required", "permission_required", "staff_member_required", "user_passes_test"}
_PUBLIC_WRAPPERS = {"login_not_required"}
_MAX_WRAP_DEPTH = 6

MAX_DEPTH = 12
# Per-file model bounds: entries in one pattern list, entries across a file's
# lists, and registrations on one router. A real URLconf is far below these.
MAX_LIST_ENTRIES = 5_000
MAX_FILE_ENTRIES = 20_000
MAX_ROUTER_REGISTRATIONS = 5_000
MAX_PREFIXES_PER_LIST = 64
MAX_STEPS = 200_000
MAX_ROUTES = 50_000
_MAX_EXPR_DEPTH = 64
_ORPHANS = "<orphans>"


@dataclass
class Target:
    """What an ``include()`` (or a bare list/attribute mount) points at."""

    kind: str  # "module" | "name" | "attr" | "inline" | "unknown"
    value: str = ""  # dotted module, local/imported name, or attribute base
    attr: str = ""  # for kind="attr": the attribute (`urls`, `urlpatterns`)
    entries: list["Entry"] = field(default_factory=list)  # kind="inline"


@dataclass
class Entry:
    kind: str  # "leaf" | "include" | "mount"
    line: int
    segment: str | None = None  # None: a non-literal route (e.g. settings.BASE_PATH)
    regex: bool = False
    target: Target | None = None
    auth: str = "unknown"
    guard: str | None = None


@dataclass
class UrlConf:
    rel: str
    is_urlconf: bool
    emit_unmounted_routers: bool
    lists: dict[str, list[Entry]] = field(default_factory=dict)
    # router variable → [(prefix, line)] from `router.register("prefix", ViewSet)`
    routers: dict[str, list[tuple[str, int]]] = field(default_factory=dict)
    # bound name → (relative-import level, module, imported attribute or "")
    imports: dict[str, tuple[int, str, str]] = field(default_factory=dict)
    truncated: bool = False  # a per-file cap was hit


@dataclass
class DjangoRoute:
    path: str
    file: str
    line: int
    auth: str = "unknown"
    guards: list[str] = field(default_factory=list)
    evidence: str | None = None
    method: str = "ANY"  # a URLconf doesn't say which verbs the view takes


# ---------- Parsing ----------


def parse_urlconf(content: str, rel: str, *, is_urlconf: bool, drf: bool) -> UrlConf | None:
    """Build the URLconf model for one file, or ``None`` when it can't be
    parsed (the caller then falls back to the regex extractor)."""
    tree = safe_parse(content)
    if tree is None:
        return None
    try:
        return _Builder(rel, is_urlconf=is_urlconf, drf=drf).build(tree)
    except RecursionError:
        return None


class _Builder:
    def __init__(self, rel: str, *, is_urlconf: bool, drf: bool):
        self.conf = UrlConf(rel=rel, is_urlconf=is_urlconf, emit_unmounted_routers=drf or is_urlconf)
        self.consumed: set[int] = set()
        self._list_ids: dict[str, set[int]] = {}
        self._total = 0

    def build(self, tree: ast.Module) -> UrlConf:
        for stmt in _module_statements(tree.body):
            self._statement(stmt)
        # path()/re_path()/url() calls the list model didn't account for (inside
        # a function, a comprehension, a dynamic container): keep emitting them
        # unprefixed, as the regex extractor always did.
        orphans: list[Entry] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and id(node) not in self.consumed and self._is_url_call(node):
                entry = self._url_entry(node, 0)
                # An empty route here (e.g. inside an AppConfig.get_urls()) sits at
                # a mount point we can't see; claiming "/" would be wrong.
                if entry is not None and entry.segment:
                    orphans.append(entry)
        if orphans and self.conf.is_urlconf:
            self._extend(_ORPHANS, orphans)
        return self.conf

    # -- statements --

    def _statement(self, stmt: ast.stmt) -> None:
        conf = self.conf
        if isinstance(stmt, ast.ImportFrom):
            for alias in stmt.names:
                if alias.name != "*":
                    conf.imports[alias.asname or alias.name] = (stmt.level or 0, stmt.module or "", alias.name)
        elif isinstance(stmt, ast.Import):
            for alias in stmt.names:
                if alias.asname:
                    conf.imports[alias.asname] = (0, alias.name, "")
                else:
                    head = alias.name.split(".")[0]
                    conf.imports[head] = (0, head, "")
        elif isinstance(stmt, (ast.Assign, ast.AnnAssign)):
            targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
            value = stmt.value
            if value is None:
                return
            for target in targets:
                if isinstance(target, ast.Name):
                    self._assign(target.id, value)
        elif isinstance(stmt, ast.AugAssign) and isinstance(stmt.op, ast.Add) and isinstance(stmt.target, ast.Name):
            name = stmt.target.id
            entries = self._entries(stmt.value, name, 0)
            if entries or name in conf.lists:
                self._extend(name, entries)
        elif isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
            self._call_statement(stmt.value)

    def _assign(self, name: str, value: ast.expr) -> None:
        conf = self.conf
        callee = call_name(value) if isinstance(value, ast.Call) else None
        if callee and callee.endswith("Router") and callee != "Router":
            conf.routers.setdefault(name, [])
            return
        entries = self._entries(value, name, 0)
        if entries or name == "urlpatterns" or (isinstance(value, (ast.List, ast.Tuple)) and not value.elts):
            # Union, never replace: a reassignment, an if/else or try/except
            # alternative, or `urlpatterns = wrap(urlpatterns)` keeps every
            # route any branch defines (precision trade-off: a route replaced
            # on every path is still reported).
            self._extend(name, entries)

    def _extend(self, name: str, entries: list[Entry]) -> None:
        """Add entries to a list once each, within the per-list/per-file caps."""
        target = self.conf.lists.setdefault(name, [])
        ids = self._list_ids.setdefault(name, set())
        for entry in entries:
            if id(entry) in ids:
                continue
            if len(target) >= MAX_LIST_ENTRIES or self._total >= MAX_FILE_ENTRIES:
                self.conf.truncated = True
                return
            ids.add(id(entry))
            target.append(entry)
            self._total += 1

    def _call_statement(self, call: ast.Call) -> None:
        func = call.func
        if not isinstance(func, ast.Attribute) or not isinstance(func.value, ast.Name):
            return
        owner, method = func.value.id, func.attr
        conf = self.conf
        if method == "register" and call.args:
            prefix = str_const(call.args[0])
            if prefix is None or len(call.args) + len(call.keywords) < 2:
                return
            # A locally built router, or one named like the conventional `router`.
            if owner in conf.routers or owner.lower().endswith("router"):
                regs = conf.routers.setdefault(owner, [])
                if len(regs) < MAX_ROUTER_REGISTRATIONS:
                    regs.append((prefix, call.lineno))
                else:
                    conf.truncated = True
            return
        if method in {"append", "extend", "insert"} and call.args:
            arg = call.args[-1]
            if method == "extend":
                entries = self._entries(arg, owner, 0)
            else:
                entries = self._entries(ast.List(elts=[arg], ctx=ast.Load()), owner, 0)
            if entries or owner in conf.lists:
                self._extend(owner, entries)

    # -- expressions --

    def _entries(self, node: ast.expr, self_name: str, depth: int) -> list[Entry]:
        """The URL entries an expression contributes to a pattern list."""
        if depth > _MAX_EXPR_DEPTH:
            return []
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            out: list[Entry] = []
            for elt in node.elts:
                if isinstance(elt, ast.Starred):
                    out.extend(self._entries(elt.value, self_name, depth + 1))
                elif isinstance(elt, ast.Call) and self._is_url_call(elt):
                    entry = self._url_entry(elt, depth + 1)
                    if entry is not None:
                        out.append(entry)
                else:
                    out.extend(self._entries(elt, self_name, depth + 1))
            return out
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return self._entries(node.left, self_name, depth + 1) + self._entries(node.right, self_name, depth + 1)
        if isinstance(node, ast.Name):
            if node.id == self_name:
                # `urlpatterns = format_suffix_patterns(urlpatterns)` / `x = x + x`:
                # the list already holds these (lists are unions), add nothing.
                return []
            return [Entry("mount", getattr(node, "lineno", 0), segment="", target=Target("name", node.id))]
        if isinstance(node, ast.Attribute) and node.attr in {"urls", "urlpatterns"}:
            base = dotted(node.value)
            if base:
                return [Entry("mount", node.lineno, segment="", target=Target("attr", base, node.attr))]
            return []
        if isinstance(node, ast.Call):
            if self._is_url_call(node):
                entry = self._url_entry(node, depth + 1)
                return [entry] if entry is not None else []
            # Known wrappers (`i18n_patterns`, `format_suffix_patterns`, ...) and
            # unknown ones (`decorate_urlpatterns(api, login_required)`) alike:
            # whatever pattern lists they're handed stay mounted. Non-pattern
            # arguments resolve to nothing.
            out = []
            for arg in node.args:
                inner = arg.value if isinstance(arg, ast.Starred) else arg
                out.extend(self._entries(inner, self_name, depth + 1))
            return out
        return []

    @staticmethod
    def _is_url_call(node: ast.Call) -> bool:
        func = node.func
        if isinstance(func, ast.Name):
            name = func.id
        elif isinstance(func, ast.Attribute) and not (isinstance(func.value, ast.Name) and func.value.id == "os"):
            name = func.attr
        else:
            return False
        return name in _URL_FUNCS and len(node.args) + len(node.keywords) >= 2

    def _url_entry(self, call: ast.Call, depth: int) -> Entry | None:
        self.consumed.add(id(call))
        regex = _URL_FUNCS[call_name(call) or "path"]
        route = call.args[0] if call.args else _kw(call, "route", "regex")
        view = call.args[1] if len(call.args) > 1 else _kw(call, "view")
        if route is None or view is None:
            return None
        segment = str_const(route)
        if isinstance(view, ast.Call) and call_name(view) == "include":
            self.consumed.add(id(view))
            target_node = view.args[0] if view.args else _kw(view, "arg")
            target = self._include_target(target_node, depth + 1) if target_node is not None else Target("unknown")
            return Entry("include", call.lineno, segment=segment, regex=regex, target=target)
        auth, guard = _wrapper_auth(view)
        return Entry("leaf", call.lineno, segment=segment, regex=regex, auth=auth, guard=guard)

    def _include_target(self, node: ast.expr, depth: int) -> Target:
        if depth > _MAX_EXPR_DEPTH:
            return Target("unknown")
        module = str_const(node)
        if module is not None:
            return Target("module", module)
        if isinstance(node, ast.Tuple) and 2 <= len(node.elts) <= 3 and str_const(node.elts[1]) is not None:
            # include((patterns, "app_name")) / include(("mod.urls", "app"), namespace=...)
            return self._include_target(node.elts[0], depth + 1)
        if isinstance(node, (ast.List, ast.Tuple)):
            return Target("inline", entries=self._entries(node, "", depth + 1))
        if isinstance(node, ast.Name):
            return Target("name", node.id)
        if isinstance(node, ast.Attribute):
            base = dotted(node.value)
            if base:
                return Target("attr", base, node.attr)
        if isinstance(node, ast.Call) and call_name(node) in _PASSTHROUGH_FUNCS:
            return Target("inline", entries=self._entries(node, "", depth + 1))
        return Target("unknown")


def _wrapper_auth(view: ast.expr) -> tuple[str, str | None]:
    """`login_required(v)` / `permission_required("p")(v)` / nested wrappers
    around the view in the URLconf → ("required" | "anonymous", wrapper)."""
    node = view
    for _ in range(_MAX_WRAP_DEPTH):
        if not isinstance(node, ast.Call):
            break
        func = node.func
        # `permission_required("p")(view)`: the decorator factory is func.func.
        name = call_name(func.func) if isinstance(func, ast.Call) else call_name(func)
        if name in _AUTH_WRAPPERS:
            return "required", name
        if name in _PUBLIC_WRAPPERS:
            return "anonymous", name
        if not node.args:
            break
        node = node.args[0]
    return "unknown", None


def _kw(call: ast.Call, *names: str) -> ast.expr | None:
    for kw in call.keywords:
        if kw.arg in names:
            return kw.value
    return None


def _module_statements(body: list[ast.stmt], depth: int = 0):
    """Module-level statements, descending into `if settings.DEBUG:` /
    `try:` / `with` / `for` blocks but not into functions or classes."""
    if depth > 16:
        return
    for stmt in body:
        yield stmt
        if isinstance(stmt, (ast.If, ast.For, ast.While)):
            yield from _module_statements(stmt.body, depth + 1)
            yield from _module_statements(stmt.orelse, depth + 1)
        elif isinstance(stmt, ast.With):
            yield from _module_statements(stmt.body, depth + 1)
        elif isinstance(stmt, ast.Try) or type(stmt).__name__ == "TryStar":
            yield from _module_statements(stmt.body, depth + 1)
            for handler in stmt.handlers:
                yield from _module_statements(handler.body, depth + 1)
            yield from _module_statements(stmt.orelse, depth + 1)
            yield from _module_statements(stmt.finalbody, depth + 1)


# ---------- Path joining ----------


def _strip_anchors(segment: str) -> str:
    if segment.startswith("\\A"):
        segment = segment[2:]
    segment = segment.lstrip("^")
    if segment.endswith("\\Z"):
        segment = segment[:-2]
    while segment.endswith("$") and not segment.endswith("\\$"):
        segment = segment[:-1]
    return segment


def join_segments(segments: list[tuple[str, bool]]) -> str:
    """Concatenate URLconf segments the way Django does (no separator added),
    stripping regex anchors, and return a single-leading-slash path."""
    joined = "".join(_strip_anchors(text) if regex else text for text, regex in segments)
    path = "/" + joined.lstrip("/")
    while "//" in path:
        path = path.replace("//", "/")
    return path


# ---------- Graph ----------


class UrlGraph:
    def __init__(self, confs: dict[str, UrlConf], project_dirs: list[str]):
        self.confs = confs
        # Directories holding manage.py: Django's sys.path roots, tried first
        # when resolving an absolute dotted module.
        self._project_dirs = set(project_dirs)
        self._anchor_cache: dict[str, list[str]] = {}
        self.routes: list[DjangoRoute] = []
        self._seen: set[tuple[str, str, int]] = set()
        self._expanded: set[tuple[str, str]] = set()
        self._prefix_count: dict[tuple[str, str], int] = {}
        self._mounted_routers: set[tuple[str, str]] = set()
        self._router_mounts: set[tuple[str, str, str]] = set()
        self._steps = 0
        self.truncated = False

    # -- resolution --

    def _module_rel(self, from_rel: str, level: int, module: str) -> str | None:
        parts = [p for p in module.split(".") if p]
        if level:
            base = posixpath.dirname(from_rel)
            for _ in range(level - 1):
                base = posixpath.dirname(base)
            anchors = [base]
        else:
            if not parts:
                return None
            anchors = self._absolute_anchors(from_rel)
        for anchor in anchors:
            stem = posixpath.join(anchor, *parts) if parts else anchor
            if not stem:
                continue
            for cand in (stem + ".py", posixpath.join(stem, "__init__.py")):
                if cand in self.confs:
                    return cand
        return None

    def _absolute_anchors(self, from_rel: str) -> list[str]:
        """manage.py directories above the file (deepest first), the repo
        root, then the file's ancestors. Indexed, cached per directory."""
        directory = posixpath.dirname(from_rel)
        cached = self._anchor_cache.get(directory)
        if cached is not None:
            return cached
        ancestors: list[str] = []
        d = directory
        while d:
            ancestors.append(d)
            d = posixpath.dirname(d)
        project = [a for a in ancestors if a in self._project_dirs]
        if "" in self._project_dirs:
            project.append("")
        anchors = list(dict.fromkeys(project + [""] + ancestors))
        self._anchor_cache[directory] = anchors
        return anchors

    def _import_module(self, conf: UrlConf, name: str) -> tuple[str | None, str]:
        """For a bound name: (module file it names or comes from, imported attr)."""
        level, module, attr = conf.imports[name]
        if attr:
            sub = f"{module}.{attr}" if module else attr
            rel = self._module_rel(conf.rel, level, sub)
            if rel is not None:
                return rel, ""  # `from pkg import api_urls` binds a module
        return self._module_rel(conf.rel, level, module), attr

    def _resolve(self, conf: UrlConf, target: Target | None):
        """→ ("list", conf, name) | ("router", conf, name) | ("inline", conf, entries) | None"""
        if target is None:
            return None
        kind = target.kind
        if kind == "inline":
            return ("inline", conf, target.entries)
        if kind == "module":
            rel = self._module_rel(conf.rel, 0, target.value)
            return self._urlpatterns_of(rel)
        if kind == "name":
            name = target.value
            if name in conf.lists:
                return ("list", conf, name)
            if name in conf.imports:
                rel, attr = self._import_module(conf, name)
                if rel is None:
                    return None
                if not attr:
                    return self._urlpatterns_of(rel)
                other = self.confs[rel]
                if attr in other.lists:
                    return ("list", other, attr)
                if attr in other.routers:
                    return None  # include(router) without .urls isn't valid Django
            return None
        if kind == "attr":
            base, attr = target.value, target.attr
            if "." in base:
                return None
            if attr == "urls" and base in conf.routers:
                return ("router", conf, base)
            if base in conf.imports:
                rel, imported = self._import_module(conf, base)
                if rel is None:
                    return None
                other = self.confs[rel]
                if not imported:
                    # `from . import api` + include(api.urlpatterns)
                    return self._urlpatterns_of(rel) if attr == "urlpatterns" else None
                if attr == "urls" and imported in other.routers:
                    return ("router", other, imported)
                if attr == "urlpatterns" and imported in other.lists:
                    return ("list", other, imported)
            return None
        return None

    def _urlpatterns_of(self, rel: str | None):
        if rel is None:
            return None
        conf = self.confs[rel]
        if conf.is_urlconf and "urlpatterns" in conf.lists:
            return ("list", conf, "urlpatterns")
        return None

    # -- expansion --

    def _emit(self, path: str, file: str, line: int, entry: Entry | None = None) -> None:
        if len(self.routes) >= MAX_ROUTES:
            self.truncated = True
            return
        key = (path, file, line)
        if key in self._seen:
            return
        self._seen.add(key)
        route = DjangoRoute(path, file, line)
        if entry is not None and entry.guard:
            route.auth = entry.auth
            route.guards = [entry.guard] if entry.auth == "required" else []
            route.evidence = f"{entry.guard}(...) in {file}:{line}"
        self.routes.append(route)

    def _expand_list(self, conf: UrlConf, name: str, prefix: list[tuple[str, bool]], depth: int, stack: frozenset) -> None:
        key = (conf.rel, name)
        if key in stack or depth > MAX_DEPTH:
            return
        count = self._prefix_count.get(key, 0)
        if count >= MAX_PREFIXES_PER_LIST:
            self.truncated = True
            return
        self._prefix_count[key] = count + 1
        self._expanded.add(key)
        stack = stack | {key}
        for entry in conf.lists.get(name, []):
            self._expand_entry(conf, entry, prefix, depth, stack)

    def _expand_entry(self, conf: UrlConf, entry: Entry, prefix: list[tuple[str, bool]], depth: int, stack: frozenset) -> None:
        self._steps += 1
        if self._steps > MAX_STEPS or len(self.routes) >= MAX_ROUTES:
            self.truncated = True
            return
        if entry.kind == "leaf":
            if entry.segment is not None:
                self._emit(join_segments(prefix + [(entry.segment, entry.regex)]), conf.rel, entry.line, entry)
            return
        resolved = self._resolve(conf, entry.target)
        if entry.kind == "mount":
            if resolved is not None:
                self._expand_resolved(resolved, prefix, depth + 1, stack)
            return
        # include(): a dynamic route (`settings.BASE_PATH`) joins as "".
        child_prefix = prefix + [(entry.segment or "", entry.regex)]
        if resolved is not None:
            self._expand_resolved(resolved, child_prefix, depth + 1, stack)
        elif entry.segment is not None:
            path = join_segments(child_prefix)
            if path != "/":
                self._emit(path, conf.rel, entry.line)

    def _expand_resolved(self, resolved, prefix: list[tuple[str, bool]], depth: int, stack: frozenset) -> None:
        kind, conf, ref = resolved
        if depth > MAX_DEPTH:
            self.truncated = True
            return
        if kind == "list":
            self._expand_list(conf, ref, prefix, depth, stack)
        elif kind == "inline":
            for entry in ref:
                self._expand_entry(conf, entry, prefix, depth, stack)
        elif kind == "router":
            self._mounted_routers.add((conf.rel, ref))
            mount = (conf.rel, ref, join_segments(prefix))
            if mount in self._router_mounts:
                return  # the same router mounted at the same prefix again
            self._router_mounts.add(mount)
            for segment, line in conf.routers.get(ref, []):
                self._steps += 1
                if self._steps > MAX_STEPS or len(self.routes) >= MAX_ROUTES:
                    self.truncated = True
                    return
                self._emit(join_segments(prefix + [(segment, False)]), conf.rel, line)

    def _references(self) -> set[tuple[str, str]]:
        """Every (file, list) some include/mount resolves to."""
        refs: set[tuple[str, str]] = set()
        budget = MAX_STEPS
        for conf in self.confs.values():
            stack = [e for entries in conf.lists.values() for e in entries]
            while stack and budget > 0:
                budget -= 1
                entry = stack.pop()
                resolved = self._resolve(conf, entry.target)
                if resolved is None:
                    continue
                kind, other, ref = resolved
                if kind == "list" and other is not conf:
                    refs.add((other.rel, ref))
                elif kind == "list" and ref != "urlpatterns":
                    refs.add((other.rel, ref))
                elif kind == "inline":
                    stack.extend(ref)
        return refs

    def expand(self) -> list[DjangoRoute]:
        refs = self._references()
        ordered = sorted(self.confs.values(), key=lambda c: c.rel)

        def list_order(conf: UrlConf) -> list[str]:
            names = sorted(conf.lists, key=lambda n: (n != "urlpatterns", n == _ORPHANS, n))
            return names

        # 1. Root URLconfs: urlpatterns no other URLconf includes.
        for conf in ordered:
            if conf.is_urlconf and "urlpatterns" in conf.lists and (conf.rel, "urlpatterns") not in refs:
                self._expand_list(conf, "urlpatterns", [], 0, frozenset())
        # 2. Anything not reached yet: unreferenced lists first (they may mount
        #    the rest under a prefix), then the remainder (include cycles).
        for want_referenced in (False, True):
            for conf in ordered:
                for name in list_order(conf):
                    key = (conf.rel, name)
                    if key in self._expanded or ((key in refs) != want_referenced):
                        continue
                    self._expand_list(conf, name, [], 0, frozenset())
        # 3. Routers nobody mounted keep the pre-#2 unprefixed emission.
        for conf in ordered:
            if not conf.emit_unmounted_routers:
                continue
            for name in sorted(conf.routers):
                if (conf.rel, name) in self._mounted_routers:
                    continue
                for segment, line in conf.routers[name]:
                    self._emit(join_segments([(segment, False)]), conf.rel, line)
        return self.routes


__all__ = ["DjangoRoute", "UrlConf", "UrlGraph", "join_segments", "parse_urlconf"]
