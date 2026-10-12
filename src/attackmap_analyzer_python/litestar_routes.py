"""Litestar / Starlite route handlers, controllers and routers (#2).

- ``@get("/x")`` / ``@post()`` (no path → ``/``) / ``@get(path=["/a", "/b"])``
  / ``@route("/x", http_method=["GET", "POST"])`` / ``@websocket("/ws")``,
  at any indentation — module level, inside a ``Controller``, or inside a
  factory function.
- ``class UserController(Controller): path = "/users"`` joins the controller
  path onto each handler path.
- ``Router(path="/api", route_handlers=[UserController, health])`` joins the
  router path onto what it lists; nested routers chain.
- Route auth (#256): ``guards=[...]`` on the handler, controller or router →
  ``required``; ``exclude_from_auth=True`` (or ``opt={"exclude_from_auth":
  True}``) with no guard → ``anonymous``. Anything else stays ``unknown``.

Decorators only count when their name is imported from ``litestar``/``starlite``
(so a project's own ``get`` decorator never fires).
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field

from ._pyast import call_name, dotted, expr_names, keyword, safe_parse, str_const, str_list

_HANDLER_KINDS = {
    "get": ["GET"],
    "post": ["POST"],
    "put": ["PUT"],
    "patch": ["PATCH"],
    "delete": ["DELETE"],
    "head": ["HEAD"],
    "route": None,  # methods come from http_method=
    "websocket": ["WS"],
    "websocket_listener": ["WS"],
}
_LITESTAR_MODULES = ("litestar", "starlite")
_MAX_NEST = 32
_MAX_ROUTER_DEPTH = 8
_MAX_PREFIXES = 32


@dataclass
class Handler:
    file: str
    line: int
    name: str
    paths: list[str]
    methods: list[str]
    module_level: bool
    guards: list[str] = field(default_factory=list)
    excluded: bool = False


@dataclass
class Controller:
    file: str
    name: str
    path: str
    guards: list[str]
    handlers: list[Handler] = field(default_factory=list)


@dataclass
class Router:
    file: str
    var: str | None
    path: str
    members: list[str]
    guards: list[str]


@dataclass
class LitestarFile:
    rel: str
    handlers: list[Handler] = field(default_factory=list)  # not inside a controller
    controllers: list[Controller] = field(default_factory=list)
    routers: list[Router] = field(default_factory=list)


@dataclass
class LitestarRoute:
    path: str
    method: str
    file: str
    line: int
    auth: str = "unknown"
    guards: list[str] = field(default_factory=list)
    evidence: str | None = None


def _is_litestar_module(module: str | None) -> bool:
    return bool(module) and module.split(".")[0] in _LITESTAR_MODULES


def parse_litestar(content: str, rel: str) -> LitestarFile | None:
    """The file's handlers/controllers/routers; ``None`` only when it can't be
    parsed (the caller then falls back to the decorator regex)."""
    tree = safe_parse(content)
    if tree is None:
        return None
    aliases: dict[str, str] = {}
    module_aliases: set[str] = set()
    router_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and _is_litestar_module(node.module):
            for alias in node.names:
                bound = alias.asname or alias.name
                if alias.name in _HANDLER_KINDS:
                    aliases[bound] = alias.name
                elif alias.name in {"Router", "Litestar", "Starlite"}:
                    router_names.add(bound)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if _is_litestar_module(alias.name):
                    module_aliases.add(alias.asname or alias.name.split(".")[0])
    out = LitestarFile(rel=rel)
    if not aliases and not module_aliases and not router_names:
        # Mentions litestar but imports no handler decorator from it — e.g. a
        # test using `unittest.mock.patch("...")`, which is not a route.
        return out
    try:
        _visit(tree.body, None, True, out, aliases, module_aliases, 0)
        _collect_routers(tree, out, router_names, module_aliases)
    except RecursionError:
        return None
    return out


def _decorator_kind(dec: ast.expr, aliases: dict[str, str], module_aliases: set[str]) -> str | None:
    if not isinstance(dec, ast.Call):
        return None
    func = dec.func
    if isinstance(func, ast.Name):
        return aliases.get(func.id)
    if isinstance(func, ast.Attribute) and func.attr in _HANDLER_KINDS:
        base = dotted(func.value)
        if base and base.split(".")[0] in module_aliases:
            return func.attr
    return None


def _handler_from(fn: ast.FunctionDef | ast.AsyncFunctionDef, dec: ast.Call, kind: str, rel: str, module_level: bool) -> Handler | None:
    path_node = dec.args[0] if dec.args else keyword(dec, "path")
    if path_node is None:
        paths = ["/"]
    else:
        single = str_const(path_node)
        paths = [single] if single is not None else (str_list(path_node) or [])
    if not paths:
        return None  # a computed path: nothing reliable to report
    methods = _HANDLER_KINDS[kind]
    if methods is None:
        methods = _http_methods(keyword(dec, "http_method")) or ["ANY"]
    guards = expr_names(keyword(dec, "guards"))
    return Handler(
        file=rel,
        line=dec.lineno,
        name=fn.name,
        paths=paths,
        methods=list(methods),
        module_level=module_level,
        guards=guards,
        excluded=_excluded_from_auth(dec),
    )


def _http_methods(node: ast.expr | None) -> list[str]:
    if node is None:
        return []
    elts = node.elts if isinstance(node, (ast.List, ast.Tuple, ast.Set)) else [node]
    out: list[str] = []
    for elt in elts[:16]:
        value = str_const(elt)
        if value is None and isinstance(elt, ast.Attribute):
            value = elt.attr  # HttpMethod.GET
        if value and value.isalpha():
            out.append(value.upper())
    return out


def _excluded_from_auth(dec: ast.Call) -> bool:
    flag = keyword(dec, "exclude_from_auth")
    if isinstance(flag, ast.Constant) and flag.value is True:
        return True
    opt = keyword(dec, "opt")
    if isinstance(opt, ast.Dict):
        for key, value in zip(opt.keys, opt.values):
            if str_const(key) == "exclude_from_auth" and isinstance(value, ast.Constant) and value.value is True:
                return True
    return False


def _visit(body, controller: Controller | None, module_level: bool, out: LitestarFile, aliases, module_aliases, depth: int) -> None:
    if depth > _MAX_NEST:
        return
    for stmt in body:
        if isinstance(stmt, ast.ClassDef):
            ctrl = None
            if any((dotted(base) or "").endswith("Controller") for base in stmt.bases):
                ctrl = Controller(file=out.rel, name=stmt.name, path="", guards=[])
                for item in stmt.body:
                    if isinstance(item, (ast.Assign, ast.AnnAssign)):
                        targets = item.targets if isinstance(item, ast.Assign) else [item.target]
                        for target in targets:
                            if isinstance(target, ast.Name) and target.id == "path":
                                ctrl.path = str_const(item.value) or ""
                            elif isinstance(target, ast.Name) and target.id == "guards":
                                ctrl.guards = expr_names(item.value)
                out.controllers.append(ctrl)
            _visit(stmt.body, ctrl, False, out, aliases, module_aliases, depth + 1)
        elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for dec in stmt.decorator_list:
                kind = _decorator_kind(dec, aliases, module_aliases)
                if kind is None:
                    continue
                handler = _handler_from(stmt, dec, kind, out.rel, module_level)
                if handler is None:
                    continue
                if controller is not None:
                    controller.handlers.append(handler)
                else:
                    out.handlers.append(handler)
            _visit(stmt.body, None, False, out, aliases, module_aliases, depth + 1)
        elif isinstance(stmt, (ast.If, ast.With, ast.Try, ast.For, ast.While)) or type(stmt).__name__ == "TryStar":
            for block in ("body", "orelse", "finalbody"):
                _visit(getattr(stmt, block, []) or [], controller, module_level, out, aliases, module_aliases, depth + 1)
            for handler in getattr(stmt, "handlers", []) or []:
                _visit(handler.body, controller, module_level, out, aliases, module_aliases, depth + 1)


def _collect_routers(tree: ast.Module, out: LitestarFile, router_names: set[str], module_aliases: set[str]) -> None:
    assigned: dict[int, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    assigned[id(node.value)] = target.id
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name) and func.id in router_names:
            pass
        elif isinstance(func, ast.Attribute) and func.attr in {"Router", "Litestar", "Starlite"} and (dotted(func.value) or "").split(".")[0] in module_aliases:
            pass
        else:
            continue
        is_app = call_name(node) in {"Litestar", "Starlite"}
        path_node = None if is_app else (node.args[0] if node.args else keyword(node, "path"))
        path = str_const(path_node) or "" if path_node is not None else ""
        members_node = keyword(node, "route_handlers")
        if members_node is None and not is_app and len(node.args) > 1:
            members_node = node.args[1]
        if members_node is None and is_app and node.args:
            members_node = node.args[0]
        members = [name.split(".")[-1] for name in expr_names(members_node, limit=256)]
        out.routers.append(
            Router(file=out.rel, var=assigned.get(id(node)), path=path, members=members, guards=expr_names(keyword(node, "guards")))
        )


def _join(*parts: str) -> str:
    pieces = [p.strip("/") for p in parts if p and p.strip("/")]
    return "/" + "/".join(pieces) if pieces else "/"


def resolve_litestar(files: list[LitestarFile]) -> list[LitestarRoute]:
    """Join router and controller paths onto every handler, repo-wide."""
    routers = [r for f in files for r in f.routers]
    # member name → routers that list it
    listed_by: dict[str, list[Router]] = {}
    for router in routers:
        for member in router.members:
            listed_by.setdefault(member, []).append(router)
    defined: dict[str, set[str]] = {}
    for f in files:
        for ctrl in f.controllers:
            defined.setdefault(ctrl.name, set()).add(f.rel)
        for handler in f.handlers:
            defined.setdefault(handler.name, set()).add(f.rel)
        for router in f.routers:
            if router.var:
                defined.setdefault(router.var, set()).add(f.rel)

    def owners(name: str, file: str) -> list[Router]:
        # A router listing `name` counts when it's in the same file or the name
        # is defined exactly once in the repo (an unambiguous import).
        unique = len(defined.get(name, ())) == 1
        return [r for r in listed_by.get(name, []) if r.file == file or unique]

    memo: dict[tuple[str, str], list[tuple[str, list[str]]]] = {}

    def mounts(name: str, file: str, stack: frozenset = frozenset()) -> list[tuple[str, list[str]]]:
        """(prefix, inherited guards) for each way `name` is mounted. Memoized;
        a router cycle or a chain deeper than _MAX_ROUTER_DEPTH stops there."""
        key = (name, file)
        if key in memo:
            return memo[key]
        if key in stack or len(stack) >= _MAX_ROUTER_DEPTH:
            return [("", [])]
        result: list[tuple[str, list[str]]] = []
        for router in owners(name, file):
            parents = mounts(router.var, router.file, stack | {key}) if router.var else [("", [])]
            for parent_prefix, parent_guards in parents:
                result.append((_join(parent_prefix, router.path), parent_guards + router.guards))
                if len(result) >= _MAX_PREFIXES:
                    break
            if len(result) >= _MAX_PREFIXES:
                break
        memo[key] = result = result or [("", [])]
        return result

    routes: list[LitestarRoute] = []

    def emit(handler: Handler, prefix: str, ctrl_path: str, inherited: list[str]) -> None:
        guards = inherited + handler.guards
        if guards:
            auth, evidence = "required", f"guards=[{', '.join(guards)}]"
        elif handler.excluded:
            auth, evidence = "anonymous", "exclude_from_auth=True"
        else:
            auth, evidence = "unknown", None
        for hpath in handler.paths:
            for method in handler.methods:
                routes.append(
                    LitestarRoute(
                        path=_join(prefix, ctrl_path, hpath),
                        method=method,
                        file=handler.file,
                        line=handler.line,
                        auth=auth,
                        guards=list(guards),
                        evidence=evidence,
                    )
                )

    for f in files:
        for ctrl in f.controllers:
            for prefix, inherited in mounts(ctrl.name, f.rel):
                for handler in ctrl.handlers:
                    emit(handler, prefix, ctrl.path, inherited + ctrl.guards)
        for handler in f.handlers:
            for prefix, inherited in (mounts(handler.name, f.rel) if handler.module_level else [("", [])]):
                emit(handler, prefix, "", inherited)
    # One handler mounted twice at the same path with different auth (a
    # guarded and an unguarded router) collapses to one route downstream, so
    # its auth isn't known.
    auth_by_key: dict[tuple[str, str, str], set[str]] = {}
    for route in routes:
        auth_by_key.setdefault((route.path, route.method, route.file), set()).add(route.auth)
    for route in routes:
        if len(auth_by_key[(route.path, route.method, route.file)]) > 1:
            route.auth, route.guards, route.evidence = "unknown", [], None
    return routes


__all__ = ["LitestarFile", "LitestarRoute", "parse_litestar", "resolve_litestar"]
