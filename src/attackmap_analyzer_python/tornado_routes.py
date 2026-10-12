"""Tornado URLSpec routing paired with RequestHandler methods (#2).

``tornado.web.Application([(r"/users/(\\d+)", UserHandler), url(r"/x", X)])``
(or a ``handlers = [...]`` list handed to it, or ``add_handlers``) maps a
regex to a handler class; the HTTP methods are the ``get``/``post``/... the
class defines. A ``WebSocketHandler`` subclass is a ``WS`` route. A handler
that defines no verb itself (inherits them) is ``ANY``.

A URL spec counts only when it sits in a list/tuple literal, its pattern
starts with ``/``, and its handler is a known ``*Handler`` class (anywhere in
the repo) or at least named like one. Route auth (#256): a verb method
decorated with ``@tornado.web.authenticated`` is ``required``.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field

from ._pyast import call_name, dotted, safe_parse, str_const

_VERBS = ("get", "post", "put", "patch", "delete", "head", "options")
_MAX_INHERIT = 3
_MAX_SPECS = 5_000


@dataclass
class HandlerClass:
    file: str
    name: str
    bases: list[str]
    methods: dict[str, bool] = field(default_factory=dict)  # VERB → @authenticated
    websocket: bool = False
    direct: bool = False  # a base is named *Handler


@dataclass
class UrlSpec:
    file: str
    line: int
    pattern: str
    handler: str  # last dotted component of the handler expression


@dataclass
class TornadoFile:
    rel: str
    classes: list[HandlerClass] = field(default_factory=list)
    specs: list[UrlSpec] = field(default_factory=list)


@dataclass
class TornadoRoute:
    path: str
    method: str
    file: str
    line: int
    auth: str = "unknown"
    guards: list[str] = field(default_factory=list)
    evidence: str | None = None


def parse_tornado(content: str, rel: str) -> TornadoFile | None:
    tree = safe_parse(content)
    if tree is None:
        return None
    out = TornadoFile(rel=rel)
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            bases = [dotted(b) or "" for b in node.bases]
            # Every class is recorded: one that subclasses RequestHandler only
            # through a project base (`class Api(BaseView)`) is resolved later.
            cls = HandlerClass(
                file=rel,
                name=node.name,
                bases=[b.split(".")[-1] for b in bases if b],
                websocket=any("WebSocket" in b for b in bases),
                direct=any(b.endswith("Handler") for b in bases),
            )
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name in _VERBS:
                    cls.methods[item.name.upper()] = any(
                        (dotted(d) or "").split(".")[-1] == "authenticated" for d in item.decorator_list
                    )
            out.classes.append(cls)
        elif isinstance(node, (ast.List, ast.Tuple)) and len(out.specs) < _MAX_SPECS:
            for elt in node.elts:
                spec = _spec(elt, rel)
                if spec is not None:
                    out.specs.append(spec)
    return out


def _spec(node: ast.expr, rel: str) -> UrlSpec | None:
    if isinstance(node, ast.Tuple) and len(node.elts) >= 2:
        pattern, handler = node.elts[0], node.elts[1]
    elif isinstance(node, ast.Call) and call_name(node) in {"url", "URLSpec"} and len(node.args) >= 2:
        pattern, handler = node.args[0], node.args[1]
    else:
        return None
    text = str_const(pattern)
    name = dotted(handler)
    if text is None or name is None or not text.lstrip("^").startswith("/"):
        return None
    return UrlSpec(file=rel, line=node.lineno, pattern=text, handler=name.split(".")[-1])


def _path(pattern: str) -> str:
    path = pattern.lstrip("^")
    while path.endswith("$") and not path.endswith("\\$"):
        path = path[:-1]
    return path or "/"


def resolve_tornado(files: list[TornadoFile]) -> list[TornadoRoute]:
    by_name: dict[str, list[HandlerClass]] = {}
    for f in files:
        for cls in f.classes:
            by_name.setdefault(cls.name, []).append(cls)

    def lookup(name: str, file: str) -> HandlerClass | None:
        found = by_name.get(name, [])
        same = [c for c in found if c.file == file]
        if same:
            return same[0]
        return found[0] if len(found) == 1 else None

    def verbs(cls: HandlerClass) -> tuple[dict[str, bool], bool, bool]:
        """(verb → authenticated, websocket, is a handler) through up to
        _MAX_INHERIT levels of bases."""
        methods: dict[str, bool] = {}
        websocket = cls.websocket
        handler = cls.direct
        seen: set[int] = set()
        current: list[HandlerClass] = [cls]
        for _ in range(_MAX_INHERIT + 1):
            nxt: list[HandlerClass] = []
            for c in current:
                if id(c) in seen:
                    continue
                seen.add(id(c))
                websocket = websocket or c.websocket
                handler = handler or c.direct
                for verb, authed in c.methods.items():
                    methods.setdefault(verb, authed)
                for base in c.bases:
                    parent = lookup(base, c.file)
                    if parent is not None:
                        nxt.append(parent)
            current = nxt
        return methods, websocket, handler

    routes: list[TornadoRoute] = []
    for f in files:
        for spec in f.specs:
            cls = lookup(spec.handler, spec.file)
            methods, websocket, handler = verbs(cls) if cls is not None else ({}, False, False)
            if not handler and not spec.handler.endswith("Handler"):
                continue
            path = _path(spec.pattern)
            if websocket:
                routes.append(TornadoRoute(path, "WS", spec.file, spec.line))
                continue
            if not methods:
                routes.append(TornadoRoute(path, "ANY", spec.file, spec.line))
                continue
            for verb in sorted(methods):
                if methods[verb]:
                    routes.append(
                        TornadoRoute(
                            path, verb, spec.file, spec.line,
                            auth="required",
                            guards=["@tornado.web.authenticated"],
                            evidence=f"@tornado.web.authenticated on {spec.handler}.{verb.lower()}",
                        )
                    )
                else:
                    routes.append(TornadoRoute(path, verb, spec.file, spec.line))
    return routes


__all__ = ["TornadoFile", "TornadoRoute", "parse_tornado", "resolve_tornado"]
