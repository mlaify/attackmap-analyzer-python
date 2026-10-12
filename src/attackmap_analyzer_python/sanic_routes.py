"""Sanic ``@app.route(...)`` / ``@bp.websocket(...)`` decorators (#2).

The verb decorators (``@app.get``) stay with the regex extractor. ``route``
takes its verbs from ``methods=[...]`` and defaults to ``GET`` (Sanic's own
default, and what core's ``@x.route`` pattern assumes, so the two analyzers'
routes merge instead of duplicating). The receiver must be ``app``/``bp``/
``blueprint`` or a name assigned from ``Sanic(...)`` / ``Blueprint(...)``.
"""

from __future__ import annotations

import ast

from ._pyast import call_name, keyword, safe_parse, str_const

_RECEIVERS = {"app", "bp", "blueprint"}


def _normalize(path: str) -> str:
    """Leading slash, no `//` runs: the shape core gives the same decorator."""
    path = "/" + path.strip().lstrip("/")
    while "//" in path:
        path = path.replace("//", "/")
    return path


def _methods(node: ast.expr | None) -> list[str]:
    """`methods=["GET", "post"]`, a tuple/set, or `HTTPMethod.DELETE` enums."""
    if node is None:
        return []
    elts = node.elts if isinstance(node, (ast.List, ast.Tuple, ast.Set)) else [node]
    out: list[str] = []
    for elt in elts[:16]:
        value = str_const(elt)
        if value is None and isinstance(elt, ast.Attribute):
            value = elt.attr  # HTTPMethod.DELETE
        if value and value.isalpha():
            out.append(value.upper())
    return out


def sanic_routes(content: str) -> list[tuple[str, str, int]] | None:
    """[(path, method, line)], or ``None`` when the file can't be parsed."""
    tree = safe_parse(content)
    if tree is None:
        return None
    receivers = set(_RECEIVERS)
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and call_name(node.value) in {"Sanic", "Blueprint"}:
            receivers.update(t.id for t in node.targets if isinstance(t, ast.Name))
    out: list[tuple[str, str, int]] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in node.decorator_list:
            if not (isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute)):
                continue
            owner = dec.func.value
            if not (isinstance(owner, ast.Name) and owner.id in receivers):
                continue
            kind = dec.func.attr
            if kind not in {"route", "websocket"}:
                continue
            path = str_const(dec.args[0] if dec.args else keyword(dec, "uri"))
            if path is None:
                continue
            path = _normalize(path)
            if kind == "websocket":
                out.append((path, "WS", dec.lineno))
                continue
            methods = _methods(keyword(dec, "methods")) or ["GET"]
            for method in dict.fromkeys(methods):
                out.append((path, method, dec.lineno))
    return out


__all__ = ["sanic_routes"]
