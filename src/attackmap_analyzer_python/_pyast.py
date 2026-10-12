"""Small, defensive helpers around :mod:`ast` for the route extractors.

The analyzed repository is untrusted: files can be huge, truncated, Python 2,
or deliberately pathological. Nothing here executes code — ``ast.parse`` only
builds a syntax tree — but parsing still has to be bounded and must never
raise out of ``analyze()``.
"""

from __future__ import annotations

import ast

# Files above this size are left to the regex extractors. Real URLconfs,
# controllers and handler modules are far smaller; this only bounds the cost of
# a hostile or generated file.
MAX_PARSE_CHARS = 1_000_000


def safe_parse(content: str) -> ast.Module | None:
    """Parse ``content`` or return ``None`` (too big, not Python 3, hostile)."""
    if len(content) > MAX_PARSE_CHARS:
        return None
    try:
        return ast.parse(content)
    except (SyntaxError, ValueError, RecursionError, MemoryError, OverflowError):
        return None


def call_name(node: ast.AST) -> str | None:
    """The trailing name of a call target: ``path`` for ``path(...)`` and
    ``urls.path(...)``, ``DefaultRouter`` for ``routers.DefaultRouter()``."""
    if isinstance(node, ast.Call):
        node = node.func
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def dotted(node: ast.AST, *, max_parts: int = 8) -> str | None:
    """``a.b.c`` for a Name/Attribute chain, else ``None``."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute) and len(parts) < max_parts:
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name) or len(parts) >= max_parts:
        return None
    parts.append(node.id)
    return ".".join(reversed(parts))


def str_const(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def keyword(call: ast.Call, name: str) -> ast.expr | None:
    for kw in call.keywords:
        if kw.arg == name:
            return kw.value
    return None


def str_list(node: ast.AST | None, *, limit: int = 64) -> list[str] | None:
    """String elements of a list/tuple/set literal (non-strings skipped), or
    ``None`` when ``node`` isn't such a literal."""
    if not isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return None
    out: list[str] = []
    for elt in node.elts[:limit]:
        value = str_const(elt)
        if value is not None:
            out.append(value)
    return out


def expr_names(node: ast.AST | None, *, limit: int = 16) -> list[str]:
    """Readable names of the elements of a list/tuple literal (``[a, b.c]`` →
    ``["a", "b.c"]``; calls give their callee)."""
    if not isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return []
    out: list[str] = []
    for elt in node.elts[:limit]:
        target = elt.func if isinstance(elt, ast.Call) else elt
        name = dotted(target)
        if name:
            out.append(name)
    return out
