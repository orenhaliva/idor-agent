#!/usr/bin/env python3
"""find_routes.py - framework-agnostic, grep-based HTTP route candidate finder.

Usage:  python find_routes.py <repo_root> [--json out.json] [--max-files N]
                              [--include-tests] [--include-comments]

Finds CANDIDATE HTTP routes in unknown / legacy codebases (recall over precision;
an LLM agent verifies them later).  Standard library only, no network, no LLM.

Each candidate:
  file, line, method ("GET", "GET,POST", "ANY", "UNKNOWN", "WS", "RPC"), path
  (full path incl. unambiguous prefix, or null), path_local (path before prefix),
  prefix, path_params, framework_guess, kind (http|rpc|ws|file|convention),
  snippet (matched line + next 2), handler_hint, path_expr (non-literal path expr).
Per file we also record `prefix_candidates` (class / router / group / mount prefixes).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from collections import Counter

# --------------------------------------------------------------------------- config
SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", ".venv", "venv",
             "__pycache__", "target", "site-packages", ".tox", ".next", ".nuxt",
             "coverage", "bower_components", ".gradle", ".mypy_cache", "Pods",
             "third_party", "env"}
TEST_DIRS = {"test", "tests", "__tests__", "spec", "specs", "e2e", "__mocks__",
             "cypress", "playwright", "testing", "testdata", "integration-tests"}
TEST_FILE_RX = re.compile(
    r"(^test_.*\.py$|_test\.(py|go|rb|exs?)$|\.(test|spec)\.[jt]sx?$|\.(test|spec)\.[mc][jt]s$|"
    r"(Test|Tests|IT)\.(java|kt|cs|scala)$|_spec\.rb$|Test\.php$|^conftest\.py$)")
MAX_SIZE = 1_000_000

PY = {"py"}
JS = {"js", "jsx", "ts", "tsx", "mjs", "cjs", "mts", "cts"}
GO = {"go"}
PHP = {"php", "phtml", "inc", "php5", "php7"}
JAVA = {"java"}
KT = {"kt", "kts"}
SCALA = {"scala"}
GROOVY = {"groovy"}
RB = {"rb", "ru"}
CS = {"cs"}
RS = {"rs"}
EX = {"ex", "exs"}
PL = {"pl", "pm"}
DART = {"dart"}
SWIFT = {"swift"}
LUA = {"lua"}
FILEROUTE = {"jsp", "asp", "aspx", "ashx", "asmx", "cgi", "cfm"}
SRC_EXT = (PY | JS | GO | PHP | JAVA | KT | SCALA | GROOVY | RB | CS | RS | EX | PL |
           DART | SWIFT | LUA | FILEROUTE)
C_FAMILY = JS | GO | PHP | JAVA | KT | SCALA | GROOVY | CS | RS | DART | SWIFT
HASH_COMMENT = PY | RB | EX | PL | PHP

VERB_LIST = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")
CLIENT_RECV = {"axios", "http", "https", "got", "superagent", "request", "requests", "fetch",
               "supertest", "agent", "cy", "$http", "httpclient", "client", "ky", "$", "jquery",
               "nock", "chai", "curl", "session", "wx", "uni", "resttemplate", "webclient",
               "testclient", "resty", "req", "res", "ctx", "headers", "header", "params", "query",
               "cache", "map", "store", "config", "settings", "env", "os", "storage", "cookies"}

# --------------------------------------------------------------------------- text helpers
_STRIP_STR = re.compile(r'"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'|`[^`]*`')
LIT_RX = re.compile(
    r'''^\s*(?:[rRbBuUfF]|@|\$){0,2}(?:"""(.*?)"""|"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)'|`((?:[^`\\]|\\.)*)`)''',
    re.S)
ANY_LIT = re.compile(r'''"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)'|`((?:[^`\\]|\\.)*)`''')
KW_RX = re.compile(r"^\s*(\w+)\s*[=:]\s*(?![=>])(.*)$", re.S)
PATH_KWS = ("path", "url", "rule", "value", "route", "uri", "pattern", "url_path", "UriTemplate",
            "Template", "template", "urlPattern")


def lit(arg):
    m = LIT_RX.match(arg)
    if not m:
        return None
    for g in m.groups():
        if g is not None:
            return g
    return None


def first_lit_in(text):
    m = ANY_LIT.search(text)
    if not m:
        return None
    for g in m.groups():
        if g is not None:
            return g
    return None


def all_lits(text):
    return [next(g for g in m.groups() if g is not None) for m in ANY_LIT.finditer(text)]


def arg_value(a):
    s = lit(a)
    if s is not None:
        return s
    t = a.strip()
    if t[:1] in "[{(":
        return first_lit_in(t)
    return None


def read_call(lines, i, col, maxlines=25, maxchars=6000):
    """Scan from lines[i][col:] (just after an opening bracket) to the matching closer.
    Returns (top-level args, end_line, end_col, raw_inner_text)."""
    depth = 0
    q = None
    args, cur, raw = [], [], []
    j, pos, total = i, col, 0
    n = len(lines)
    while j < n and j - i < maxlines:
        s = lines[j]
        k, L = pos, len(s)
        while k < L:
            c = s[k]
            if q:
                cur.append(c)
                if c == "\\" and k + 1 < L:
                    cur.append(s[k + 1])
                    k += 2
                    continue
                if c == q:
                    q = None
            elif c in "\"'`":
                q = c
                cur.append(c)
            elif c in "([{":
                depth += 1
                cur.append(c)
            elif c in ")]}":
                if depth == 0:
                    args.append("".join(cur))
                    return args, j, k + 1, "".join(raw) + s[pos:k]
                depth -= 1
                cur.append(c)
            elif c == "," and depth == 0:
                args.append("".join(cur))
                cur = []
            else:
                cur.append(c)
            k += 1
        raw.append(s[pos:] + "\n")
        total += L
        cur.append("\n")
        if q in ("'", '"'):
            q = None
        j += 1
        pos = 0
        if total > maxchars:
            break
    args.append("".join(cur))
    return args, min(j, n) - 1, 0, "".join(raw)


def pick_path(args, need_slash=True, kws=PATH_KWS, first_n=3, allow_empty=True):
    """Return (path, expr, rejected). rejected=True if string literals existed but none looked like a path."""
    saw = False

    def ok(s):
        return (not need_slash) or s.startswith("/") or s.startswith("*") or (allow_empty and s == "")

    for a in args[:first_n]:
        if KW_RX.match(a) and not a.lstrip().startswith(("'", '"')):
            continue
        s = arg_value(a)
        if s is None:
            continue
        saw = True
        if ok(s):
            return s, None, False
    for a in args:
        m = KW_RX.match(a)
        if m and m.group(1) in kws:
            s = arg_value(m.group(2))
            if s is not None:
                saw = True
                if ok(s):
                    return s, None, False
    expr = None
    if not saw and args and args[0].strip() and not KW_RX.match(args[0]):
        expr = " ".join(args[0].split())[:80]
    return None, expr, saw


def kwarg(args, name):
    for a in args:
        m = KW_RX.match(a)
        if m and m.group(1) == name:
            return m.group(2)
    return None


def methods_in(text):
    out = []
    for s in all_lits(text):
        u = s.upper()
        if u in VERB_LIST and u not in out:
            out.append(u)
    return out


def join_path(prefix, local):
    parts = [p.strip("/") for p in (prefix or "", local or "") if p and p.strip("/")]
    return "/" + "/".join(parts)


def normalize_path(p):
    if p is None:
        return None
    if p == "":
        return "/"
    if p.startswith(("/", "*", "^")) or "://" in p:
        return p
    return "/" + p


_PARAM_RXS = [
    re.compile(r"\{\*?(\w+)(?:[?:=][^}]*)?\}"),
    re.compile(r"<(?:[\w.]+:)?(\w+)>"),
    re.compile(r"(?:(?<=[/.\-(])|^):(\w+)"),
    re.compile(r"\[\[?(?:\.{3})?(\w+)\]\]?"),
    re.compile(r"\(\?P<(\w+)>"),
    re.compile(r"(?<=/)\*(\w+)"),
]


def extract_params(path):
    if not path:
        return []
    found = []
    for rx in _PARAM_RXS:
        for m in rx.finditer(path):
            found.append((m.start(), m.group(1)))
    found.sort()
    out = []
    for _, n in found:
        if n not in out:
            out.append(n)
    return out


def block_end(lines, start, maxlines=1500):
    depth, seen = 0, False
    for j in range(start, min(len(lines), start + maxlines)):
        for c in _STRIP_STR.sub('""', lines[j]):
            if c == "{":
                depth += 1
                seen = True
            elif c == "}":
                depth -= 1
        if seen and depth <= 0:
            return j
    return min(len(lines) - 1, start + maxlines)


def singular(w):
    w = w.strip("/").split("/")[-1]
    if w.endswith("ies"):
        return w[:-3] + "y"
    if w.endswith("ses") or w.endswith("xes"):
        return w[:-2]
    if w.endswith("s") and not w.endswith("ss"):
        return w[:-1]
    return w


# --------------------------------------------------------------------------- comment mask
def comment_mask(lines, ext):
    """0 = code, 1 = line comment / docstring, 2 = block comment (annotation docblocks ok)."""
    n = len(lines)
    mask = [0] * n
    if ext in PY:
        inq = None
        for i, l in enumerate(lines):
            s = l.strip()
            if inq:
                mask[i] = 1
                if inq in s:
                    inq = None
                continue
            if s.startswith("#"):
                mask[i] = 1
                continue
            for q in ('"""', "'''"):
                c = s.count(q)
                if c % 2 == 1:
                    inq = q
                    if s.lstrip("rRbBuUfF").startswith(q):
                        mask[i] = 1
                    break
                if c >= 2 and s.lstrip("rRbBuUfF").startswith(q):
                    mask[i] = 1
                    break
        return mask
    if ext in RB | EX | PL:
        inb = False
        for i, l in enumerate(lines):
            s = l.strip()
            if ext in RB:
                if s.startswith("=begin"):
                    inb = True
                if inb:
                    mask[i] = 1
                    if s.startswith("=end"):
                        inb = False
                    continue
            if s.startswith("#"):
                mask[i] = 1
        return mask
    if ext in C_FAMILY:
        inb = False
        hash_ok = ext in PHP
        for i, l in enumerate(lines):
            s = l.strip()
            if inb:
                mask[i] = 2
                if "*/" in s:
                    inb = False
                continue
            if s.startswith("//") or (hash_ok and s.startswith("#") and not s.startswith("#[")):
                mask[i] = 1
            elif s.startswith("/*"):
                mask[i] = 2
                if "*/" not in s[2:]:
                    inb = True
    return mask


# --------------------------------------------------------------------------- rule registry
class Rule:
    __slots__ = ("exts", "rx", "fn", "doc_ok", "fallback")

    def __init__(self, exts, rx, fn, doc_ok, fallback):
        self.exts, self.rx, self.fn, self.doc_ok, self.fallback = exts, rx, fn, doc_ok, fallback


RULES = []


def rule(exts, pattern, doc_ok=False, fallback=False, flags=0):
    def deco(fn):
        RULES.append(Rule(frozenset(exts), re.compile(pattern, flags), fn, doc_ok, fallback))
        return fn
    return deco


# --------------------------------------------------------------------------- per-file ctx
class Ctx:
    def __init__(self, rel, text, lines, ext):
        self.rel, self.text, self.lines, self.ext = rel, text, lines, ext
        self.out = []
        self.seen = set()
        self.lines_hit = set()
        self.var_prefix = {}       # router/group variable -> prefix
        self.scopes = []           # dicts: start, end, var, prefix
        self.classes = []          # (line, prefix, name)
        self.class_lines = set()
        self.prefix_cands = []
        self.jaxrs_paths = {}      # line -> path (method-level @Path)
        self.cs_routes = {}        # line -> path (method-level [Route])
        self.used_aux = set()
        self._hint = {}

    def has(self, pat):
        v = self._hint.get(pat)
        if v is None:
            v = self._hint[pat] = bool(re.search(pat, self.text))
        return v

    # ---- prefix resolution
    def prefix_for(self, line, recv=None):
        if recv:
            recv = recv.split(".")[-1].lstrip("$")
            for sc in reversed(self.scopes):
                if sc["var"] == recv and sc["start"] <= line <= sc["end"]:
                    return sc["prefix"]
            if recv in self.var_prefix:
                return self.var_prefix[recv]
            return None
        parts = [sc["prefix"] for sc in self.scopes if sc["var"] is None and sc["start"] <= line <= sc["end"]]
        return ("/" + "/".join(p.strip("/") for p in parts if p.strip("/"))) if parts else None

    def class_prefix(self, line):
        best = None
        for (ln, pref, name) in self.classes:
            if ln < line:
                best = (pref, name)
        return best

    def add_prefix(self, kind, prefix, line, name=None, target=None):
        d = {"kind": kind, "prefix": prefix, "line": line + 1}
        if name:
            d["name"] = name
        if target:
            d["target"] = target
        self.prefix_cands.append(d)

    # ---- candidate emission
    def add(self, i, method, local, fw, *, kind="http", handler=None, prefix=None, expr=None,
            extra=None, line_override=None):
        path = local
        if prefix:
            path = join_path(prefix, local or "")
        path = normalize_path(path)
        li = i if line_override is None else line_override
        key = (li, method, path)
        if key in self.seen:
            return
        self.seen.add(key)
        self.lines_hit.add(li)
        snippet = "\n".join(x.rstrip() for x in self.lines[li:li + 3])[:500]
        d = {"file": self.rel, "line": li + 1, "method": method or "UNKNOWN", "path": path,
             "path_params": extract_params(path or local or ""), "framework_guess": fw,
             "kind": kind, "snippet": snippet, "handler_hint": handler}
        if prefix:
            d["prefix"] = prefix
            d["path_local"] = normalize_path(local) if local is not None else None
        if expr:
            d["path_expr"] = expr
        if extra:
            d.update(extra)
        self.out.append(d)


# --------------------------------------------------------------------------- handler hints
_KW_NOT_FN = {"if", "for", "while", "return", "new", "switch", "catch", "function", "await", "async",
              "super", "this", "throw", "typeof", "when", "elif", "with", "except", "def", "fn"}
_SIG_RXS = [re.compile(p) for p in (
    r"\bfun\s+(?:<[^>]*>\s*)?(?:[\w.]+\.)?(\w+)\s*\(",
    r"\bdef\s+(?:self\.)?(\w+[!?]?)",
    r"\bfunction\s*&?\s*(\w+)\s*\(",
    r"\bfunc\s+(?:\([^)]*\)\s*)?(\w+)",
    r"\bfn\s+(\w+)",
    r"\bclass\s+(\w+)",
)]
_GENERIC_SIG = re.compile(r"(?<![\w.@])(\w+)\s*(?:<[^>]*>)?\s*\(")


def sig_handler(lines, j, col=0, span=8):
    for k in range(j, min(len(lines), j + span)):
        s = lines[k][col:] if k == j else lines[k]
        t = s.strip()
        if not t:
            continue
        if k != j and t.startswith(("@", "[", "#[", "*", "//", "/*", "#")):
            continue
        for rx in _SIG_RXS:
            m = rx.search(s)
            if m:
                return m.group(1)
        if k != j or t:
            for m in _GENERIC_SIG.finditer(s):
                nm = m.group(1)
                if nm not in _KW_NOT_FN and not nm[0].isupper() or (nm not in _KW_NOT_FN and k != j):
                    return nm
    return None


_IDENT_ARG = re.compile(r"^\s*([\w$.\\:]+?)(?:\.as_view\([^)]*\))?\s*$")


def arg_handler(args, start=1):
    for a in reversed(args[start:]):
        if lit(a) is not None or KW_RX.match(a):
            continue
        m = _IDENT_ARG.match(a)
        if m:
            return m.group(1)
        t = a.strip()
        mm = re.match(r"^\[\s*([\w\\]+)::class\s*,\s*['\"](\w+)['\"]\s*\]$", t)
        if mm:
            return f"{mm.group(1)}@{mm.group(2)}"
        mm = re.search(r"function\s+(\w+)", t)
        if mm:
            return mm.group(1)
        mm = re.match(r"^(?:\w+\s*=>\s*)?(\w[\w.]*)\s*\(", t)
        if mm and mm.group(1) not in ("async", "function") and not t.startswith(("(", "async")):
            return mm.group(1)
    return None


def fw_guess(ctx, table, default):
    for name, pat in table:
        if ctx.has(pat):
            return name
    return default


PY_FW = [("fastapi", r"fastapi|APIRouter"), ("litestar", r"litestar"), ("starlette", r"starlette"),
         ("quart", r"\bquart\b"), ("flask", r"(?i)\bflask|Blueprint\("), ("sanic", r"\bsanic\b"),
         ("aiohttp", r"aiohttp"), ("bottle", r"\bbottle\b"), ("falcon", r"\bfalcon\b"),
         ("tornado", r"tornado"), ("django", r"django|rest_framework"), ("pyramid", r"pyramid"),
         ("web.py/cherrypy", r"cherrypy|web\.py")]
JS_FW = [("nestjs", r"@nestjs/"), ("fastify", r"fastify"), ("hapi", r"@hapi/|require\(['\"]hapi['\"]\)"),
         ("koa", r"\bkoa\b"), ("hono", r"\bhono\b"), ("restify", r"restify"), ("elysia", r"elysia"),
         ("trpc", r"trpc"), ("next", r"from ['\"]next|next/server"), ("express", r"express")]
GO_FW = [("gin", r"gin-gonic"), ("echo", r"labstack/echo"), ("fiber", r"gofiber"), ("chi", r"go-chi"),
         ("gorilla/mux", r"gorilla/mux"), ("httprouter", r"julienschmidt/httprouter"),
         ("beego", r"beego"), ("iris", r"kataras/iris|iris-go"), ("net/http", r"net/http")]
JAVA_FW = [("spring", r"springframework"), ("micronaut", r"micronaut"), ("quarkus/jaxrs", r"ws\.rs"),
           ("vertx", r"vertx"), ("spark", r"spark\.|sparkjava"), ("ktor", r"io\.ktor")]


# --------------------------------------------------------------------------- PYTHON
@rule(PY, r"^\s*@(?P<obj>[\w.]+)\.(?P<v>get|post|put|patch|delete|head|options|trace|route|api_route|"
          r"websocket|websocket_route|ws)\s*\(")
def py_deco(ctx, i, m):
    if m["obj"].split(".")[-1] in ("mock", "patch", "pytest", "click"):
        return
    args, endj, endcol, raw = read_call(ctx.lines, i, m.end())
    path, expr, rej = pick_path(args)
    if rej:
        return
    fw = fw_guess(ctx, PY_FW, "python-web")
    v = m["v"]
    kind = "http"
    nxt = ctx.lines[endj + 1].lstrip() if endj + 1 < len(ctx.lines) else ""
    if v in ("websocket", "websocket_route", "ws"):
        meth, kind = "WS", "ws"
    elif v in VERB_LIST_LOWER:
        meth = v.upper()
    else:
        ms = methods_in(kwarg(args, "methods") or "")
        meth = ",".join(ms) if ms else ("ANY" if nxt.startswith("class ") else "GET")
    ctx.add(i, meth, path, fw, kind=kind, handler=sig_handler(ctx.lines, endj + 1, 0),
            prefix=ctx.prefix_for(i, m["obj"]), expr=expr)


VERB_LIST_LOWER = {v.lower() for v in VERB_LIST} | {"trace"}


@rule(PY, r"^\s*@(?P<v>get|post|put|patch|delete|head|options|route|websocket)\s*\(")
def py_bare_deco(ctx, i, m):
    args, endj, endcol, raw = read_call(ctx.lines, i, m.end())
    path, expr, rej = pick_path(args)
    if rej or (path is None and expr is None):
        return
    v = m["v"]
    meth = "WS" if v == "websocket" else (v.upper() if v in VERB_LIST_LOWER else (",".join(methods_in(kwarg(args, "methods") or "")) or "GET"))
    ctx.add(i, meth, path, fw_guess(ctx, PY_FW, "bottle/litestar"), kind="ws" if v == "websocket" else "http",
            handler=sig_handler(ctx.lines, endj + 1, 0), expr=expr)


@rule(PY, r"\.add_url_rule\s*\(")
def py_add_url_rule(ctx, i, m):
    args, endj, _, _ = read_call(ctx.lines, i, m.end())
    path, expr, rej = pick_path(args)
    if rej:
        return
    ms = methods_in(kwarg(args, "methods") or "")
    h = kwarg(args, "view_func") or (args[2].strip() if len(args) > 2 else None)
    ctx.add(i, ",".join(ms) or "GET", path, "flask", handler=h and h.strip()[:60], expr=expr)


@rule(PY, r"\.(?:add_api_route|add_route|add_websocket_route|add_api_websocket_route|add_resource|add_view)\s*\(")
def py_add_route(ctx, i, m):
    args, endj, _, _ = read_call(ctx.lines, i, m.end())
    if "add_resource" in m.group(0) or "add_view" in m.group(0):
        # flask-restful add_resource(Cls, '/path') / pyramid add_view
        path, expr, rej = pick_path(args[1:] or args)
        if rej or path is None:
            return
        ctx.add(i, "ANY", path, "flask-restful", handler=args[0].strip()[:60])
        return
    path, expr, rej = pick_path(args)
    if rej:
        return
    ms = methods_in(kwarg(args, "methods") or "") or methods_in(args[0] if args else "")
    ws = "websocket" in m.group(0)
    ctx.add(i, "WS" if ws else (",".join(ms) or "ANY"), path, fw_guess(ctx, PY_FW, "python-web"),
            kind="ws" if ws else "http", handler=arg_handler(args, 1), expr=expr)


@rule(PY, r"(?<![\w.@])(?P<v>web\.get|web\.post|web\.put|web\.patch|web\.delete|web\.view|web\.head|web\.route)\s*\(")
def py_aiohttp_routetable(ctx, i, m):
    args, endj, _, _ = read_call(ctx.lines, i, m.end())
    v = m["v"].split(".")[1]
    if v == "route":
        meth = (lit(args[0]) or "ANY").upper() if args else "ANY"
        path, expr, rej = pick_path(args[1:])
    else:
        meth = v.upper() if v != "view" else "ANY"
        path, expr, rej = pick_path(args)
    if rej:
        return
    ctx.add(i, meth, path, "aiohttp", handler=arg_handler(args, 1), expr=expr)


@rule(PY, r"(?<![\w.@])(?P<v>Route|WebSocketRoute|Mount)\s*\(")
def py_starlette_route(ctx, i, m):
    if not ctx.has(r"starlette|fastapi|litestar|Route"):
        return
    args, endj, _, _ = read_call(ctx.lines, i, m.end())
    path, expr, rej = pick_path(args)
    if rej or path is None:
        return
    if m["v"] == "Mount":
        ctx.add_prefix("mount", path, i, target=(args[1].strip()[:60] if len(args) > 1 else None))
        return
    ms = methods_in(kwarg(args, "methods") or "")
    ws = m["v"] == "WebSocketRoute"
    ctx.add(i, "WS" if ws else (",".join(ms) or "GET"), path, "starlette", kind="ws" if ws else "http",
            handler=arg_handler(args, 1))


@rule(PY, r"(?<![\w.@])(?P<v>re_path|path|url)\s*\(\s*(?=[rRuUbB]?['\"])")
def py_django(ctx, i, m):
    base = os.path.basename(ctx.rel)
    if not (ctx.has(r"urlpatterns") or base.startswith(("url", "route"))):
        return
    args, endj, _, raw = read_call(ctx.lines, i, m.end())
    s = arg_value(args[0]) if args else None
    if s is None:
        return
    s = re.sub(r"\(\?P<(\w+)>[^)]*\)", r"{\1}", s.lstrip("^").rstrip("$"))
    second = args[1].strip() if len(args) > 1 else ""
    if second.startswith("include"):
        ctx.add_prefix("mount", "/" + s.strip("/"), i, target=second[:80])
        return
    fw = "django" if m["v"] != "url" or ctx.has("django") else "tornado/py-url"
    ctx.add(i, "ANY", s, fw, handler=second.split("(")[0].strip()[:60] or None)


@rule(PY, r"(?P<obj>[\w.]+)\.register\s*\(\s*r?(?=['\"])")
def py_drf_register(ctx, i, m):
    args, endj, _, _ = read_call(ctx.lines, i, m.end() - 0 if False else m.end() - 0)
    # m.end() sits before the quote: back up to the open paren
    pcol = ctx.lines[i].index("(", m.start())
    args, endj, _, _ = read_call(ctx.lines, i, pcol + 1)
    s = lit(args[0]) if args else None
    if not s or "/" in s and " " in s:
        return
    if not ctx.has(r"rest_framework|DefaultRouter|SimpleRouter|routers\."):
        return
    ctx.add(i, "ANY", "/" + s.strip("/"), "django-drf", handler=args[1].strip()[:60] if len(args) > 1 else None,
            extra={"note": "DRF router.register: expands to list/create/retrieve/update/destroy under /<prefix>/{pk}"})


@rule(PY, r"^\s*@action\s*\(")
def py_drf_action(ctx, i, m):
    args, endj, _, _ = read_call(ctx.lines, i, m.end())
    ms = methods_in(kwarg(args, "methods") or "") or ["GET"]
    up = kwarg(args, "url_path")
    h = sig_handler(ctx.lines, endj + 1, 0)
    local = lit(up) if up else h
    detail = (kwarg(args, "detail") or "").strip() == "True"
    ctx.add(i, ",".join(ms), ("{pk}/" if detail else "") + (local or ""), "django-drf", handler=h,
            extra={"note": "DRF @action relative to the registered viewset prefix"})


@rule(PY, r"""\(\s*r?(['"])(?P<p>/[^'"]*)\1\s*,\s*(?P<h>[A-Z][\w.]*)\s*[,)]""")
def py_tornado(ctx, i, m):
    h = m["h"]
    if not (ctx.has(r"tornado|RequestHandler") or h.endswith(("Handler", "View"))):
        return
    if not ctx.has(r"tornado|RequestHandler|Application|Handler"):
        return
    ctx.add(i, "ANY", m["p"], "tornado", handler=h)


# --------------------------------------------------------------------------- JS / TS
@rule(JS | JAVA | KT | SCALA | GROOVY | DART,
      r"(?P<obj>[\w$.]+)\.(?P<v>get|post|put|patch|delete|all|options|head|any)\s*\(")
def js_dotverb(ctx, i, m):
    obj = m["obj"]
    if obj.split(".")[-1].lower() in CLIENT_RECV:
        return
    args, endj, endcol, raw = read_call(ctx.lines, i, m.end())
    path, expr, rej = pick_path(args)
    if rej or (path is None and expr is None):
        return
    if path is None and expr and len(args) < 2:
        return
    v = m["v"]
    meth = "ANY" if v in ("all", "any") else v.upper()
    fw = fw_guess(ctx, JS_FW, "express-like") if ctx.ext in JS else fw_guess(ctx, JAVA_FW, "dot-verb")
    ctx.add(i, meth, path, fw, handler=arg_handler(args, 1), prefix=ctx.prefix_for(i, obj), expr=expr)


@rule(JS, r"(?P<obj>[\w$.]+)\.route\s*\(\s*(?=['\"`])")
def js_route_chain(ctx, i, m):
    pcol = ctx.lines[i].index("(", m.start("obj") + len(m["obj"]))
    args, endj, endcol, raw = read_call(ctx.lines, i, pcol + 1)
    path, expr, rej = pick_path(args, need_slash=False)
    if path is None:
        return
    if len(args) > 1 and re.match(r"^\s*[\w$.]+\s*$", args[1]):
        ctx.add_prefix("mount", path, i, name=m["obj"], target=args[1].strip())
        return
    fw = fw_guess(ctx, JS_FW, "express-like")
    found = False
    rest = ctx.lines[endj][endcol:]
    seg = [(endj, rest)] + [(k, ctx.lines[k]) for k in range(endj + 1, min(len(ctx.lines), endj + 14))]
    for k, s in seg:
        for mm in re.finditer(r"\.(get|post|put|patch|delete|all|options|head)\s*\(", s):
            found = True
            sub, ej, _, _ = read_call(ctx.lines, k, mm.end())
            ctx.add(i, "ANY" if mm.group(1) == "all" else mm.group(1).upper(), path, fw,
                    handler=arg_handler([""] + sub, 1), line_override=k)
        if s.rstrip().endswith(";") and k >= endj:
            break
        if k > endj and not s.strip():
            break
    if not found:
        ctx.add(i, "UNKNOWN", path, fw)


def _enclosing_obj(raw, pos):
    depth, a = 0, pos
    while a > 0:
        a -= 1
        if raw[a] == "}":
            depth += 1
        elif raw[a] == "{":
            if depth == 0:
                break
            depth -= 1
    depth, b = 0, pos
    while b < len(raw):
        if raw[b] == "{":
            depth += 1
        elif raw[b] == "}":
            if depth == 0:
                break
            depth -= 1
        b += 1
    return a, b


@rule(JS, r"(?P<obj>[\w$.]+)\.route\s*\(\s*(?=[\[{])")
def js_route_obj(ctx, i, m):
    pcol = ctx.lines[i].index("(", m.start("obj") + len(m["obj"]))
    args, endj, _, raw = read_call(ctx.lines, i, pcol + 1, maxlines=120, maxchars=20000)
    fw = fw_guess(ctx, JS_FW, "fastify/hapi")
    for pm in re.finditer(r"""\b(?:url|path)\s*:\s*(['"`])(?P<p>[^'"`]*)\1""", raw):
        a, b = _enclosing_obj(raw, pm.start())
        obj = raw[a:b]
        mm = re.search(r"\bmethod\s*:\s*(\[[^\]]*\]|['\"`]\w+['\"`])", obj)
        ms = methods_in(mm.group(1)) if mm else []
        if not mm:
            continue
        ln = i + raw[:pm.start()].count("\n")
        h = re.search(r"\bhandler\s*:\s*([\w$.]+)", obj)
        ctx.add(i, ",".join(ms) or "ANY", pm["p"], fw, handler=h.group(1) if h else None,
                prefix=ctx.prefix_for(i, m["obj"]), line_override=min(ln, len(ctx.lines) - 1))


@rule(JS, r"(?P<obj>[\w$.]+)\.(?:use|register)\s*\(\s*(?=['\"`/]|[\w$.]+\s*,\s*\{)")
def js_mount(ctx, i, m):
    pcol = ctx.lines[i].index("(", m.start("obj") + len(m["obj"]))
    args, endj, _, raw = read_call(ctx.lines, i, pcol + 1)
    p = None
    if args and lit(args[0]) is not None and lit(args[0]).startswith("/"):
        p = lit(args[0])
    else:
        pm = re.search(r"""\bprefix\s*:\s*['"`]([^'"`]*)""", raw)
        if pm:
            p = pm.group(1)
    if p:
        ctx.add_prefix("mount", p, i, name=m["obj"],
                       target=(args[1].strip()[:60] if len(args) > 1 and not args[1].strip().startswith("{") else args[0].strip()[:60]))


@rule(JS | JAVA | KT, r"^\s*@(?P<v>Get|Post|Put|Patch|Delete|Options|Head|All|Sse)\s*(?:\(|$)")
def nest_verb(ctx, i, m):
    if i in ctx.class_lines:
        return
    if m.group(0).rstrip().endswith("("):
        args, endj, endcol, raw = read_call(ctx.lines, i, m.end())
    else:
        args, endj, endcol, raw = [], i, m.end(), ""
    path, expr, rej = pick_path(args, need_slash=False, kws=("path", "value"))
    v = m["v"]
    fw = "nestjs" if ctx.ext in JS else ("micronaut" if ctx.has("micronaut") else "nest-like")
    cp = ctx.class_prefix(i)
    meth = "ANY" if v == "All" else ("GET" if v == "Sse" else v.upper())
    ctx.add(i, meth, path if path is not None else "", fw, handler=sig_handler(ctx.lines, endj, endcol),
            prefix=cp[0] if cp else None, expr=expr, extra={"controller": cp[1]} if cp and cp[1] else None)


@rule(JS, r"^\s*@(?P<v>SubscribeMessage|MessagePattern|EventPattern|GrpcMethod|WebSocketGateway)\s*\(")
def nest_rpc(ctx, i, m):
    args, endj, _, raw = read_call(ctx.lines, i, m.end())
    s = first_lit_in(raw) if args else None
    if m["v"] == "WebSocketGateway":
        return
    ctx.add(i, "WS" if m["v"] == "SubscribeMessage" else "RPC", s, "nestjs",
            kind="ws" if m["v"] == "SubscribeMessage" else "rpc", handler=sig_handler(ctx.lines, endj + 1, 0),
            expr=None if s else raw.strip()[:60])


@rule(JS, r"^\s*@(?P<v>Query|Mutation|Subscription)\s*\((?P<a>[^)]*)\)\s*$")
def nest_graphql(ctx, i, m):
    if not ctx.has(r"@nestjs/graphql|@Resolver"):
        return
    ctx.add(i, "RPC", None, "nestjs-graphql", kind="rpc", handler=sig_handler(ctx.lines, i + 1, 0),
            extra={"graphql_op": m["v"].lower()})


@rule(JS, r"\.(?P<v>query|mutation|subscription)\s*\(\s*(?![\"'`])")
def trpc(ctx, i, m):
    lo = max(0, i - 10)
    window = "\n".join(ctx.lines[lo:i + 1])
    if not re.search(r"rocedure|\.input\(|createTRPCRouter|trpc", window):
        return
    nm = None
    for k in range(i, lo - 1, -1):
        mm = re.match(r"^\s*['\"]?([\w$]+)['\"]?\s*:\s*\w*[\w.]*", ctx.lines[k])
        if mm:
            nm = mm.group(1)
            break
    ctx.add(i, "RPC", nm, "trpc", kind="rpc", handler=nm, extra={"procedure_type": m["v"]})


# ----- file-system routes (Next.js / SvelteKit / Nuxt)
def _export_methods(ctx):
    res = []
    for i, l in enumerate(ctx.lines):
        for mm in re.finditer(r"export\s+(?:async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b|"
                              r"export\s+(?:const|let|var)\s+(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b|"
                              r"\bas\s+(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b", l):
            res.append((mm.group(1) or mm.group(2) or mm.group(3), i))
    return res


def file_routes(ctx):
    if ctx.ext not in JS:
        return
    rel = ctx.rel
    m = re.search(r"(?:^|/)pages/api/(.+)\.(?:js|jsx|ts|tsx|mjs|cjs)$", rel)
    if m:
        segs = [s for s in m.group(1).split("/")]
        if segs[-1] == "index":
            segs = segs[:-1]
        path = "/api" + ("/" + "/".join(segs) if segs else "")
        meths = []
        for l in ctx.lines:
            for mm in re.finditer(r"""method\s*[!=]==?\s*['"](\w+)['"]|case\s+['"](GET|POST|PUT|PATCH|DELETE)['"]""", l):
                u = (mm.group(1) or mm.group(2)).upper()
                if u in VERB_LIST and u not in meths:
                    meths.append(u)
        ln = next((k for k, l in enumerate(ctx.lines) if re.search(r"export\s+default|module\.exports", l)), 0)
        hm = re.search(r"export\s+default\s+(?:async\s+)?function\s+(\w+)", ctx.text)
        ctx.add(ln, ",".join(meths) or "ANY", path, "nextjs-pages-api", kind="http",
                handler=hm.group(1) if hm else None, extra={"file_route": True})
        return
    m = re.search(r"(?:^|/)app/(?:(.*)/)?route\.(?:js|jsx|ts|tsx|mjs)$", rel) or \
        re.search(r"(?:^|/)app/route\.(?:js|jsx|ts|tsx|mjs)$", rel)
    fw, segstr = "nextjs-app-router", (m.group(1) if m and m.lastindex else "") if m else None
    if not m:
        m = re.search(r"(?:^|/)routes/(?:(.*)/)?\+server\.(?:js|ts)$", rel)
        fw, segstr = "sveltekit", (m.group(1) or "") if m else None
    if m:
        segs = [s for s in (segstr or "").split("/") if s and not (s.startswith("(") and s.endswith(")")) and not s.startswith("@")]
        path = "/" + "/".join(segs)
        ex = _export_methods(ctx)
        if not ex:
            ctx.add(0, "ANY", path, fw, extra={"file_route": True})
        for meth, ln in ex:
            ctx.add(ln, meth, path, fw, handler=meth, extra={"file_route": True})
        return
    m = re.search(r"(?:^|/)server/(api|routes)/(.+)\.(?:js|ts|mjs)$", rel)
    if m:
        name = m.group(2)
        mm = re.search(r"\.(get|post|put|patch|delete|head|options)$", name)
        meth = mm.group(1).upper() if mm else "ANY"
        if mm:
            name = name[:mm.start()]
        segs = [s for s in name.split("/") if s != "index"]
        path = ("/api" if m.group(1) == "api" else "") + "/" + "/".join(segs)
        ctx.add(0, meth, path.rstrip("/") or "/", "nuxt", extra={"file_route": True})


# --------------------------------------------------------------------------- GO
_GO_RECV_SKIP = {"http", "client", "resty", "req", "res", "r.URL", "header", "headers", "query", "form",
                 "values", "viper", "cache", "ctx", "c", "os", "flag", "strings", "mux.Vars"}


@rule(GO, r"(?P<obj>[\w.]+)\.(?P<v>GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|CONNECT|TRACE|Any|Get|Post|Put|Patch|Delete|Head|Options|Connect|Trace|All|Add)\s*\(")
def go_verb(ctx, i, m):
    obj, v = m["obj"], m["v"]
    if obj.split(".")[-1].lower() in CLIENT_RECV or obj in _GO_RECV_SKIP:
        return
    args, endj, endcol, raw = read_call(ctx.lines, i, m.end())
    if v == "Add":
        if not args or (lit(args[0]) or "").upper() not in VERB_LIST:
            return
        meth = lit(args[0]).upper()
        path, expr, rej = pick_path(args[1:])
    else:
        meth = "ANY" if v in ("Any", "All") else v.upper()
        path, expr, rej = pick_path(args)
    if rej or (path is None and expr is None):
        return
    if path is None and len(args) < 2:
        return
    if v[0].islower() or (v[0].isupper() and v[1:].islower()):
        if path is not None and not path.startswith("/") and path != "":
            return
    ctx.add(i, meth, path, fw_guess(ctx, GO_FW, "go-http"), handler=arg_handler(args, 1),
            prefix=ctx.prefix_for(i, obj), expr=expr)


@rule(GO, r"(?P<obj>[\w.]+)\.(?P<v>HandleFunc|Handle|HandlerFunc|HandleMethod)\s*\(")
def go_handle(ctx, i, m):
    obj = m["obj"]
    if obj.split(".")[-1].lower() in CLIENT_RECV:
        return
    args, endj, endcol, raw = read_call(ctx.lines, i, m.end())
    meth = "ANY"
    a0 = lit(args[0]) if args else None
    if a0 and a0.upper() in VERB_LIST and len(args) > 1:     # gin/httprouter r.Handle("GET", "/x", h)
        meth = a0.upper()
        path, expr, rej = pick_path(args[1:])
    else:
        path, expr, rej = pick_path(args, first_n=1)
        if path:
            pm = re.match(r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|CONNECT|TRACE)\s+(.*)$", path)   # Go 1.22
            if pm:
                meth, path = pm.group(1), pm.group(2)
                path = path.split("/", 1)[-1] and path
                if "/" in path and not path.startswith("/"):
                    path = "/" + path.split("/", 1)[1]
    if rej or (path is None and expr is None):
        return
    tail = ctx.lines[endj][endcol:] + " " + (ctx.lines[endj + 1] if endj + 1 < len(ctx.lines) and ctx.lines[endj + 1].lstrip().startswith(".") else "")
    mm = re.search(r"\.Methods\(([^)]*)\)", tail)
    if mm:
        ms = methods_in(mm.group(1))
        if ms:
            meth = ",".join(ms)
    ctx.add(i, meth, path, fw_guess(ctx, GO_FW, "go-http"), handler=arg_handler(args, 1),
            prefix=ctx.prefix_for(i, obj), expr=expr)


@rule(GO, r"""\.(?:Method|MethodFunc)\s*\(\s*"(?P<m>\w+)"\s*,\s*"(?P<p>[^"]*)\"""")
def go_chi_method(ctx, i, m):
    obj = re.search(r"([\w.]+)\.(?:Method|MethodFunc)\s*\(", ctx.lines[i])
    ctx.add(i, m["m"].upper(), m["p"], "chi", prefix=ctx.prefix_for(i, obj.group(1) if obj else None))


@rule(GO, r"""(?P<obj>[\w.]+)\.Path\(\s*"(?P<p>/[^"]*)"\s*\)""")
def go_gorilla_path(ctx, i, m):
    tail = ctx.lines[i][m.end():] + " " + (ctx.lines[i + 1] if i + 1 < len(ctx.lines) else "")
    mm = re.search(r"\.Methods\(([^)]*)\)", tail)
    ms = methods_in(mm.group(1)) if mm else []
    ctx.add(i, ",".join(ms) or "ANY", m["p"], "gorilla/mux", prefix=ctx.prefix_for(i, m["obj"]))


@rule(GO, r"""(?P<obj>[\w.]+)\.PathPrefix\(\s*"(?P<p>/[^"]*)"\s*\)\s*\.(?:Handler|HandlerFunc)\(""")
def go_gorilla_pathprefix(ctx, i, m):
    ctx.add(i, "ANY", m["p"], "gorilla/mux", prefix=ctx.prefix_for(i, m["obj"]), extra={"note": "prefix handler"})


@rule(GO, r"""["`](?P<m>GET|POST|PUT|PATCH|DELETE)["`]\s*,\s*["`](?P<p>/[^"`]*)["`]""", fallback=True)
def go_route_table(ctx, i, m):
    ctx.add(i, m["m"], m["p"], fw_guess(ctx, GO_FW, "go-http"), extra={"note": "route table entry"})


# --------------------------------------------------------------------------- PHP
_LARAVEL_RES = {
    "resource": [("index", "GET", ""), ("create", "GET", "/create"), ("store", "POST", ""),
                 ("show", "GET", "/{p}"), ("edit", "GET", "/{p}/edit"), ("update", "PUT,PATCH", "/{p}"),
                 ("destroy", "DELETE", "/{p}")],
}
_LARAVEL_RES["apiResource"] = [r for r in _LARAVEL_RES["resource"] if r[0] not in ("create", "edit")]


def _only_except(text):
    om = re.search(r"->(only|except)\(\s*\[?([^\])]*)", text)
    return (om.group(1), set(all_lits(om.group(2)))) if om else (None, set())


@rule(PHP, r"Route::(?P<v>get|post|put|patch|delete|options|any|match|resource|apiResource|resources|apiResources|view|redirect|fallback|singleton)\s*\(")
def laravel_route(ctx, i, m):
    args, endj, endcol, raw = read_call(ctx.lines, i, m.end())
    v = m["v"]
    pref = ctx.prefix_for(i, None)
    tail = ctx.lines[endj][endcol:] + " " + " ".join(ctx.lines[endj + 1:endj + 3])
    tail = tail.split(";")[0]
    if v in ("resource", "apiResource"):
        name = lit(args[0]) if args else None
        if not name:
            return
        ctrl = arg_handler(args, 1)
        segs = name.strip("/").split(".")
        base = "/".join(f"{s}/{{{singular(s)}}}" for s in segs[:-1]) + ("/" if len(segs) > 1 else "") + segs[-1]
        last = singular(segs[-1])
        mode, names = _only_except(tail)
        for act, meth, suf in _LARAVEL_RES[v]:
            if mode == "only" and act not in names:
                continue
            if mode == "except" and act in names:
                continue
            ctx.add(i, meth, base + suf.replace("{p}", "{" + last + "}"), "laravel", prefix=pref,
                    handler=f"{ctrl}@{act}" if ctrl else act, extra={"resource": name})
        return
    if v in ("resources", "apiResources"):
        for n in all_lits(raw):
            ctx.add(i, "ANY", n, "laravel", prefix=pref, extra={"resource": n})
        return
    if v == "match":
        ms = methods_in(args[0]) if args else []
        path, expr, rej = pick_path(args[1:], need_slash=False)
        meth = ",".join(ms) or "ANY"
    else:
        meth = {"any": "ANY", "view": "GET", "redirect": "GET", "fallback": "GET"}.get(v, v.upper())
        path, expr, rej = pick_path(args if v != "fallback" else [], need_slash=False)
        if v == "fallback":
            path = "{fallbackPlaceholder}"
    if path is None and expr is None and v != "fallback":
        return
    ctx.add(i, meth, path, "laravel", handler=arg_handler(args, 1), prefix=pref, expr=expr)


@rule(PHP, r"\$(?P<obj>\w+)\s*->\s*(?P<v>get|post|put|patch|delete|options|any|map|head)\s*\(")
def slim_route(ctx, i, m):
    if m["obj"] in ("request", "req", "response", "res", "this", "client", "http", "cache", "session", "input", "headers"):
        return
    args, endj, _, raw = read_call(ctx.lines, i, m.end())
    if m["v"] == "map":
        ms = methods_in(args[0]) if args else []
        path, expr, rej = pick_path(args[1:])
        meth = ",".join(ms) or "ANY"
    else:
        path, expr, rej = pick_path(args)
        meth = "ANY" if m["v"] == "any" else m["v"].upper()
    if rej or (path is None and expr is None) or (path is None and len(args) < 2):
        return
    ctx.add(i, meth, path, "slim/lumen", handler=arg_handler(args, 1), prefix=ctx.prefix_for(i, m["obj"]), expr=expr)


@rule(PHP, r"""(?:#\[\s*Route|@Route)\s*\(""", doc_ok=True)
def symfony_route(ctx, i, m):
    if i in ctx.class_lines:
        return
    args, endj, endcol, raw = read_call(ctx.lines, i, m.end())
    path, expr, rej = pick_path(args, need_slash=False, kws=("path", "value"))
    ms = methods_in(re.sub(r".*methods\s*[:=]", "", raw, flags=re.S)) if "methods" in raw else []
    cp = ctx.class_prefix(i)
    ctx.add(i, ",".join(ms) or "ANY", path if path is not None else "", "symfony",
            handler=sig_handler(ctx.lines, endj + 1, 0), prefix=cp[0] if cp else None, expr=expr,
            extra={"controller": cp[1]} if cp and cp[1] else None)


@rule(PHP, r"register_rest_route\s*\(")
def wp_rest(ctx, i, m):
    args, endj, _, raw = read_call(ctx.lines, i, m.end())
    if len(args) < 2:
        return
    ns, rt = lit(args[0]), lit(args[1])
    if ns is None or rt is None:
        return
    ms = methods_in(raw)
    if not ms and re.search(r"READABLE", raw):
        ms = ["GET"]
    ctx.add(i, ",".join(ms) or "ANY", f"/wp-json/{ns.strip('/')}/{rt.strip('/')}", "wordpress")


@rule(PHP, r"""add_action\s*\(\s*['"]wp_ajax_(?:nopriv_)?(?P<a>\w+)['"]""")
def wp_ajax(ctx, i, m):
    ctx.add(i, "POST,GET", f"/wp-admin/admin-ajax.php?action={m['a']}", "wordpress",
            extra={"unauthenticated": "nopriv" in m.group(0)})


def php_script_route(ctx):
    if ctx.ext not in PHP:
        return
    gets = posts = other = 0
    first = None
    keys = []
    for i, l in enumerate(ctx.lines):
        if len(l) > 3000:
            continue
        for mm in re.finditer(r"\$_(GET|POST|REQUEST|FILES|COOKIE)\s*\[\s*['\"]?(\w*)", l):
            if ctx.mask[i]:
                continue
            first = i if first is None else first
            if mm.group(1) == "GET":
                gets += 1
            elif mm.group(1) == "POST":
                posts += 1
            else:
                other += 1
            if mm.group(2) and mm.group(2) not in keys and len(keys) < 15:
                keys.append(mm.group(2))
        if first is None and re.search(r"\$_(GET|POST|REQUEST)\b|filter_input\s*\(\s*INPUT_(GET|POST)|REQUEST_METHOD", l) and not ctx.mask[i]:
            first = i
    if first is None:
        return
    meth = "ANY" if (other or (gets and posts) or not (gets or posts)) else ("GET" if gets else "POST")
    ctx.add(first, meth, "/" + ctx.rel, "php-script", kind="file", extra={"inputs": keys, "file_route": True})


# --------------------------------------------------------------------------- JAVA / KOTLIN / SCALA
@rule(JAVA | KT, r"^\s*@(?P<v>Get|Post|Put|Delete|Patch|Request)Mapping\b\s*(?P<paren>\()?")
def spring_mapping(ctx, i, m):
    if i in ctx.class_lines:
        return
    if m["paren"]:
        args, endj, endcol, raw = read_call(ctx.lines, i, m.end())
    else:
        args, endj, endcol, raw = [], i, m.end(), ""
    path, expr, rej = pick_path(args, need_slash=False, kws=("value", "path"))
    v = m["v"]
    if v == "Request":
        ms = re.findall(r"RequestMethod\.(\w+)", raw)
        meth = ",".join(dict.fromkeys(x.upper() for x in ms)) or "ANY"
    else:
        meth = v.upper()
    cp = ctx.class_prefix(i)
    ctx.add(i, meth, path if path is not None else "", "spring", handler=sig_handler(ctx.lines, endj, endcol),
            prefix=cp[0] if cp else None, expr=expr, extra={"controller": cp[1]} if cp and cp[1] else None)


@rule(JAVA | KT, r"^\s*@(?P<v>GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b(?!\w)")
def jaxrs_verb(ctx, i, m):
    path = None
    for k in range(max(0, i - 6), min(len(ctx.lines), i + 7)):
        if k in ctx.jaxrs_paths and k not in ctx.used_aux and k not in ctx.class_lines:
            path = ctx.jaxrs_paths[k]
            ctx.used_aux.add(k)
            break
    cp = ctx.class_prefix(i)
    ctx.add(i, m["v"], path if path is not None else "", "jax-rs", handler=sig_handler(ctx.lines, i, m.end()),
            prefix=cp[0] if cp else None, extra={"controller": cp[1]} if cp and cp[1] else None)


@rule(JAVA | KT | SCALA | GROOVY | RB | EX | PL | LUA,
      r"""^\s*(?:Spark\.|\w+\.)?(?P<v>get|post|put|patch|delete|head|options)\s*\(?\s*(?P<q>['"])(?P<p>[^'"]*)(?P=q)""")
def bare_verb(ctx, i, m):
    p = m["p"]
    line = ctx.lines[i]
    if not (p.startswith("/") or re.search(r"\bdo\b|\{\s*$|->|=>", line)):
        return
    if m.group(0).strip().split("(")[0].split(".")[0] in ("client", "http", "request"):
        return
    if ctx.ext in RB:
        fw = "sinatra/grape"
    elif ctx.ext in EX:
        fw = "phoenix"
    else:
        fw = fw_guess(ctx, JAVA_FW, "bare-verb")
    pref = ctx.prefix_for(i, None) if ctx.ext in KT else None
    ctx.add(i, m["v"].upper(), p, fw, prefix=pref)


@rule(KT, r"""^\s*route\s*\(\s*"(?P<p>[^"]*)"\s*\)\s*\{""")
def ktor_route_scope(ctx, i, m):
    pass  # handled in prepass (scopes)


# --------------------------------------------------------------------------- C#
@rule(CS, r"\[\s*(?P<v>HttpGet|HttpPost|HttpPut|HttpPatch|HttpDelete|HttpHead|HttpOptions|AcceptVerbs)\b(?P<paren>\()?")
def cs_http(ctx, i, m):
    if m["paren"]:
        args, endj, endcol, raw = read_call(ctx.lines, i, m.end())
    else:
        args, endj, endcol, raw = [], i, m.end(), ""
    if m["v"] == "AcceptVerbs":
        meth = ",".join(methods_in(raw)) or "ANY"
        path, expr, rej = None, None, False
    else:
        meth = m["v"][4:].upper()
        path, expr, rej = pick_path(args, need_slash=False, kws=("Template", "template"))
    if path is None:
        for k in range(max(0, i - 3), min(len(ctx.lines), i + 4)):
            if k in ctx.cs_routes and k not in ctx.class_lines and k not in ctx.used_aux:
                path = ctx.cs_routes[k]
                ctx.used_aux.add(k)
                break
    cp = ctx.class_prefix(i)
    pref = cp[0] if cp else None
    if pref and cp[1]:
        pref = pref.replace("[controller]", re.sub(r"Controller$", "", cp[1]))
    ctx.add(i, meth, path if path is not None else "", "aspnet", handler=sig_handler(ctx.lines, endj, endcol),
            prefix=pref, expr=expr, extra={"controller": cp[1]} if cp and cp[1] else None)


@rule(CS, r"(?P<obj>[\w.]*)\.Map(?P<v>Get|Post|Put|Patch|Delete|Methods)\s*\(")
def cs_minimal(ctx, i, m):
    args, endj, _, raw = read_call(ctx.lines, i, m.end())
    path, expr, rej = pick_path(args, need_slash=False)
    if rej and path is None:
        return
    meth = m["v"].upper() if m["v"] != "Methods" else (",".join(methods_in(raw)) or "ANY")
    ctx.add(i, meth, path, "aspnet-minimal", handler=arg_handler(args, 1),
            prefix=ctx.prefix_for(i, m["obj"]) if m["obj"] else None, expr=expr)


@rule(CS, r"\.Map(?:Hub<[^>]*>|ControllerRoute|HttpRoute|Route)\s*\(")
def cs_other_map(ctx, i, m):
    args, endj, _, raw = read_call(ctx.lines, i, m.end())
    p = kwarg(args, "pattern") or kwarg(args, "routeTemplate")
    path = lit(p) if p else (pick_path(args, need_slash=False)[0])
    hub = "Hub" in m.group(0)
    ctx.add(i, "WS" if hub else "ANY", path, "aspnet", kind="ws" if hub else "convention",
            extra={"note": "convention-based route"})


@rule(CS, r"\[\s*(?:WebGet|WebInvoke)\b")
def cs_wcf(ctx, i, m):
    j = ctx.lines[i].index("[", m.start())
    pc = ctx.lines[i].find("(", m.end())
    if pc < 0:
        return
    args, endj, _, raw = read_call(ctx.lines, i, pc + 1)
    um = re.search(r"""UriTemplate\s*=\s*"([^"]*)\"""", raw)
    mm = re.search(r"""Method\s*=\s*"(\w+)\"""", raw)
    ctx.add(i, (mm.group(1).upper() if mm else ("GET" if "WebGet" in m.group(0) else "POST")),
            um.group(1) if um else "", "wcf", handler=sig_handler(ctx.lines, endj, 0))


# --------------------------------------------------------------------------- RUST / PLAY / GENERIC
@rule(RS, r"""^\s*#\[\s*(?P<v>get|post|put|patch|delete|head|options)\s*\(\s*"(?P<p>[^"]*)\"""")
def rust_attr(ctx, i, m):
    ctx.add(i, m["v"].upper(), m["p"], "actix/rocket", handler=sig_handler(ctx.lines, i + 1, 0))


@rule(RS, r"""\.route\s*\(\s*"(?P<p>[^"]*)"\s*,\s*(?P<v>get|post|put|patch|delete|any|head|options)\s*\(""")
def rust_axum(ctx, i, m):
    ctx.add(i, "ANY" if m["v"] == "any" else m["v"].upper(), m["p"], "axum")


@rule(RS, r"""web::resource\s*\(\s*"(?P<p>[^"]*)\"""")
def rust_actix_resource(ctx, i, m):
    ms = [x.upper() for x in re.findall(r"web::(get|post|put|patch|delete)\(\)", " ".join(ctx.lines[i:i + 6]))]
    ctx.add(i, ",".join(dict.fromkeys(ms)) or "ANY", m["p"], "actix")


# generic fallback: <anything>.<verb-ish>( "/path" ...  -- used only if nothing else matched the line
_GENERIC_RX = (r"""(?:(?P<obj>[\w$.@]+)\.)?(?P<v>get|post|put|patch|delete|any|all|route|handle|handlefunc|"""
               r"""add_route|addroute|connect|options|head)\w{0,6}\s*\(?\s*(?:\w+\s*,\s*)?['"`](?P<p>/[\w\-./{}:<>\[\]*$%@+~]*)['"`]""")


@rule(SRC_EXT, _GENERIC_RX, fallback=True, flags=re.I)
def generic_fallback(ctx, i, m):
    obj = m["obj"] or ""
    if obj.split(".")[-1].lower() in CLIENT_RECV:
        return
    if len(m["p"]) < 2:
        return
    ln = ctx.lines[i]
    if re.search(r"Replace|Trim|Split|Join|Sprintf|Contains|HasPrefix|\bfunc\s*\(|=>\s*\{?\s*$", ln) and m["v"].lower() in ("route", "handle"):
        return
    if re.search(r"Replace|Trim|Split|Sprintf|HasPrefix", ln):
        return
    if m["v"].lower() == "route" and re.search(r"\bfunc\s*\(|\bdo\b|=>", ln):
        return
    v = m["v"].lower()
    meth = v.upper() if v in VERB_LIST_LOWER else "ANY"
    ctx.add(i, meth, m["p"], "generic", extra={"confidence": "low"})


# --------------------------------------------------------------------------- Play conf/routes
PLAY_RX = re.compile(r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|\*)\s+(/\S*)\s+(\S+)")


def play_routes(ctx):
    for i, l in enumerate(ctx.lines):
        m = PLAY_RX.match(l)
        if m:
            ctx.add(i, "ANY" if m.group(1) == "*" else m.group(1), m.group(2), "play", handler=m.group(3))


# --------------------------------------------------------------------------- Rails
def rails_routes(ctx):
    stack = []   # dicts: indent, base, nested, kind
    lines = ctx.lines

    def compose(extra_kind=None):
        out = ""
        for k, e in enumerate(stack):
            nxt = stack[k + 1] if k + 1 < len(stack) else None
            if e["kind"] == "res" and nxt is not None and nxt["kind"] == "member":
                out += e["base"] + "/:id"
            elif e["kind"] == "res" and nxt is not None and nxt["kind"] == "collection":
                out += e["base"]
            elif e["kind"] in ("member", "collection"):
                continue
            else:
                out += e["nested"]
        return out

    def symstr(t):
        m = re.match(r"""\s*(?::(\w+)|(['"])([^'"]*)\2)""", t)
        if not m:
            return None
        return m.group(1) or m.group(3)

    for i, line in enumerate(lines):
        if ctx.mask[i]:
            continue
        s = line.strip()
        if not s:
            continue
        indent = len(line) - len(line.lstrip())
        if re.match(r"end\b", s):
            if stack and stack[-1]["indent"] >= indent:
                stack.pop()
            continue
        opens = bool(re.search(r"\bdo\s*(\|[^|]*\|)?\s*$", s))
        m = re.match(r"(namespace|scope)\b\s*\(?\s*(.*)", s)
        if m:
            rest = m.group(2)
            seg = ""
            if m.group(1) == "namespace":
                nm = symstr(rest)
                pm = re.search(r"\bpath:\s*(?::(\w+)|['\"]([^'\"]*)['\"])", rest)
                seg = "/" + ((pm.group(1) or pm.group(2)) if pm else (nm or "")).strip("/")
            else:
                pm = re.search(r"\bpath:\s*(?::(\w+)|['\"]([^'\"]*)['\"])", rest)
                if pm:
                    seg = "/" + (pm.group(1) or pm.group(2)).strip("/")
                elif re.match(r"""\s*(['"])(.*?)\1""", rest) and not rest.lstrip().startswith(("module:", "as:")):
                    seg = "/" + symstr(rest).strip("/") if symstr(rest) else ""
                    seg = seg.replace("(", "(")
            if opens:
                stack.append({"indent": indent, "base": seg, "nested": seg, "kind": "scope"})
            continue
        m = re.match(r"(resources|resource)\b\s*\(?\s*(.*)", s)
        if m:
            rest = m.group(2)
            singular_res = m.group(1) == "resource"
            names = re.findall(r":(\w+)", rest.split("only:")[0].split("except:")[0].split("do")[0].split("path:")[0].split("controller:")[0]) \
                if not re.match(r"""\s*['"]""", rest) else [symstr(rest)]
            names = [n for n in names if n and n not in ("only", "except", "path", "controller", "as", "module", "constraints", "param", "defaults", "format", "shallow")][:6]
            if not names:
                continue
            om = re.search(r"\b(only|except):\s*(\[[^\]]*\]|:\w+)", rest)
            mode, acts = (om.group(1), set(re.findall(r"(\w+)", om.group(2)))) if om else (None, set())
            pm = re.search(r"\bpath:\s*(?::(\w+)|['\"]([^'\"]*)['\"])", rest)
            # `controller:` overrides which controller handles the resource; `param:` renames :id
            cm = re.search(r"\bcontroller:\s*(?::(\w+)|['\"]([^'\"]*)['\"])", rest)
            ctrl = (cm.group(1) or cm.group(2)) if cm else None
            prm = re.search(r"\bparam:\s*(?::(\w+)|['\"](\w+)['\"])", rest)
            idp = ":" + (prm.group(1) or prm.group(2)) if prm else ":id"
            for nm in names:
                seg = (pm.group(1) or pm.group(2)) if pm else nm
                base = compose() + "/" + seg.strip("/")
                table = ([("index", "GET", ""), ("create", "POST", ""), ("new", "GET", "/new"), ("show", "GET", "/:id"),
                          ("edit", "GET", "/:id/edit"), ("update", "PATCH,PUT", "/:id"), ("destroy", "DELETE", "")]
                         if not singular_res else
                         [("show", "GET", ""), ("create", "POST", ""), ("new", "GET", "/new"), ("edit", "GET", "/edit"),
                          ("update", "PATCH,PUT", ""), ("destroy", "DELETE", "")])
                for act, meth, suf in table:
                    if mode == "only" and act not in acts:
                        continue
                    if mode == "except" and act in acts:
                        continue
                    if not singular_res and act == "destroy":
                        suf = "/:id"
                    suf = suf.replace("/:id", "/" + idp)
                    ctx.add(i, meth, base + suf, "rails", handler=f"{ctrl or nm}#{act}", extra={"resource": nm})
            if opens:
                nm = names[0]
                base = "/" + ((pm.group(1) or pm.group(2)) if pm else nm).strip("/")
                nested = base if singular_res else f"{base}/:{singular(nm)}_id"
                stack.append({"indent": indent, "base": base, "nested": nested, "kind": "res"})
            continue
        m = re.match(r"(member|collection)\s+do\b", s)
        if m:
            stack.append({"indent": indent, "base": "", "nested": "", "kind": m.group(1)})
            continue
        m = re.match(r"(get|post|put|patch|delete|match|options|head)\b\s*\(?\s*(.*)", s)
        if m:
            verb, rest = m.group(1), m.group(2)
            path = symstr(rest)
            hm = re.search(r"""(?:to:\s*|=>\s*)['"]([^'"]*#[^'"]*)['"]|['"](\w+#\w+)['"]""", " ".join(lines[i:i + 3]))
            h = (hm.group(1) or hm.group(2)) if hm else None
            if path is None:
                if verb != "match":
                    continue
            if verb == "match":
                vm = re.search(r"via:\s*(\[[^\]]*\]|:\w+)", " ".join(lines[i:i + 3]))
                meth = ",".join(x.upper() for x in re.findall(r"(\w+)", vm.group(1))) if vm else "ANY"
                if meth == "ALL":
                    meth = "ANY"
            else:
                meth = verb.upper()
            on = re.search(r"\bon:\s*:(\w+)", rest)
            base = compose()
            if on and stack and stack[-1]["kind"] == "res":
                base = compose() if on.group(1) == "collection" else stack[-1]["base"].join(["", ""]) and (
                    compose()[: len(compose()) - len(stack[-1]["nested"])] + stack[-1]["base"] + "/:id")
            if path is not None:
                if "=>" in rest.split(",")[0]:
                    path = symstr(rest)
                ctx.add(i, meth, base + "/" + path.lstrip("/"), "rails", handler=h)
            continue
        m = re.match(r"root\b\s*\(?\s*(.*)", s)
        if m:
            hm = re.search(r"""['"]([^'"]*#[^'"]*)['"]""", s)
            ctx.add(i, "GET", compose() + "/", "rails", handler=hm.group(1) if hm else None)
            continue
        m = re.match(r"mount\b\s*\(?\s*(.*)", s)
        if m:
            pm = re.search(r"""(?:at:\s*|=>\s*)['"]([^'"]*)['"]""", s)
            hm = re.match(r"([\w:]+)", m.group(1))
            ctx.add(i, "ANY", compose() + "/" + (pm.group(1).strip("/") if pm else ""), "rails",
                    handler=hm.group(1) if hm else None, extra={"note": "mounted engine/rack app"})
            continue
        m = re.match(r"devise_for\s+:(\w+)", s)
        if m:
            ctx.add(i, "ANY", compose() + "/" + m.group(1), "rails-devise", extra={"note": "devise routes"})
            continue
        if opens:
            stack.append({"indent": indent, "base": "", "nested": "", "kind": "other"})


# --------------------------------------------------------------------------- prepass: prefixes & scopes
def prepass(ctx):
    L, ext = ctx.lines, ctx.ext
    n = len(L)
    for i in range(n):
        l = L[i]
        if ctx.mask[i] == 1 or len(l) > 3000:
            continue
        # ---- Python routers / blueprints
        if ext in PY:
            m = re.match(r"^\s*(\w+)\s*(?::[^=]+)?=\s*(?:[\w.]+\.)?(APIRouter|Blueprint|Router|Namespace|Api)\s*\(", l)
            if m:
                args, _, _, _ = read_call(L, i, m.end())
                for kn in ("prefix", "url_prefix", "path"):
                    kv = kwarg(args, kn)
                    s = lit(kv) if kv else None
                    if s:
                        ctx.var_prefix[m.group(1)] = s
                        ctx.add_prefix("var", s, i, name=m.group(1))
                        break
            for mm in re.finditer(r"\.(?:include_router|register_blueprint|add_namespace|mount)\s*\(", l):
                args, _, _, _ = read_call(L, i, mm.end())
                pv = kwarg(args, "prefix") or kwarg(args, "url_prefix") or kwarg(args, "path")
                s = lit(pv) if pv else (lit(args[0]) if "mount" in mm.group(0) and args else None)
                if s:
                    ctx.add_prefix("mount", s, i, target=(args[0].strip()[:60] if args else None))
        # ---- Go groups / chi closures
        elif ext in GO:
            m = re.search(r"""(\w+)\s*:?=\s*([\w.]+)\.(?:Group|Route|PathPrefix|Mount|Subrouter|With)\(\s*"([^"]*)\"""", l)
            if m and not re.search(r"\.Route\(\s*\"[^\"]*\"\s*,\s*func", l):
                par = ctx.prefix_for(i, m.group(2)) or ""
                full = join_path(par, m.group(3))
                ctx.var_prefix[m.group(1)] = full
                ctx.add_prefix("group", m.group(3), i, name=m.group(1))
            m = re.search(r"""([\w.]+)\.Route\(\s*"([^"]*)"\s*,\s*func\(\s*(\w+)""", l)
            if m:
                par = ctx.prefix_for(i, m.group(1)) or ""
                full = join_path(par, m.group(2))
                ctx.scopes.append({"start": i, "end": block_end(L, i), "var": m.group(3), "prefix": full})
                ctx.add_prefix("group", m.group(2), i, name=m.group(3))
            m = re.search(r"""([\w.]+)\.Mount\(\s*"([^"]*)"\s*,\s*([^)]*)\)""", l)
            if m:
                ctx.add_prefix("mount", m.group(2), i, target=m.group(3).strip()[:60])
            m = re.search(r"""\b(\w+)\s*:?=\s*[\w.]+\.PathPrefix\(\s*"([^"]*)"\s*\)\s*\.Subrouter""", l)
        # ---- C# MapGroup
        elif ext in CS:
            m = re.search(r"""(?:var\s+)?(\w+)\s*=\s*([\w.]+)\.MapGroup\(\s*"([^"]*)\"""", l)
            if m:
                par = ctx.var_prefix.get(m.group(2).split(".")[-1], "")
                ctx.var_prefix[m.group(1)] = join_path(par, m.group(3))
                ctx.add_prefix("group", m.group(3), i, name=m.group(1))
        # ---- PHP groups
        elif ext in PHP:
            win = " ".join(L[i:i + 4])
            m = re.search(r"""Route::prefix\(\s*['"]([^'"]*)['"]\s*\)""", l) or \
                re.search(r"""->prefix\(\s*['"]([^'"]*)['"]\s*\)""", l) or \
                re.search(r"""['"]prefix['"]\s*=>\s*['"]([^'"]*)['"]""", l)
            if m and re.search(r"function|group\s*\(", win):
                start = next((k for k in range(i, min(n, i + 4)) if "{" in L[k]), None)
                if start is not None:
                    ctx.scopes.append({"start": i, "end": block_end(L, start), "var": None, "prefix": m.group(1)})
                    ctx.add_prefix("group", m.group(1), i)
            m = re.search(r"""\$(\w+)\s*->\s*group\s*\(\s*['"]([^'"]*)['"]\s*,\s*function\s*\(\s*(?:[\w\\]+\s+)?\$(\w+)""", l)
            if m:
                par = ctx.prefix_for(i, m.group(1)) or ""
                ctx.scopes.append({"start": i, "end": block_end(L, i), "var": m.group(3), "prefix": join_path(par, m.group(2))})
                ctx.add_prefix("group", m.group(2), i, name=m.group(3))
        elif ext in KT:
            m = re.match(r"""^\s*route\s*\(\s*"([^"]*)"\s*\)\s*\{""", l)
            if m:
                ctx.scopes.append({"start": i, "end": block_end(L, i), "var": None, "prefix": m.group(1)})
                ctx.add_prefix("group", m.group(1), i)

    # ---- class-level prefixes (annotation based)
    cls_rx = None
    if ext in JS | JAVA | KT:
        cls_rx = re.compile(r"^\s*@(?P<k>Controller|RequestMapping|Path|ApplicationPath)\s*(?P<paren>\()?")
    elif ext in PHP:
        cls_rx = re.compile(r"(?:#\[\s*(?P<k>Route)|@(?P<k2>Route))\s*\(")
    elif ext in CS:
        cls_rx = re.compile(r"\[\s*(?P<k>Route|Area)\s*(?P<paren>\()?")
    if cls_rx:
        for i in range(n):
            if ctx.mask[i] == 1 or (ctx.mask[i] == 2 and ext not in PHP) or len(L[i]) > 3000:
                continue
            m = cls_rx.search(L[i]) if ext in CS or ext in PHP else cls_rx.match(L[i])
            if not m:
                continue
            k = m.group("k") if "k" in cls_rx.groupindex and m.group("k") else "Route"
            if ext in JS | JAVA | KT and k == "Controller" and ext in JAVA | KT and not m.group("paren"):
                continue
            if m.re.groupindex.get("paren") and not m.group("paren") and k != "RequestMapping":
                continue
            args, endj, endcol, raw = read_call(L, i, m.end() if (m.re.groupindex.get("paren") is None or m.group("paren")) else m.end())
            s = None
            if k in ("Controller", "RequestMapping", "Path", "ApplicationPath", "Route"):
                s, _, _ = pick_path(args, need_slash=False, kws=("path", "value"))
                if s is None and k == "Controller":
                    pm = re.search(r"""\bpath\s*:\s*['"`]([^'"`]*)""", raw)
                    s = pm.group(1) if pm else None
            isclass, cname = _is_class_level(L, endj, endcol)
            if isclass:
                ctx.class_lines.add(i)
                if s is not None and k != "Area":
                    ctx.classes.append((i, s, cname))
                    ctx.add_prefix("class", s, i, name=cname)
                elif k == "Controller" and ext in JS:
                    ctx.classes.append((i, "", cname))
            else:
                if k == "Path" and s is not None:
                    ctx.jaxrs_paths[i] = s
                if k == "Route" and ext in CS and s is not None:
                    ctx.cs_routes[i] = s


_CLASS_RX = re.compile(r"\b(?:class|interface|object|record|struct)\s+([A-Za-z_]\w*)")
_MODIFIER_START = re.compile(r"^\s*(?:public|private|protected|internal|static|fun|suspend|async|def|function|abstract|final|open|override|virtual|sealed|partial|export|const|readonly)\b")


def _is_class_level(lines, endj, endcol):
    rest = lines[endj][endcol:]
    for k in range(endj, min(len(lines), endj + 9)):
        t = (rest if k == endj else lines[k]).strip()
        if not t:
            continue
        mm = _CLASS_RX.search(t)
        if mm and not t.startswith(("//", "*", "/*")):
            return True, mm.group(1)
        if t.startswith(("@", "[", "#[", "//", "*", "/*", ")", '"', "'", "}", "{")) or t.endswith(("(", ",")):
            continue
        if _MODIFIER_START.match(t) or "(" in t:
            return False, None
    return False, None


def finalize_aux(ctx):
    """Un-consumed method-level @Path / [Route]: emit as UNKNOWN candidates."""
    for ln, p in ctx.jaxrs_paths.items():
        if ln not in ctx.used_aux:
            cp = ctx.class_prefix(ln)
            ctx.add(ln, "UNKNOWN", p, "jax-rs", handler=sig_handler(ctx.lines, ln + 1, 0),
                    prefix=cp[0] if cp else None, extra={"note": "sub-resource locator or verb annotation elsewhere"})
    for ln, p in ctx.cs_routes.items():
        if ln not in ctx.used_aux:
            cp = ctx.class_prefix(ln)
            pref = cp[0].replace("[controller]", re.sub(r"Controller$", "", cp[1] or "")) if cp else None
            ctx.add(ln, "UNKNOWN", p, "aspnet", handler=sig_handler(ctx.lines, ln + 1, 0), prefix=pref)


# --------------------------------------------------------------------------- scanning
def scan_file(rel, text, ext, include_comments):
    lines = text.split("\n")
    ctx = Ctx(rel, text, lines, ext)
    ctx.mask = comment_mask(lines, ext)
    base = os.path.basename(rel)

    # file-as-route languages
    if ext in FILEROUTE:
        if ext in ("ashx", "asmx") or re.search(
                r"request\.getParameter|Request\.(QueryString|Form|Params)|Request\[|\$_(GET|POST)|CGI|param\(", text, re.I):
            ctx.add(0, "ANY", "/" + rel, "file-route:" + ext, kind="file", extra={"file_route": True})
        return ctx
    if re.search(r"(^|/)conf/routes$|\.routes$", rel) or base == "routes" and "conf" in rel:
        play_routes(ctx)
        return ctx
    if ext in RB and re.search(r"(^|/)config/routes(\.rb|/.+\.rb)$", rel):
        rails_routes(ctx)
        return ctx

    prepass(ctx)
    file_routes(ctx)

    rules = [r for r in RULES if ext in r.exts]
    primary = [r for r in rules if not r.fallback]
    fallback = [r for r in rules if r.fallback]
    for i, line in enumerate(lines):
        mk = ctx.mask[i]
        if len(line) > 3000 or not line.strip():
            continue
        if mk == 1 and not include_comments:
            continue
        for r in primary:
            if mk == 2 and not (r.doc_ok or include_comments):
                continue
            for m in r.rx.finditer(line) if r.fn in _MULTI else _one(r.rx.search(line)):
                r.fn(ctx, i, m)
        if i not in ctx.lines_hit and (mk == 0 or include_comments):
            for r in fallback:
                m = r.rx.search(line)
                if m:
                    r.fn(ctx, i, m)
    finalize_aux(ctx)
    if ext in PHP:
        php_script_route(ctx)
    if include_comments:
        for d in ctx.out:
            if ctx.mask[d["line"] - 1]:
                d["in_comment"] = True
    return ctx


_MULTI = set()


def _one(m):
    return [m] if m else []


def should_skip_dir(name, include_tests):
    if name in SKIP_DIRS or name.startswith(".") or name.endswith(".egg-info"):
        return True
    if not include_tests and name.lower() in TEST_DIRS:
        return True
    return False


def walk(root, include_tests):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if not should_skip_dir(d, include_tests))
        for fn in sorted(filenames):
            full = os.path.join(dirpath, fn)
            ext = fn.rsplit(".", 1)[-1].lower() if "." in fn else ""
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            is_play = fn == "routes" and "conf" in rel.split("/")
            if ext not in SRC_EXT and not is_play and not fn.endswith(".routes"):
                continue
            if fn.endswith((".min.js", ".bundle.js", ".d.ts")):
                continue
            if not include_tests and TEST_FILE_RX.search(fn):
                continue
            yield full, rel, ext


def read_text(path):
    try:
        if os.path.islink(path):
            return None
        sz = os.path.getsize(path)
        if sz == 0 or sz >= MAX_SIZE:
            return None
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return None
    if b"\x00" in data[:8192]:
        return None
    text = data.decode("utf-8", errors="replace")
    if sz > 50_000 and sz / (text.count("\n") + 1) > 400:   # minified
        return None
    return text


def main(argv=None):
    ap = argparse.ArgumentParser(description="Framework-agnostic HTTP route candidate finder.")
    ap.add_argument("repo_root")
    ap.add_argument("--json", dest="json_out", help="write full results to this JSON file")
    ap.add_argument("--max-files", type=int, default=0, help="stop after scanning N source files")
    ap.add_argument("--include-tests", action="store_true", help="also scan test/spec dirs and files")
    ap.add_argument("--include-comments", action="store_true",
                    help="keep matches inside comments/docstrings (flagged in_comment)")
    ap.add_argument("--top", type=int, default=60, help="how many candidates to print (default 60)")
    a = ap.parse_args(argv)

    root = os.path.abspath(a.repo_root)
    if not os.path.isdir(root):
        print(f"error: {root} is not a directory", file=sys.stderr)
        return 2
    t0 = time.time()
    cands, files_meta = [], {}
    scanned = 0
    for full, rel, ext in walk(root, a.include_tests):
        if a.max_files and scanned >= a.max_files:
            break
        text = read_text(full)
        if text is None:
            continue
        scanned += 1
        try:
            ctx = scan_file(rel, text, ext, a.include_comments)
        except Exception as e:   # never crash the whole run on one odd file
            print(f"warn: {rel}: {type(e).__name__}: {e}", file=sys.stderr)
            continue
        if ctx.out or ctx.prefix_cands:
            files_meta[rel] = {"prefix_candidates": ctx.prefix_cands}
        cands.extend(ctx.out)

    cands.sort(key=lambda d: (d["file"], d["line"]))
    counts = Counter(d["framework_guess"] for d in cands)
    result = {"repo_root": root, "files_scanned": scanned, "total_candidates": len(cands),
              "counts_by_framework": dict(counts.most_common()),
              "elapsed_sec": round(time.time() - t0, 2), "files": files_meta, "candidates": cands}
    if a.json_out:
        os.makedirs(os.path.dirname(os.path.abspath(a.json_out)), exist_ok=True)
        with open(a.json_out, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)

    print(f"repo: {root}")
    print(f"files scanned: {scanned}   total candidates: {len(cands)}   ({result['elapsed_sec']}s)")
    print("by framework_guess:")
    for k, v in counts.most_common():
        print(f"  {k:24s} {v}")
    print(f"first {min(a.top, len(cands))}:")
    for d in cands[:a.top]:
        print(f"  {d['method']:8s} {d['path'] if d['path'] is not None else '(unknown)'}  {d['file']}:{d['line']}")
    if a.json_out:
        print(f"json written: {a.json_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
