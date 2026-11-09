"""Read-only code tools exposed to the LLM investigator: grep, read_lines, list_dir, rag_search.

All paths are relative to the repo root and confined to it. Outputs are truncated so a
single tool result can't flood the model's context.
"""
from __future__ import annotations

import re
from pathlib import Path

from rag import SKIP_DIRS, CODE_EXT, TEXT_EXT

MAX_OUT = 6_000  # keeps per-turn input small: history is re-sent every turn (free-tier input-token quotas)


class CodeTools:
    def __init__(self, repo: Path, searcher=None):
        self.repo = repo.resolve()
        self.searcher = searcher

    def _safe(self, rel: str) -> Path:
        p = (self.repo / rel.lstrip("/")).resolve()
        if not str(p).startswith(str(self.repo)):
            raise ValueError("path escapes repo")
        return p

    def _files(self, under: str = "", glob: str | None = None):
        base = self._safe(under or ".")
        it = base.rglob(glob or "*") if base.is_dir() else [base]
        for p in it:
            if p.is_file() and not any(part in SKIP_DIRS for part in p.relative_to(self.repo).parts) \
                    and p.suffix in CODE_EXT | TEXT_EXT and p.stat().st_size < 600_000:
                yield p

    # ---- tools -------------------------------------------------------------------------
    def grep(self, pattern: str, path: str = "", glob: str | None = None, max_hits: int = 60, context: int = 0) -> str:
        try:
            rx = re.compile(pattern)
        except re.error as e:
            return f"invalid regex: {e}"
        out, n = [], 0
        for p in sorted(self._files(path, glob)):
            try:
                lines = p.read_text(errors="replace").splitlines()
            except OSError:
                continue
            for i, l in enumerate(lines):
                if rx.search(l):
                    n += 1
                    if n > max_hits:
                        out.append(f"... more than {max_hits} hits; narrow the pattern or path")
                        return "\n".join(out)[:MAX_OUT]
                    rel = p.relative_to(self.repo)
                    if context:
                        for j in range(max(0, i - context), min(len(lines), i + context + 1)):
                            out.append(f"{rel}:{j + 1}{':' if j == i else '-'} {lines[j][:220]}")
                        out.append("--")
                    else:
                        out.append(f"{rel}:{i + 1}: {l.strip()[:220]}")
        return ("\n".join(out) or "no matches")[:MAX_OUT]

    def read_lines(self, path: str, start: int = 1, end: int | None = None) -> str:
        p = self._safe(path)
        if not p.is_file():
            return f"no such file: {path}"
        lines = p.read_text(errors="replace").splitlines()
        start = max(1, int(start))
        end = min(len(lines), int(end) if end else start + 150)
        if end - start > 200:
            end = start + 200
        body = "\n".join(f"{i}: {lines[i - 1]}" for i in range(start, end + 1))
        return f"{path} lines {start}-{end} of {len(lines)}\n{body}"[:MAX_OUT]

    def list_dir(self, path: str = "", depth: int = 2) -> str:
        base = self._safe(path or ".")
        out = []
        for p in sorted(base.rglob("*")):
            rel = p.relative_to(base)
            if len(rel.parts) > depth or any(part in SKIP_DIRS or part.startswith(".") for part in rel.parts):
                continue
            out.append(("  " * (len(rel.parts) - 1)) + rel.name + ("/" if p.is_dir() else ""))
            if len(out) > 400:
                out.append("...")
                break
        return "\n".join(out)[:MAX_OUT]

    def rag_search(self, query: str, k: int = 6) -> str:
        if not self.searcher:
            return "rag index not available"
        hits = self.searcher.search(query, min(int(k), 10))
        out = []
        for h in hits:
            body = "\n".join(h["text"].splitlines()[:45])
            out.append(f"### {h['file']}:{h['start']}-{h['end']} (sim {h['score']})\n{body}")
        return "\n\n".join(out)[:MAX_OUT]

    # ---- Gemini function declarations -------------------------------------------------
    DECLS = [
        {"name": "grep", "description": "Regex search over repo source files. Returns path:line: text. Use to find definitions, callers, queries, auth checks.",
         "parameters": {"type": "object", "properties": {
             "pattern": {"type": "string", "description": "Python regex"},
             "path": {"type": "string", "description": "optional sub-directory or file to limit the search"},
             "glob": {"type": "string", "description": "optional filename glob, e.g. *.py"},
             "context": {"type": "integer", "description": "lines of context around each hit (0-5)"}},
             "required": ["pattern"]}},
        {"name": "read_lines", "description": "Read a line range of a file (max 300 lines). Use after grep/rag_search to see full functions.",
         "parameters": {"type": "object", "properties": {
             "path": {"type": "string"}, "start": {"type": "integer"}, "end": {"type": "integer"}}, "required": ["path", "start"]}},
        {"name": "rag_search", "description": "Semantic search over the whole repo (FAISS). Good for 'where is X checked', 'model for Y', 'authorization for Z'.",
         "parameters": {"type": "object", "properties": {"query": {"type": "string"}, "k": {"type": "integer"}}, "required": ["query"]}},
        {"name": "list_dir", "description": "List a directory tree (depth 1-3).",
         "parameters": {"type": "object", "properties": {"path": {"type": "string"}, "depth": {"type": "integer"}}}},
    ]

    def call(self, name: str, args: dict) -> str:
        fn = {"grep": self.grep, "read_lines": self.read_lines, "rag_search": self.rag_search, "list_dir": self.list_dir}.get(name)
        if not fn:
            return f"unknown tool {name}"
        try:
            return fn(**{k: v for k, v in (args or {}).items() if v not in (None, "")})
        except Exception as e:  # tool errors go back to the model, not up the stack
            return f"tool error: {type(e).__name__}: {e}"
