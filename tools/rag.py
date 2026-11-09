"""Local RAG over a repository: FAISS + local code embeddings. No network after the model download.

  python tools/rag.py index  <repo_root> [--out .cache/<name>]
  python tools/rag.py search <index_dir> "query text" [-k 8] [--json]

Chunking is language-agnostic:
  * Python  -> AST (one chunk per function / method / class header / module glue)
  * others  -> split at lines that look like a function/method/class start in common
               languages; fall back to 60-line windows. Long units are windowed.
Embeddings: jinaai/jina-embeddings-v2-base-code (fastembed / ONNX, CPU).
Index:      FAISS IndexFlatIP on L2-normalised vectors (exact cosine search, deterministic).
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import sys
from pathlib import Path

MODEL = "jinaai/jina-embeddings-v2-base-code"
SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", ".venv", "venv", "__pycache__", "target",
             ".next", ".nuxt", "coverage", ".cache", ".idea", ".vscode", "bower_components", "public/build",
             # translations / locale data: large, never contain authorization logic
             "language", "languages", "lang", "locale", "locales", "i18n", "l10n", "translations"}
# generated / bundled / lock files: no authorization logic, slow to embed
SKIP_FILE = re.compile(r"(\.min\.(js|css)$|\.map$|\.lock$|package-lock\.json$|yarn\.lock$|pnpm-lock\.yaml$|\.bundle\.js$)")
MAX_TEXT_FILE = 150_000  # big json/yaml/xml are usually data dumps
CODE_EXT = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".go", ".php", ".java", ".kt", ".rb", ".cs",
            ".rs", ".scala", ".ex", ".exs", ".erb", ".vue", ".svelte"}
TEXT_EXT = {".md", ".sql", ".toml", ".json", ".yaml", ".yml", ".ini", ".cfg", ".xml", ".prisma", ".graphql", ".proto", ".env.example"}
MAX_FILE = 600_000
WINDOW, OVERLAP, MAX_UNIT = 60, 10, 160

# a line that starts a function / method / class in many languages (heuristic, used only for chunk boundaries)
UNIT_START = re.compile(
    r"^\s*(?:export\s+)?(?:default\s+)?(?:public|private|protected|static|final|abstract|async|override|internal|\s)*"
    r"(?:def |class |func |function\b|fn |interface |struct |module |sub |"
    r"(?:const|let|var)\s+\w+\s*=\s*(?:async\s*)?(?:\([^)]*\)|\w+)\s*=>|"
    r"[\w<>\[\],\s]+\s+\w+\s*\([^;]*\)\s*(?:throws [\w, ]+)?\s*\{?\s*$|"
    r"@\w+(?:Mapping|Route|Get|Post|Put|Patch|Delete)\b|"
    r"(?:get|post|put|patch|delete)\s+['\"/])"
)


def iter_files(root: Path):
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root)
        if any(part in SKIP_DIRS for part in rel.parts) or not p.is_file():
            continue
        if SKIP_FILE.search(p.name):
            continue
        size = p.stat().st_size
        if (p.suffix in CODE_EXT and size <= MAX_FILE) or (p.suffix in TEXT_EXT and size <= MAX_TEXT_FILE):
            yield p, str(rel)


def windows(rel, lines, start_line, kind, name):
    out = []
    for s in range(0, max(len(lines), 1), WINDOW - OVERLAP):
        seg = lines[s:s + WINDOW]
        if "".join(seg).strip():
            out.append(dict(file=rel, start=start_line + s, end=start_line + s + len(seg) - 1, kind=kind, name=name, text="\n".join(seg)))
        if s + WINDOW >= len(lines):
            break
    return out


def chunk_python(rel, src):
    try:
        tree = ast.parse(src)
    except (SyntaxError, ValueError):
        return chunk_generic(rel, src)
    lines, chunks, covered = src.splitlines(), [], set()

    def add(node, kind, name):
        seg = lines[node.lineno - 1:node.end_lineno]
        if len(seg) > MAX_UNIT:
            chunks.extend(windows(rel, seg, node.lineno, kind, name))
        else:
            chunks.append(dict(file=rel, start=node.lineno, end=node.end_lineno, kind=kind, name=name, text="\n".join(seg)))
        covered.update(range(node.lineno, node.end_lineno + 1))

    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            add(node, "function", node.name)
        elif isinstance(node, ast.ClassDef):
            methods = [n for n in node.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
            head_end = (methods[0].lineno - 1) if methods else node.end_lineno
            chunks.append(dict(file=rel, start=node.lineno, end=head_end, kind="class", name=node.name,
                               text="\n".join(lines[node.lineno - 1:head_end])))
            for m in methods:
                add(m, "method", f"{node.name}.{m.name}")
            covered.update(range(node.lineno, node.end_lineno + 1))
    rest = [i for i in range(1, len(lines) + 1) if i not in covered and lines[i - 1].strip()]
    if rest:
        chunks.extend(windows(rel, [lines[i - 1] for i in rest], rest[0], "module", rel))
    return chunks


def chunk_generic(rel, src):
    lines = src.splitlines()
    starts = [i for i, l in enumerate(lines) if UNIT_START.match(l)]
    if len(starts) < 2:
        return windows(rel, lines, 1, "text", rel)
    bounds = ([0] if starts[0] > 0 else []) + starts + [len(lines)]
    chunks = []
    for a, b in zip(bounds, bounds[1:]):
        seg = lines[a:b]
        if not "".join(seg).strip():
            continue
        name = seg[0].strip()[:80]
        if len(seg) > MAX_UNIT:
            chunks.extend(windows(rel, seg, a + 1, "unit", name))
        else:
            chunks.append(dict(file=rel, start=a + 1, end=b, kind="unit", name=name, text="\n".join(seg)))
    # merge tiny neighbours so one-liners don't become noise
    merged = []
    for c in chunks:
        if merged and merged[-1]["file"] == c["file"] and (c["end"] - c["start"]) < 4 and (merged[-1]["end"] - merged[-1]["start"]) < 80:
            m = merged[-1]; m["end"] = c["end"]; m["text"] += "\n" + c["text"]
        else:
            merged.append(c)
    return merged


def build(root: Path, out: Path):
    import faiss
    import numpy as np
    from fastembed import TextEmbedding

    chunks = []
    for p, rel in iter_files(root):
        try:
            src = p.read_text(errors="strict")
        except (UnicodeDecodeError, OSError):
            continue
        chunks.extend(chunk_python(rel, src) if p.suffix == ".py" else
                      chunk_generic(rel, src) if p.suffix in CODE_EXT else windows(rel, src.splitlines(), 1, "text", rel))
    if not chunks:
        sys.exit("no indexable files found")
    texts = [f"# file: {c['file']} lines {c['start']}-{c['end']} ({c['kind']} {c['name']})\n{c['text']}"[:6000] for c in chunks]
    print(f"{len(chunks)} chunks from {len({c['file'] for c in chunks})} files; embedding with {MODEL} (CPU) ...", flush=True)
    vecs = np.array(list(TextEmbedding(MODEL).embed(texts, batch_size=16)), dtype="float32")
    faiss.normalize_L2(vecs)
    index = faiss.IndexFlatIP(vecs.shape[1])
    index.add(vecs)
    out.mkdir(parents=True, exist_ok=True)
    faiss.write_index(index, str(out / "repo.faiss"))
    (out / "chunks.json").write_text(json.dumps(chunks))
    (out / "meta.json").write_text(json.dumps({"repo_root": str(root), "model": MODEL, "chunks": len(chunks)}))
    print(f"index: {index.ntotal} x {vecs.shape[1]}d -> {out}")


class Searcher:
    def __init__(self, index_dir: Path):
        import faiss
        from fastembed import TextEmbedding

        self.faiss = faiss
        self.index = faiss.read_index(str(index_dir / "repo.faiss"))
        self.chunks = json.loads((index_dir / "chunks.json").read_text())
        self.model = TextEmbedding(MODEL)

    def search(self, query: str, k: int = 8):
        import numpy as np

        v = np.array(list(self.model.embed([query])), dtype="float32")
        self.faiss.normalize_L2(v)
        scores, ids = self.index.search(v, k)
        return [dict(score=round(float(s), 3), **self.chunks[i]) for s, i in zip(scores[0], ids[0]) if i >= 0]


def default_out(root: Path) -> Path:
    h = hashlib.sha1(str(root.resolve()).encode()).hexdigest()[:10]
    return Path(__file__).resolve().parent.parent / ".cache" / f"{root.resolve().name}-{h}"


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("index"); a.add_argument("repo"); a.add_argument("--out")
    b = sub.add_parser("search"); b.add_argument("index_dir"); b.add_argument("query"); b.add_argument("-k", type=int, default=8); b.add_argument("--json", action="store_true")
    args = ap.parse_args()
    if args.cmd == "index":
        root = Path(args.repo)
        build(root, Path(args.out) if args.out else default_out(root))
    else:
        hits = Searcher(Path(args.index_dir)).search(args.query, args.k)
        if args.json:
            print(json.dumps(hits, indent=1))
        else:
            for h in hits:
                print(f"--- {h['file']}:{h['start']}-{h['end']}  sim={h['score']}  [{h['kind']} {h['name'][:60]}]")
                print("\n".join(h["text"].splitlines()[:40]))


if __name__ == "__main__":
    main()
