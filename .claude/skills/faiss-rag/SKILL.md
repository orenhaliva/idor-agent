---
name: faiss-rag
description: Build and query the local FAISS RAG index of a repository (local code embeddings, no API). Use before an IDOR check, or whenever semantic code search over a repo is needed.
---

# Local RAG over a repo (FAISS)

`tools/rag.py`: the embedding model runs locally (`jinaai/jina-embeddings-v2-base-code`, via fastembed/ONNX on CPU).
The index is FAISS `IndexFlatIP` on normalised vectors, so search is exact cosine similarity and the same
query on the same index always returns the same results.

## Build
```bash
.venv/bin/python -I tools/rag.py index <repo_root> --out .cache/<name>
```
- Indexes code (py, js/ts, go, php, java/kt, rb, cs, rs, ...) and text/config (md, sql, yaml, json, prisma, ...).
  It skips node_modules, vendor, build, dist, .git and virtualenvs, plus files over 600 KB.
- Chunking: Python by AST (function, method, class header, module glue). Other languages split at
  function/class-looking lines, with 60-line windows as the fallback.
- Time: about 3k chunks takes about 6-7 min on a laptop CPU. The first run downloads the model (about 300 MB) to the fastembed cache.
- Output: `repo.faiss`, `chunks.json` (file, start, end, kind, name, text), `meta.json`.
- Run it in the background for big repos, and rebuild after checking out another commit (one index per checkout).

## Query
```bash
.venv/bin/python -I tools/rag.py search .cache/<name> "where is the current user loaded from the token" -k 8
.venv/bin/python -I tools/rag.py search .cache/<name> "delete invoice by id" --json
```
Good queries describe behaviour, not names: "check that the order belongs to the caller",
"query filtered by tenant", "load document by id and return it". Follow up hits with grep and read_lines.

## In code
```python
import sys; sys.path.insert(0, "tools")
from rag import Searcher
s = Searcher(Path(".cache/<name>"))
for h in s.search("ownership check before update", k=6): print(h["file"], h["start"], h["score"])
```
