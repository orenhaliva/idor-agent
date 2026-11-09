"""Build RAG indexes for a case file faster: the vuln commit is indexed in full with tools/rag.py, and the fix commit
reuses the vuln commit's vectors for every chunk whose text is unchanged (only changed chunks are embedded).
The output is identical to a full `rag.py index` of the fix commit (same chunking, same model, same normalisation).

  python bench/index_cases.py --cases bench/fresh_cases.json [slug ...]

Reads only slug / commits / analysis_root from the case file.
"""
import json
import subprocess
import sys
from pathlib import Path

B = Path(__file__).resolve().parent
ROOT = B.parent
sys.path.insert(0, str(B)); sys.path.insert(0, str(ROOT / "tools"))
from prepare import ANALYSIS_ROOT, load_cases  # noqa: E402


def chunks_for(root: Path) -> list[dict]:
    import rag
    chunks = []
    for p, rel in rag.iter_files(root):
        try:
            src = p.read_text(errors="strict")
        except (UnicodeDecodeError, OSError):
            continue
        chunks.extend(rag.chunk_python(rel, src) if p.suffix == ".py" else
                      rag.chunk_generic(rel, src) if p.suffix in rag.CODE_EXT else rag.windows(rel, src.splitlines(), 1, "text", rel))
    return chunks


def text_of(c: dict) -> str:  # must match tools/rag.py build()
    return f"# file: {c['file']} lines {c['start']}-{c['end']} ({c['kind']} {c['name']})\n{c['text']}"[:6000]


def incremental(src_idx: Path, root: Path, out: Path):
    import faiss
    import numpy as np
    import rag
    from fastembed import TextEmbedding

    old_chunks = json.loads((src_idx / "chunks.json").read_text())
    old = faiss.read_index(str(src_idx / "repo.faiss"))
    by_text = {text_of(c): i for i, c in enumerate(old_chunks)}
    chunks = chunks_for(root)
    texts = [text_of(c) for c in chunks]
    new_t = sorted({t for t in texts if t not in by_text})
    print(f"{len(chunks)} chunks; reusing {len(texts) - sum(t in set(new_t) for t in texts)}, embedding {len(new_t)}", flush=True)
    fresh = {}
    if new_t:
        v = np.array(list(TextEmbedding(rag.MODEL).embed(new_t, batch_size=16)), dtype="float32")
        faiss.normalize_L2(v)
        fresh = dict(zip(new_t, v))
    vecs = np.stack([fresh[t] if t in fresh else old.reconstruct(by_text[t]) for t in texts]).astype("float32")
    index = faiss.IndexFlatIP(vecs.shape[1]); index.add(vecs)
    out.mkdir(parents=True, exist_ok=True)
    faiss.write_index(index, str(out / "repo.faiss"))
    (out / "chunks.json").write_text(json.dumps(chunks))
    (out / "meta.json").write_text(json.dumps({"repo_root": str(root), "model": rag.MODEL, "chunks": len(chunks)}))
    print(f"index: {index.ntotal} -> {out}", flush=True)


def main():
    args = sys.argv[1:]
    cases_file = B / "cases.json"
    if "--cases" in args:
        i = args.index("--cases"); cases_file = Path(args[i + 1]); args = args[:i] + args[i + 2:]
    for c in load_cases(cases_file):
        s = c["slug"]
        if s == "aegra" or (args and s not in args):
            continue
        for kind in ("vuln", "fix"):
            wt = B / "work" / f"{s}-{kind}"
            if not wt.exists():
                subprocess.run(["git", "-C", str(B / "repos" / s), "worktree", "add", "-f", "--detach", str(wt), c[f"{kind}_commit"]],
                               check=True, capture_output=True)
            root = wt / ANALYSIS_ROOT.get(s, ".")
            idx = ROOT / ".cache" / f"{s}-{kind}"
            if (idx / "repo.faiss").exists():
                print(f"skip {s}-{kind} (indexed)", flush=True); continue
            print(f"== indexing {s}-{kind}: {root}", flush=True)
            src = ROOT / ".cache" / f"{s}-vuln"
            if kind == "fix" and (src / "repo.faiss").exists():
                subprocess.run([str(ROOT / ".venv/bin/python"), "-I", __file__, "--incremental", str(src), str(root), str(idx)], check=False)
            else:
                subprocess.run([str(ROOT / ".venv/bin/python"), "-I", str(ROOT / "tools/rag.py"), "index", str(root), "--out", str(idx)], check=False)
    print("ALL DONE", flush=True)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--incremental":
        incremental(Path(sys.argv[2]), Path(sys.argv[3]), Path(sys.argv[4]))
    else:
        main()
