"""Check out vuln/fix commits of every case into bench/work/<slug>-{vuln,fix} and build RAG indexes.

  python bench/prepare.py [--cases bench/cases.json] [slug ...]

Reads only slug / commits / analysis_root from the case file (never routes or summaries).
"""
import json, subprocess, sys
from pathlib import Path
B = Path(__file__).resolve().parent
ROOT = B.parent
# analysis root = the server package (whole repo unless it's a monorepo); case files may carry "analysis_root"
ANALYSIS_ROOT = {"filebrowser": ".", "netmaker": ".", "publify": "publify_core", "fat_free_crm": ".",
                 "easyappointments": "application", "xxl-job": "xxl-job-admin", "khoj": "src/khoj",
                 "flowise": "packages/server", "aegra": "libs/aegra-api"}


def load_cases(path: Path) -> list[dict]:
    cases = json.load(open(path))
    for c in cases:
        if c.get("analysis_root"):
            ANALYSIS_ROOT.setdefault(c["slug"], c["analysis_root"])
    return cases


def main():
    args = sys.argv[1:]
    cases_file = B / "cases.json"
    if "--cases" in args:
        i = args.index("--cases"); cases_file = Path(args[i + 1]); args = args[:i] + args[i + 2:]
    cases = load_cases(cases_file)
    for c in cases:
        s = c["slug"]
        if s == "aegra" or (args and s not in args):
            continue
        repo = B / "repos" / s
        for kind in ("vuln", "fix"):
            wt = B / "work" / f"{s}-{kind}"
            if not wt.exists():
                subprocess.run(["git", "-C", str(repo), "worktree", "add", "-f", "--detach", str(wt), c[f"{kind}_commit"]], check=True, capture_output=True)
            root = wt / ANALYSIS_ROOT.get(s, ".")
            idx = ROOT / ".cache" / f"{s}-{kind}"
            if (idx / "repo.faiss").exists():
                print(f"skip {s}-{kind} (indexed)", flush=True); continue
            print(f"== indexing {s}-{kind}: {root}", flush=True)
            subprocess.run([str(ROOT / ".venv/bin/python"), "-I", str(ROOT / "tools/rag.py"), "index", str(root), "--out", str(idx)], check=False)
    print("ALL DONE", flush=True)


if __name__ == "__main__":
    main()
