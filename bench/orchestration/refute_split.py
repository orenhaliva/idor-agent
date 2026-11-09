"""Orchestration helper: split a target's claims.md into groups of <= N for parallel refuters, then merge.

Each group gets its own copy of the target (code/, index/, rag.sh) at <targets>/<tid>r<k>/ with v2/claims.md holding
only its claims (global claim ids kept), so the frozen refuter brief runs unchanged.

  python refute_split.py split <targets> <tid> [N]
  python refute_split.py merge <targets> <tid>
"""
import re
import shutil
import sys
from pathlib import Path

cmd, tdir, tid = sys.argv[1], Path(sys.argv[2]), sys.argv[3]
t = tdir / tid
if cmd == "split":
    n = int(sys.argv[4]) if len(sys.argv) > 4 else 15
    body = (t / "v2" / "claims.md").read_text()
    blocks = ["## " + b for b in re.split(r"^## ", body, flags=re.M)[1:]]
    for old in tdir.glob(f"{tid}r*"):
        shutil.rmtree(old)
    for g, i in enumerate(range(0, len(blocks), n), 1):
        d = tdir / f"{tid}r{g}"
        (d / "v2").mkdir(parents=True)
        shutil.copytree(t / "code", d / "code", symlinks=True)
        shutil.copytree(t / "index", d / "index")
        shutil.copy(t / "rag.sh", d / "rag.sh")
        (d / "v2" / "claims.md").write_text("# Claims to verify\n\n" + "\n".join(blocks[i:i + n]))
        print(d, len(blocks[i:i + n]))
else:
    lines = []
    for d in sorted(tdir.glob(f"{tid}r*"), key=lambda p: int(p.name.split("r")[-1])):
        f = d / "v2" / "refute.txt"
        if not f.exists():
            sys.exit(f"missing {f}")
        lines += [l for l in f.read_text().splitlines() if l.strip()]
    (t / "v2" / "refute.txt").write_text("\n".join(lines) + "\n")
    print(f"merged {len(lines)} refute lines")
