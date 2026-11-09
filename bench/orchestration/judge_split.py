"""Orchestration helper: split a target's packs into groups of <= N for parallel blind judges, then merge.

  python judge_split.py split <T/tid> [N]   -> T/tid/v2/jNN/packs/suspect_*.md
  python judge_split.py merge <T/tid>       -> concatenates T/tid/v2/jNN/judge.txt into T/tid/v2/judge.txt
"""
import shutil
import sys
from pathlib import Path

cmd, t = sys.argv[1], Path(sys.argv[2])
v2 = t / "v2"
if cmd == "split":
    n = int(sys.argv[3]) if len(sys.argv) > 3 else 25
    packs = sorted((v2 / "packs").glob("suspect_*.md"))
    for old in v2.glob("j[0-9][0-9]"):
        shutil.rmtree(old)
    for g, i in enumerate(range(0, len(packs), n), 1):
        d = v2 / f"j{g:02d}" / "packs"
        d.mkdir(parents=True)
        for p in packs[i:i + n]:
            shutil.copy(p, d / p.name)
        print(d)
else:
    lines = []
    for j in sorted(v2.glob("j[0-9][0-9]")):
        f = j / "judge.txt"
        if not f.exists():
            sys.exit(f"missing {f}")
        lines += [l for l in f.read_text().splitlines() if l.strip()]
    (v2 / "judge.txt").write_text("\n".join(lines) + "\n")
    print(f"merged {len(lines)} judge lines")
