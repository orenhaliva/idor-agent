"""Convention-routing fallback: derive route candidates from controller classes when routes are not declared.

Many frameworks (especially legacy ones) route by convention, /<controller>/<method>/<args...>, so a grep for route
declarations finds nothing. This pass lists public methods of classes that live in controller/handler-style
directories, in any of several languages. Stdlib only. Candidates only: the investigator verifies them.

  python tools/convention_routes.py <root> [--json out.json]
"""
import json
import re
import sys
from pathlib import Path

DIR_RX = re.compile(r"(^|/)(controllers?|handlers?|endpoints?|api|views|actions|resources)(/|$)", re.I)
SKIP = {".git", "node_modules", "vendor", "dist", "build", "test", "tests", "spec", "__pycache__"}
LANG = {
    ".php": (re.compile(r"^\s*(?:abstract\s+|final\s+)?class\s+(\w+)"),
             re.compile(r"^\s*(?:public\s+)?(?:static\s+)?function\s+(\w+)\s*\(([^)]*)\)"),
             re.compile(r"^\s*(?:private|protected)\s+(?:static\s+)?function")),
    ".cs": (re.compile(r"^\s*(?:public\s+)?(?:partial\s+)?class\s+(\w+)"),
            re.compile(r"^\s*public\s+(?:async\s+|virtual\s+|override\s+)*[\w<>\[\],\s]+\s+(\w+)\s*\(([^)]*)\)"), None),
    ".java": (re.compile(r"^\s*(?:public\s+)?(?:abstract\s+)?class\s+(\w+)"),
              re.compile(r"^\s*public\s+(?!class)[\w<>\[\],\s]+\s+(\w+)\s*\(([^)]*)\)"), None),
    ".py": (re.compile(r"^class\s+(\w+)"), re.compile(r"^\s+(?:async\s+)?def\s+(\w+)\s*\(([^)]*)\)"), None),
    ".rb": (re.compile(r"^\s*class\s+(\w+)"), re.compile(r"^\s*def\s+(\w+)\s*\(?([^)]*)\)?"),
            re.compile(r"^\s*(private|protected)\s*$")),
}


def params_of(sig: str, lang: str) -> list[str]:
    out = []
    for p in sig.split(","):
        p = p.strip()
        if not p or p in ("self", "cls"):
            continue
        name = re.findall(r"\$?(\w+)\s*(?:=.*)?$", p.split(":")[0].strip())
        if name and name[0] not in ("self", "cls", "request", "req", "res", "response", "args", "kwargs"):
            out.append(name[0])
    return out[:4]


def scan(root: Path) -> list[dict]:
    cands = []
    for f in sorted(root.rglob("*")):
        rel = f.relative_to(root)
        if not f.is_file() or f.suffix not in LANG or any(p in SKIP for p in rel.parts):
            continue
        if not DIR_RX.search(str(rel.parent).replace("\\", "/") + "/"):
            continue
        class_rx, meth_rx, private_rx = LANG[f.suffix]
        try:
            lines = f.read_text(errors="replace").splitlines()
        except OSError:
            continue
        cls, private_section = None, False
        for i, line in enumerate(lines, 1):
            m = class_rx.match(line)
            if m:
                cls, private_section = m.group(1), False
                continue
            if private_rx and private_rx.match(line):
                if f.suffix == ".rb":
                    private_section = True
                continue
            m = meth_rx.match(line)
            if not (m and cls) or private_section:
                continue
            name = m.group(1)
            if name.startswith("_") or name.lower() in ("construct", "initialize", "init", "dispose", "tostring", "equals", "gethashcode"):
                continue
            ctrl = re.sub(r"(Controller|Handler|Endpoint|Resource|Api|View)$", "", cls)
            # controllers nested in sub-folders keep the folder in the URL (common convention)
            sub = DIR_RX.split(str(rel.parent).replace("\\", "/"))[-1].strip("/")
            prefix = f"/{sub.lower()}" if sub else ""
            path = f"{prefix}/{ctrl.lower()}/{name}" + "".join(f"/{{{p}}}" for p in params_of(m.group(2), f.suffix))
            cands.append({"file": str(rel), "line": i, "method": "ANY", "path": path, "handler_hint": f"{cls}.{name}",
                          "framework_guess": "convention-routing", "path_params": params_of(m.group(2), f.suffix)})
    return cands


if __name__ == "__main__":
    root = Path(sys.argv[1])
    c = scan(root)
    if "--json" in sys.argv:
        Path(sys.argv[sys.argv.index("--json") + 1]).write_text(json.dumps({"candidates": c}, indent=1))
    print(f"{len(c)} convention-routing candidates")
    for x in c[:40]:
        print(f"  {x['method']} {x['path']}  ({x['file']}:{x['line']})")
