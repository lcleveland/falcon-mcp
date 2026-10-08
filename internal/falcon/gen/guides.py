"""Print upstream's query guides as JSON {uri: text}.

Run by gen with the path of an unpacked CrowdStrike/falcon-mcp tree. The
guide text is built in Python at import time (f-strings, generated
tables), so it is evaluated here rather than parsed in Go. Only the
standard library is needed.
"""
import ast, importlib, json, pathlib, sys
root = pathlib.Path(sys.argv[1]).resolve()
sys.path.insert(0, str(root))
out = {}
for f in sorted((root / "falcon_mcp/modules").rglob("*.py")):
    tree = ast.parse(f.read_text())
    mod = ".".join(f.relative_to(root).with_suffix("").parts)
    imports = {}
    for n in ast.walk(tree):
        if isinstance(n, ast.ImportFrom) and n.module and n.module.startswith("falcon_mcp.resources"):
            for a in n.names:
                imports[a.asname or a.name] = (n.module, a.name)
    for n in ast.walk(tree):
        if isinstance(n, ast.Call) and getattr(n.func, "id", "") == "TextResource":
            kw = {k.arg: k.value for k in n.keywords}
            uri = kw["uri"].args[0].value
            if not isinstance(kw["text"], ast.Name) or kw["text"].id not in imports:
                sys.exit(f"{f}: {uri}: text is not a constant imported from falcon_mcp.resources")
            m, name = imports[kw["text"].id]
            out[uri] = getattr(importlib.import_module(m), name)
json.dump(out, sys.stdout, sort_keys=True)
