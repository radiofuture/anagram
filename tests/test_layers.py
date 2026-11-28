"""Layer contract (CONTRIBUTING.md, "Layers").

The test reads each module of `src/anagram` with `ast`. It gives each module
a layer (the longest prefix in `LAYER` wins) and checks each `anagram` import
(top level, in a function, or under `TYPE_CHECKING`) against `ALLOWED`.

`KNOWN` holds the crossings that exist, as (from module, to module) pairs.
It is a ratchet and it is empty: the test fails when a new crossing appears.
Do not add a pair to `KNOWN`; use a port (a `Protocol` in the lower layer)
instead.

`LAYER` maps each package to its layer or cross-cutting part: one package for
each layer and each cross-cutting part. Layer codes: L1 identity, L2 app
(local data), L3 network and discovery, L4 admission; XC core, XM models,
XP proofs, XG agent gateway, XS shell, XT test tools.

Inside a layer, the part on the computer of a person is `app/` and the part
on the server (the node) is `node/`.
"""

from __future__ import annotations

import ast
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"

LAYER = {
    "anagram": "XS",  # the package root: the version, `python -m anagram`
    "anagram.core": "XC",
    "anagram.models": "XM",
    "anagram.proofs": "XP",
    "anagram.identity": "L1",
    "anagram.local": "L2",
    "anagram.network": "L3",
    "anagram.admission": "L4",
    "anagram.gateway": "XG",
    "anagram.shell": "XS",
    "anagram.sim": "XT",
    "anagram.vectors": "XT",
}

# A layer may import itself and the layers in its set.
ALLOWED = {
    "XC": {"XC"},
    "XM": {"XC", "XM"},
    "XP": {"XC", "XP"},
    "L1": {"XC", "XP", "L1"},
    "L2": {"XM", "XC", "XP", "L1", "L2"},
    "L3": {"XM", "XC", "XP", "L1", "L2", "L3"},
    "L4": {"XC", "XP", "L1", "L3", "L4"},
    "XG": {"XM", "XC", "XP", "L1", "L2", "L3", "XG"},
    "XS": {"XM", "XC", "XP", "L1", "L2", "L3", "L4", "XG", "XS", "XT"},
    "XT": {"XM", "XC", "XP", "L1", "L2", "L3", "L4", "XS", "XG", "XT"},
}

# Known layer crossings (kept empty as a ratchet).
KNOWN: set[tuple[str, str]] = set()


def layer_of(module: str) -> str | None:
    parts = module.split(".")
    for i in range(len(parts), 0, -1):
        found = LAYER.get(".".join(parts[:i]))
        if found:
            return found
    return None


def _modules():
    for path in sorted((SRC / "anagram").rglob("*.py")):
        parts = list(path.relative_to(SRC).with_suffix("").parts)
        package = parts[-1] == "__init__"
        if package:
            parts = parts[:-1]
        yield ".".join(parts), path, package


def _targets(module: str, package: bool, node: ast.AST, known: set[str]) -> list[str]:
    if isinstance(node, ast.Import):
        return [alias.name for alias in node.names]
    if not isinstance(node, ast.ImportFrom):
        return []
    base = node.module or ""
    if node.level:
        parts = module.split(".") if package else module.split(".")[:-1]
        parts = parts[: len(parts) - (node.level - 1)]
        base = ".".join(parts + ([node.module] if node.module else []))
    # `from anagram.x import y` imports the module `anagram.x.y` when it exists.
    return [f"{base}.{a.name}" if f"{base}.{a.name}" in known else base for a in node.names]


def crossings() -> dict[tuple[str, str], list[str]]:
    """Map each crossing (from, to) to the places that make it."""
    modules = list(_modules())
    known = {module for module, _, _ in modules}
    found: dict[tuple[str, str], list[str]] = {}
    for module, path, package in modules:
        for node in ast.walk(ast.parse(path.read_text(), str(path))):
            for target in _targets(module, package, node, known):
                if target.split(".")[0] != "anagram":
                    continue
                src, dst = layer_of(module), layer_of(target)
                if src and dst and dst not in ALLOWED[src]:
                    where = f"{path.relative_to(SRC)}:{node.lineno} ({src} -> {dst})"
                    found.setdefault((module, target), []).append(where)
    return found


def test_each_module_has_a_layer():
    assert [m for m, _, _ in _modules() if layer_of(m) is None] == []


def test_no_new_layer_crossing():
    found = crossings()
    new = {pair: found[pair] for pair in set(found) - KNOWN}
    assert not new, f"new layer crossing; use a port, not an import: {new}"


def test_known_crossings_still_exist():
    gone = KNOWN - set(crossings())
    assert not gone, f"a known crossing is gone; remove it from KNOWN: {sorted(gone)}"


def test_a_new_crossing_fails(tmp_path, monkeypatch):
    """The check sees an upward import in a function body."""
    root = tmp_path / "anagram"
    for pkg in ("", "identity", "shell", "shell/ui"):
        (root / pkg).mkdir(parents=True, exist_ok=True)
        (root / pkg / "__init__.py").write_text("")
    (root / "identity" / "__init__.py").write_text(
        "def f():\n    from anagram.shell.ui import server\n"
    )
    (root / "shell" / "ui" / "server.py").write_text("")
    monkeypatch.setitem(globals(), "SRC", tmp_path)
    assert set(crossings()) == {("anagram.identity", "anagram.shell.ui.server")}


# The public face of a layer: code outside a layer
# imports only the layer's `api` module. Code inside the layer imports its
# own modules. The cross-cutting parts (core, proofs, models) are libraries
# and keep their modules public. The test tools (layer XT: the vector makers
# and the simulator) are like the tests: they build and check the inside of a
# layer (the locked formats), so they may import its modules. A facade name
# that only the tests or the test tools use is not public.
_API_LAYERS = {"identity", "local", "network", "admission"}


def api_crossings() -> list[str]:
    modules = list(_modules())
    known = {module for module, _, _ in modules}
    found = []
    for module, path, package in modules:
        if layer_of(module) == "XT":
            continue
        mine = module.split(".")[1] if "." in module else ""
        for node in ast.walk(ast.parse(path.read_text(), str(path))):
            for target in _targets(module, package, node, known):
                parts = target.split(".")
                if len(parts) < 2 or parts[0] != "anagram" or parts[1] not in _API_LAYERS:
                    continue
                if parts[1] != mine and target != f"anagram.{parts[1]}.api":
                    found.append(f"{path.relative_to(SRC)}:{node.lineno} {module} -> {target}")
    return found


def test_outside_a_layer_import_only_its_api():
    found = api_crossings()
    assert found == [], f"import the public name from <layer>.api: {found}"


def test_a_test_tool_may_import_past_the_api(tmp_path, monkeypatch):
    root = tmp_path / "anagram"
    for pkg in ("", "local", "local/index", "vectors"):
        (root / pkg).mkdir(parents=True, exist_ok=True)
        (root / pkg / "__init__.py").write_text("")
    (root / "local" / "api.py").write_text("")
    (root / "local" / "index" / "store.py").write_text("")
    (root / "vectors" / "a.py").write_text("from anagram.local.index import store\n")
    monkeypatch.setitem(globals(), "SRC", tmp_path)
    assert api_crossings() == []


def test_an_import_past_the_api_fails(tmp_path, monkeypatch):
    root = tmp_path / "anagram"
    for pkg in ("", "local", "network", "local/index"):
        (root / pkg).mkdir(parents=True, exist_ok=True)
        (root / pkg / "__init__.py").write_text("")
    (root / "local" / "api.py").write_text("")
    (root / "local" / "index" / "store.py").write_text("")
    (root / "network" / "a.py").write_text(
        "from anagram.local.api import x\nfrom anagram.local.index import store\n"
    )
    monkeypatch.setitem(globals(), "SRC", tmp_path)
    assert [f.split(" ", 1)[1] for f in api_crossings()] == [
        "anagram.network.a -> anagram.local.index.store"
    ]


def _api_exports(layer: str) -> set[str]:
    path = SRC / "anagram" / layer / "api.py"
    if not path.exists():
        return set()
    tree = ast.parse(path.read_text(), str(path))
    exports: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "__all__":
                    if isinstance(node.value, ast.List | ast.Tuple):
                        for elt in node.value.elts:
                            if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                                exports.add(elt.value)
    return exports


def unused_api_exports() -> list[str]:
    """Return `<layer>.api.<name>` for every name in `<layer>/api.py` `__all__`
    that has no consumer outside its layer in non-XT production code."""
    exports = {layer: _api_exports(layer) for layer in _API_LAYERS}
    used: dict[str, set[str]] = {layer: set() for layer in _API_LAYERS}
    for module, path, _ in _modules():
        if layer_of(module) == "XT":
            continue
        mine = module.split(".")[1] if "." in module else ""
        tree = ast.parse(path.read_text(), str(path))
        aliases: dict[str, str] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                for layer in _API_LAYERS:
                    if layer == mine:
                        continue
                    if node.module == f"anagram.{layer}.api":
                        for alias in node.names:
                            if alias.name == "*":
                                used[layer].update(exports[layer])
                            else:
                                used[layer].add(alias.name)
                    elif node.module == f"anagram.{layer}":
                        for alias in node.names:
                            if alias.name == "api":
                                aliases[alias.asname or "api"] = layer
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    for layer in _API_LAYERS:
                        if layer != mine and alias.name == f"anagram.{layer}.api" and alias.asname:
                            aliases[alias.asname] = layer
        if aliases:
            for node in ast.walk(tree):
                if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
                    layer_hit = aliases.get(node.value.id)
                    if layer_hit is not None:
                        used[layer_hit].add(node.attr)
    return [
        f"anagram.{layer}.api.{name}"
        for layer in sorted(_API_LAYERS)
        for name in sorted(exports[layer] - used[layer])
    ]


def test_no_unused_api_exports():
    found = unused_api_exports()
    assert found == [], f"unused facade export (remove from <layer>.api): {found}"


def test_an_unused_api_export_fails(tmp_path, monkeypatch):
    root = tmp_path / "anagram"
    for pkg in ("", "local", "network"):
        (root / pkg).mkdir(parents=True, exist_ok=True)
        (root / pkg / "__init__.py").write_text("")
    (root / "local" / "api.py").write_text('__all__ = ["used_name", "unused_name"]\n')
    (root / "network" / "a.py").write_text("from anagram.local.api import used_name\n")
    monkeypatch.setitem(globals(), "SRC", tmp_path)
    assert unused_api_exports() == ["anagram.local.api.unused_name"]


# The two sides of a layer: the app (`*/app/`, on the computer
# of a person) and the node (`*/node/`, the server) share code only through
# the rest of their layer (formats, trust), never through each other.
_SIDES = ("app", "node")


def _side(module: str, packages: set[str]) -> str | None:
    """`app` or `node` when a package of that name holds the module. The
    shell is the composition root and wires both sides, so it has none."""
    parts = module.split(".")
    dirs = parts if module in packages else parts[:-1]
    if len(dirs) < 2 or dirs[1] == "shell":
        return None
    return next((d for d in dirs[2:] if d in _SIDES), None)


def side_crossings() -> list[str]:
    modules = list(_modules())
    known = {module for module, _, _ in modules}
    packages = {module for module, _, package in modules if package}
    found = []
    for module, path, package in modules:
        mine = _side(module, packages)
        if mine is None:
            continue
        for node in ast.walk(ast.parse(path.read_text(), str(path))):
            for target in _targets(module, package, node, known):
                theirs = _side(target, packages) if target.startswith("anagram.") else None
                if theirs is not None and theirs != mine:
                    found.append(f"{path.relative_to(SRC)}:{node.lineno} {module} -> {target}")
    return found


def test_node_and_app_do_not_import_each_other():
    found = side_crossings()
    assert found == [], f"share the code through the layer (formats, trust): {found}"


def test_a_node_import_of_the_app_fails(tmp_path, monkeypatch):
    root = tmp_path / "anagram"
    for pkg in ("", "network", "network/matching", "network/matching/app", "network/matching/node"):
        (root / pkg).mkdir(parents=True, exist_ok=True)
        (root / pkg / "__init__.py").write_text("")
    (root / "network" / "matching" / "app" / "client.py").write_text("")
    (root / "network" / "matching" / "node" / "relay.py").write_text(
        "def f():\n    from anagram.network.matching.app.client import x\n"
    )
    monkeypatch.setitem(globals(), "SRC", tmp_path)
    assert [f.split(" ", 1)[1] for f in side_crossings()] == [
        "anagram.network.matching.node.relay -> anagram.network.matching.app.client"
    ]


# Boundaries between the node services: the composition root
# gives each service what it needs; no service sets or reads the inside of
# another one.
_SERVICES = {"identity", "labs", "admission", "vault", "reads", "matching", "directory"}


def test_node_app_sets_no_attribute_of_a_service():
    tree = ast.parse((SRC / "anagram" / "shell" / "node" / "app.py").read_text())
    set_attrs = [
        ast.unparse(t)
        for node in ast.walk(tree)
        if isinstance(node, ast.Assign | ast.AugAssign | ast.AnnAssign)
        for t in (node.targets if isinstance(node, ast.Assign) else [node.target])
        if isinstance(t, ast.Attribute)
    ]
    assert set_attrs == []


def test_the_sides_of_a_layer_are_app_and_node():
    """No package is named `host` (the old word for the node) or `device`
    (the old word for the app side; "device" now names only a key holder)."""
    old = [p for p in (SRC / "anagram").rglob("__init__.py") if p.parent.name in ("host", "device")]
    assert old == []


def test_no_node_service_reads_a_private_name_of_another():
    found = []
    node_code = [p for p in (SRC / "anagram").rglob("*.py") if "node" in p.parts[:-1]]
    node_code += list((SRC / "anagram" / "admission").rglob("*.py"))
    for path in sorted(node_code):
        for node in ast.walk(ast.parse(path.read_text(), str(path))):
            if (
                isinstance(node, ast.Attribute)
                and node.attr.startswith("_")
                and not node.attr.startswith("__")
                and isinstance(node.value, ast.Attribute)
                and node.value.attr in _SERVICES
            ):
                found.append(f"{path.relative_to(SRC)}:{node.lineno} {ast.unparse(node)}")
    assert found == []


# The UI and the app: a UI part calls the public API of
# the client parts, of the index, and of the other UI parts. No code reads a
# private name (`x._name`) of an object that is not `self`, and no module
# imports a private name of another module.
def test_no_ui_code_reads_a_private_name_of_another_object():
    found = []
    for pkg in ("shell/ui", "shell/app"):
        for path in sorted((SRC / "anagram" / pkg).rglob("*.py")):
            for node in ast.walk(ast.parse(path.read_text(), str(path))):
                where = f"{path.relative_to(SRC)}:{getattr(node, 'lineno', 0)}"
                if isinstance(node, ast.ImportFrom) and (node.module or "").startswith("anagram"):
                    found += [f"{where} {a.name}" for a in node.names if _private(a.name)]
                if (
                    isinstance(node, ast.Attribute)
                    and _private(node.attr)
                    and not (isinstance(node.value, ast.Name) and node.value.id in ("self", "cls"))
                ):
                    found.append(f"{where} {ast.unparse(node)}")
    assert found == []


def _private(name: str) -> bool:
    return name.startswith("_") and not name.startswith("__")


# Duck typing of the client: a layer names what it needs
# from the app client as a typed port (`local/ports.py`), not as a
# parameter `client` with no type, `Any`, or `object` that it reads with
# `getattr`.
_TYPED_LAYERS = ("identity", "local", "network", "admission", "gateway")
_LOOSE = {"Any", "object", "Any | None", "object | None", "None | Any", "None | object"}


def duck_typed_clients() -> list[str]:
    found = []
    for layer in _TYPED_LAYERS:
        for path in sorted((SRC / "anagram" / layer).rglob("*.py")):
            for node in ast.walk(ast.parse(path.read_text(), str(path))):
                where = f"{path.relative_to(SRC)}:{getattr(node, 'lineno', 0)}"
                if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                    args = node.args
                    for a in args.posonlyargs + args.args + args.kwonlyargs:
                        ann = ast.unparse(a.annotation) if a.annotation else None
                        if a.arg == "client" and (ann is None or ann in _LOOSE):
                            found.append(f"{where} {node.name}(client: {ann})")
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id in ("getattr", "hasattr")
                    and node.args
                    and ast.unparse(node.args[0]).split(".")[0] == "client"
                ):
                    found.append(f"{where} {ast.unparse(node)}")
    return sorted(found, key=lambda f: (f.split(":")[0], int(f.split(":")[1].split()[0])))


def test_no_layer_reads_a_duck_typed_client():
    found = duck_typed_clients()
    assert found == [], f"name what the client gives as a typed port: {found}"


def test_a_duck_typed_client_fails(tmp_path, monkeypatch):
    (tmp_path / "anagram" / "local").mkdir(parents=True)
    (tmp_path / "anagram" / "local" / "a.py").write_text(
        "from typing import Any\n\n\n"
        "def f(client: Any):\n"
        "    return getattr(client.labs, 'lab_list', None)\n\n\n"
        "def g(client):\n"
        "    pass\n\n\n"
        "def h(client: 'Port'):\n"
        "    pass\n"
    )
    monkeypatch.setitem(globals(), "SRC", tmp_path)
    assert duck_typed_clients() == [
        "anagram/local/a.py:4 f(client: Any)",
        "anagram/local/a.py:5 getattr(client.labs, 'lab_list', None)",
        "anagram/local/a.py:8 g(client: None)",
    ]


def test_admission_reads_no_connection_of_the_identity_service():
    """Admission uses its own `AdmissionStore`; the composition root gives
    it the connection and the lock (docs/design/shared-sqlite-connection.md)."""
    found = []
    for path in sorted((SRC / "anagram" / "admission").rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(), str(path))):
            if isinstance(node, ast.Attribute) and node.attr in ("db", "lock"):
                if isinstance(node.value, ast.Name) and node.value.id == "identity":
                    found.append(f"{path.relative_to(SRC)}:{node.lineno} {ast.unparse(node)}")
    assert found == []
