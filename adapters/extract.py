"""Pass 1a: deterministic per-file extraction of code facts, each carrying its own file:line.

Nothing here interprets. A fact says "backend/models/Parent.js line 120 registers a Mongoose
model named 'User' from schema variable userSchema" -- not "this system has a user store". The
leap from facts to DFD elements is pass 2's job (adapters/synthesize.py), and keeping the two
apart is what makes pass 3 (adapters/verify_dfd.py) possible at all: you cannot independently
re-derive a claim that was never separable from its evidence.

Cross-file resolution -- which module a `require` points at, which model a route's `User.findOne`
actually refers to, what mount path a router hangs off -- is deliberately NOT done here. See
adapters/resolve.py. This module only reports what a single file says.

Scope honesty: these patterns are matched to conventional Express/Mongoose/React idioms, and
KidsTube is a small, clean, conventional instance of them. They will not transfer to Nest, Prisma,
or GraphQL without rewriting this module and resolve.py. The generalisable contributions of this
subsystem are the schema, the fact-id citation discipline, and the derivability-ceiling reporting
-- not these JS patterns.
"""
from __future__ import annotations
from pathlib import Path

from adapters import jsparse as js
from adapters.schema import CodeFact

# Mongoose query/mutation methods, split by whether they read or write. The split drives flow
# direction (Process->DataStore vs DataStore->Process), so it is data rather than a guess at
# call sites.
READ_OPS = {"find", "findOne", "findById", "aggregate", "countDocuments", "count",
            "distinct", "exists", "populate"}
WRITE_OPS = {"create", "save", "insertMany", "updateOne", "updateMany", "update",
             "findByIdAndUpdate", "findOneAndUpdate", "replaceOne",
             "deleteOne", "deleteMany", "remove", "findByIdAndDelete", "findOneAndDelete"}
DB_OPS = READ_OPS | WRITE_OPS

HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}

SKIP_DIRS = {"node_modules", ".git", "build", "dist", "coverage"}
SKIP_FILE_SUFFIXES = (".test.js", ".spec.js")


def _rel(path: Path, root: Path) -> str:
    return str(path.relative_to(root)).replace("\\", "/")


def _fact(construct: str, file: str, node, fields: dict, *, derived: bool = False,
          confidence: str = "high") -> CodeFact:
    line = js.line(node)
    return CodeFact(id=CodeFact.make_id(construct, file, line, fields), construct=construct,
                    file=file, line=line, end_line=js.end_line(node), fields=fields,
                    derived=derived, confidence=confidence)


def _resolve_require(module_path: str, from_file: str) -> str | None:
    """'../models/Parent' from backend/routes/auth.js -> 'backend/models/Parent.js'.

    Returns None for bare package names ('express', 'mongoose') -- those are third-party and have
    no file in this repo to cite.
    """
    if not module_path.startswith("."):
        return None
    base = (Path(from_file).parent / module_path).as_posix()
    parts: list[str] = []
    for seg in base.split("/"):
        if seg == "." or seg == "":
            continue
        if seg == "..":
            if parts:
                parts.pop()
            continue
        parts.append(seg)
    resolved = "/".join(parts)
    return resolved if resolved.endswith(".js") else resolved + ".js"


def _path_join_literal(node, source: bytes) -> str | None:
    """Static value of `path.join(__dirname, 'uploads')` relative to the file's directory.

    Returns a marker-prefixed relative path ('@dirname/uploads') that resolve.py anchors to the
    repo. Any non-static argument makes the whole join non-static, and we return None rather than
    inventing a path -- a fabricated fs_path would be a citation to a directory that may not
    exist.
    """
    if node is None or node.type != "call_expression":
        return None
    if js.callee(node, source) != "path.join":
        return None
    segments = []
    for arg in js.call_args(node):
        if arg.type == "identifier" and js.text(arg, source) == "__dirname":
            segments.append("@dirname")
            continue
        lit = js.string_literal(arg, source)
        if lit is None:
            return None
        segments.append(lit)
    return "/".join(segments) if segments else None


def _string_branches(node, source: bytes) -> list[str]:
    """Every static string a ternary/logical-or expression could evaluate to.

    frontend/src/api/config.js's baseURL is
        NODE_ENV === 'production' ? 'http://host:5000/api'
                                  : (process.env.REACT_APP_API_URL || 'http://127.0.0.1:5000/api')
    -- a ternary whose alternative is itself a logical-or over an env var. Collecting every branch
    and letting resolve.py take the suffix they agree on beats picking one, because picking one is
    a guess about deployment that the source does not make.
    """
    if node is None:
        return []
    lit = js.string_literal(node, source)
    if lit is not None:
        return [lit]
    if node.type == "parenthesized_expression":
        out = []
        for c in node.children:
            if c.type not in ("(", ")"):
                out.extend(_string_branches(c, source))
        return out
    if node.type == "ternary_expression":
        return (_string_branches(node.child_by_field_name("consequence"), source)
                + _string_branches(node.child_by_field_name("alternative"), source))
    if node.type == "binary_expression":
        return (_string_branches(node.child_by_field_name("left"), source)
                + _string_branches(node.child_by_field_name("right"), source))
    return []


def _bindings(root, source: bytes, file: str) -> tuple[list[CodeFact], dict[str, str]]:
    """require/import bindings in this file, plus a local-name -> resolved-file index.

    The index is what stops `const User = require('../models/Parent')` from being read as a model
    called "Parent". Nothing here decides what 'User' *is* -- only which file would know.
    """
    facts: list[CodeFact] = []
    index: dict[str, str] = {}

    for name, value, decl in js.declarations(root, source):
        if value.type != "call_expression" or js.callee(value, source) != "require":
            continue
        args = js.call_args(value)
        if not args:
            continue
        module_path = js.string_literal(args[0], source)
        if module_path is None:
            continue
        resolved = _resolve_require(module_path, file)
        fields = {"local_name": name, "module_path": module_path, "resolved_file": resolved}
        facts.append(_fact("require_binding", file, decl, fields))
        if resolved:
            index[name] = resolved

    # `const { auth, requireRole } = require('../middleware/ageCheck')`
    for n in js.walk(root):
        if n.type != "variable_declarator":
            continue
        name_node = n.child_by_field_name("name")
        value = n.child_by_field_name("value")
        if name_node is None or value is None or name_node.type != "object_pattern":
            continue
        if value.type != "call_expression" or js.callee(value, source) != "require":
            continue
        args = js.call_args(value)
        module_path = js.string_literal(args[0], source) if args else None
        if module_path is None:
            continue
        resolved = _resolve_require(module_path, file)
        for c in name_node.children:
            if c.type != "shorthand_property_identifier_pattern":
                continue
            local = js.text(c, source)
            facts.append(_fact("require_binding", file, n,
                               {"local_name": local, "module_path": module_path,
                                "resolved_file": resolved}))
            if resolved:
                index[local] = resolved

    for n in js.walk(root):
        if n.type != "import_statement":
            continue
        src_node = n.child_by_field_name("source")
        module_path = js.string_literal(src_node, source) if src_node else None
        if module_path is None:
            continue
        resolved = _resolve_require(module_path, file)
        for d in js.walk(n):
            if d.type in ("identifier", "import_specifier"):
                local = js.text(d, source).split(" as ")[-1].strip()
                if not local or local == module_path:
                    continue
                facts.append(_fact("es_import_binding", file, n,
                                   {"local_name": local, "module_path": module_path,
                                    "resolved_file": resolved}))
                if resolved:
                    index[local] = resolved
                break
    return facts, index


def _mongoose(root, source: bytes, file: str) -> list[CodeFact]:
    facts = []
    for name, value, decl in js.declarations(root, source):
        if value.type != "new_expression":
            continue
        ctor = value.child_by_field_name("constructor")
        if ctor is None or js.text(ctor, source) != "mongoose.Schema":
            continue
        args = js.call_args(value)
        options = args[1] if len(args) > 1 else None
        collection_opt = js.string_literal(js.object_property(options, source, "collection"), source)
        field_names = []
        if args:
            for pair in args[0].children if args[0].type == "object" else []:
                if pair.type != "pair":
                    continue
                k = pair.child_by_field_name("key")
                if k is not None:
                    field_names.append(js.text(k, source).strip("'\""))
        facts.append(_fact("mongoose_schema", file, decl,
                           {"schema_var": name, "collection_option": collection_opt,
                            "schema_fields": field_names}))

    for call in js.calls(root, source, "mongoose.model"):
        args = js.call_args(call)
        if not args:
            continue
        model_name = js.string_literal(args[0], source)
        if model_name is None:
            continue
        # arg 2 is an explicit collection override. KidsTube never uses it, but pluralising over
        # an override would be a wrong answer no downstream check catches, so we look.
        explicit = js.string_literal(args[2], source) if len(args) > 2 else None
        facts.append(_fact("mongoose_model", file, call,
                           {"model_name": model_name,
                            "schema_var": js.text(args[1], source) if len(args) > 1 else None,
                            "explicit_collection": explicit}))

    for n in js.walk(root):
        if n.type != "assignment_expression":
            continue
        left = n.child_by_field_name("left")
        right = n.child_by_field_name("right")
        if left is None or js.text(left, source) != "module.exports":
            continue
        model_name = None
        if right is not None and right.type == "call_expression" \
                and js.callee(right, source) == "mongoose.model":
            a = js.call_args(right)
            model_name = js.string_literal(a[0], source) if a else None
        facts.append(_fact("module_export", file, n,
                           {"expr_kind": right.type if right is not None else None,
                            "model_name": model_name}))

    for call in js.calls(root, source, "mongoose.connect"):
        args = js.call_args(call)
        uri = None
        if args:
            uri = js.string_literal(args[0], source)
            if uri is None and args[0].type == "identifier":
                # `mongoose.connect(MONGODB_URI, ...)` -- a variable, not the literal you'd grep
                # for. Resolve the const binding in this file.
                target = js.text(args[0], source)
                for name, value, _ in js.declarations(root, source):
                    if name == target:
                        branches = _string_branches(value, source)
                        uri = branches[0] if branches else None
                        break
        facts.append(_fact("db_connect", file, call, {"uri": uri}))
    return facts


def _env_defaults(root, source: bytes, file: str) -> list[CodeFact]:
    facts = []
    for name, value, decl in js.declarations(root, source):
        branches = _string_branches(value, source)
        if len(branches) < 2 or "process.env" not in js.text(value, source):
            continue
        facts.append(_fact("env_default", file, decl,
                           {"name": name, "branches": branches}))
    return facts


def _express(root, source: bytes, file: str, bindings: dict[str, str]) -> list[CodeFact]:
    facts = []
    for call in js.calls_matching(root, source,
                                  lambda c: c in ("app.use", "router.use", "server.use")):
        args = js.call_args(call)
        if len(args) < 2:
            continue
        mount = js.string_literal(args[0], source)
        if mount is None:
            continue
        handler = args[1]
        handler_text = js.text(handler, source)

        if handler.type == "call_expression" and js.callee(handler, source) == "express.static":
            static_args = js.call_args(handler)
            fs_path = _path_join_literal(static_args[0], source) if static_args else None
            if fs_path is None and static_args:
                fs_path = js.string_literal(static_args[0], source)
            facts.append(_fact("express_static_mount", file, call,
                               {"mount_path": mount, "fs_path": fs_path}))
            continue

        if handler.type == "identifier":
            facts.append(_fact("express_mount", file, call,
                               {"mount_path": mount, "router_local": handler_text,
                                "router_file": bindings.get(handler_text)}))

    for call in js.calls_matching(root, source,
                                  lambda c: c.startswith("router.") and c.split(".")[-1] in HTTP_METHODS):
        args = js.call_args(call)
        if not args:
            continue
        route_path = js.string_literal(args[0], source)
        if route_path is None:
            continue
        method = js.callee(call, source).split(".")[-1].upper()
        middleware = [js.text(a, source) for a in args[1:]
                      if a.type not in ("arrow_function", "function_expression")]
        fields = {"method": method, "router_path": route_path, "middleware": middleware}
        route_fact = _fact("express_route", file, call, fields)
        facts.append(route_fact)

        for a in args[1:]:
            if a.type == "call_expression" and js.callee(a, source) == "requireRole":
                roles = js.array_string_elements(js.call_args(a)[0], source) if js.call_args(a) else []
                facts.append(_fact("role_check", file, a,
                                   {"roles": roles, "route_fact_id": route_fact.id,
                                    "mechanism": "requireRole"}))
            if a.type == "call_expression" and js.callee(a, source) \
                    and js.callee(a, source).endswith(".single"):
                field_arg = js.call_args(a)
                facts.append(_fact("multer_use", file, a,
                                   {"field": js.string_literal(field_arg[0], source) if field_arg else None,
                                    "uploader": js.callee(a, source).split(".")[0],
                                    "route_fact_id": route_fact.id}))
    return facts


def _role_comparisons(root, source: bytes, file: str,
                      route_spans: list[tuple[int, int, str]]) -> list[CodeFact]:
    """`req.user.userType !== 'child'` / `user.userType === 'parent'`.

    This is the fact that separates EE1 from EE2: both are User documents, distinguished only by
    a userType discriminator. Without it the adapter emits one undifferentiated "User" entity and
    loses the hand DFD's central actor distinction.
    """
    facts = []
    for n in js.walk(root):
        if n.type != "binary_expression":
            continue
        op = None
        for c in n.children:
            if c.type in ("===", "!==", "==", "!="):
                op = c.type
        if op is None:
            continue
        left = n.child_by_field_name("left")
        right = n.child_by_field_name("right")
        if left is None or right is None:
            continue
        left_text = js.text(left, source)
        role = js.string_literal(right, source)
        if role is None or not (left_text.endswith("userType") or left_text.endswith(".role")):
            continue
        facts.append(_fact("role_check", file, n,
                           {"roles": [role], "mechanism": "userType_comparison",
                            "operator": op, "subject": left_text,
                            "route_fact_id": js.enclosing_span(n, route_spans)}))
    return facts


def _db_operations(root, source: bytes, file: str, bindings: dict[str, str],
                   route_spans: list[tuple[int, int, str]]) -> list[CodeFact]:
    """`User.findOne(...)` inside a route handler, attributed to that route.

    `local_name` is reported, never a model name: this file knows `User` is bound to
    ../models/Parent, and nothing more. Which model that file registers -- and therefore which
    collection -- is resolve.py's job, because only Parent.js can answer it.
    """
    facts = []
    model_instances: dict[str, str] = {}
    for name, value, _ in js.declarations(root, source):
        if value.type != "new_expression":
            continue
        ctor = value.child_by_field_name("constructor")
        if ctor is not None and js.text(ctor, source) in bindings:
            model_instances[name] = js.text(ctor, source)

    for n in js.walk(root):
        if n.type != "call_expression":
            continue
        c = js.callee(n, source)
        if c is None or "." not in c:
            continue
        receiver, _, op = c.rpartition(".")
        if op not in DB_OPS:
            continue
        if receiver in bindings:
            local_name, via = receiver, "model_binding"
        elif receiver in model_instances:
            local_name, via = model_instances[receiver], "model_instance"
        else:
            continue
        facts.append(_fact("db_operation", file, n,
                           {"local_name": local_name, "module_path": bindings[local_name],
                            "op": op, "access": "read" if op in READ_OPS else "write",
                            "via": via, "route_fact_id": js.enclosing_span(n, route_spans)}))
    return facts


def _fs_writes(root, source: bytes, file: str) -> list[CodeFact]:
    facts = []
    for n in js.walk(root):
        if n.type != "call_expression":
            continue
        c = js.callee(n, source)
        if c is None:
            continue
        if c in ("multer.diskStorage",):
            args = js.call_args(n)
            dest = js.object_property(args[0], source, "destination") if args else None
            fs_path = None
            if dest is not None:
                for inner in js.walk(dest):
                    fs_path = _path_join_literal(inner, source)
                    if fs_path:
                        break
            facts.append(_fact("fs_write", file, n,
                               {"fs_path": fs_path, "mechanism": "multer.diskStorage"}))
        elif c.startswith("fs.") and c.split(".")[-1] in (
                "writeFile", "writeFileSync", "mkdirSync", "createWriteStream", "appendFile"):
            args = js.call_args(n)
            fs_path = _path_join_literal(args[0], source) if args else None
            facts.append(_fact("fs_write", file, n,
                               {"fs_path": fs_path, "mechanism": c}))
    return facts


def _web_storage(root, source: bytes, file: str) -> list[CodeFact]:
    facts = []
    for n in js.walk(root):
        if n.type != "call_expression":
            continue
        c = js.callee(n, source)
        if c is None or "." not in c:
            continue
        store, _, op = c.rpartition(".")
        if store not in ("localStorage", "sessionStorage",
                         "window.localStorage", "window.sessionStorage"):
            continue
        if op not in ("getItem", "setItem", "removeItem", "clear"):
            continue
        args = js.call_args(n)
        facts.append(_fact("web_storage_access", file, n,
                           {"store": store.split(".")[-1],
                            "key": js.string_literal(args[0], source) if args else None,
                            "op": op,
                            "access": "read" if op == "getItem" else "write"}))
    return facts


def _http_client(root, source: bytes, file: str, bindings: dict[str, str]) -> list[CodeFact]:
    facts = []
    for name, value, decl in js.declarations(root, source):
        if value.type != "call_expression" or js.callee(value, source) != "axios.create":
            continue
        args = js.call_args(value)
        base = js.object_property(args[0], source, "baseURL") if args else None
        branches: list[str] = []
        if base is not None:
            branches = _string_branches(base, source)
            if not branches and base.type == "identifier":
                target = js.text(base, source)
                for n2, v2, _ in js.declarations(root, source):
                    if n2 == target:
                        branches = _string_branches(v2, source)
                        break
        facts.append(_fact("http_client_config", file, decl,
                           {"client_local": name, "base_url_branches": branches}))

    clients = {f.fields["client_local"] for f in facts if f.construct == "http_client_config"}
    clients |= {n for n, r in bindings.items() if r and r.endswith("api/config.js")}
    for n in js.walk(root):
        if n.type != "call_expression":
            continue
        c = js.callee(n, source)
        if c is None or "." not in c:
            continue
        receiver, _, method = c.rpartition(".")
        if method not in HTTP_METHODS or receiver not in clients:
            continue
        args = js.call_args(n)
        if not args:
            continue
        literal = js.string_literal(args[0], source)
        raw = js.text(args[0], source)
        facts.append(_fact("http_client_call", file, n,
                           {"client_local": receiver, "method": method.upper(),
                            "path_literal": literal, "path_expr": raw}))
    return facts


def extract_file(path: Path, repo_root: Path) -> list[CodeFact]:
    file = _rel(path, repo_root)
    root, source = js.parse_file(path)

    binding_facts, bindings = _bindings(root, source, file)
    facts = list(binding_facts)
    facts += _mongoose(root, source, file)
    facts += _env_defaults(root, source, file)

    express_facts = _express(root, source, file, bindings)
    facts += express_facts
    route_spans = [(f.line, f.end_line, f.id) for f in express_facts
                   if f.construct == "express_route"]

    facts += _role_comparisons(root, source, file, route_spans)
    facts += _db_operations(root, source, file, bindings, route_spans)
    facts += _fs_writes(root, source, file)
    facts += _web_storage(root, source, file)
    facts += _http_client(root, source, file, bindings)
    return facts


def source_files(repo_root: Path) -> list[Path]:
    out = []
    for p in sorted(repo_root.rglob("*.js")):
        if any(part in SKIP_DIRS for part in p.relative_to(repo_root).parts):
            continue
        if p.name.endswith(SKIP_FILE_SUFFIXES):
            continue
        out.append(p)
    return out


def extract_repo(repo_root: Path) -> list[CodeFact]:
    """Every fact in the repository, sorted deterministically so a re-run diffs cleanly."""
    facts: list[CodeFact] = []
    for path in source_files(repo_root):
        facts.extend(extract_file(path, repo_root))
    facts.sort(key=lambda f: (f.file, f.line, f.construct, f.id))
    return facts
