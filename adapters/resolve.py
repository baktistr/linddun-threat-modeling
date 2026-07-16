"""Pass 1b: cross-file resolution. Turns per-file facts into the joins a DFD actually needs.

extract.py reports what one file says. Three questions need more than one file to answer, and each
is a place where the obvious shortcut is wrong on this codebase:

  Which collection does a model write to?
      routes/auth.js says `const User = require('../models/Parent')`. The naive chain
      local-name -> collection gives "users" and happens to be right. The naive chain
      filename -> collection gives "parents" and is wrong. Neither is the real chain, which is
      local binding -> module path -> that module's module_export -> mongoose.model's first
      argument -> Mongoose's pluralisation. models/Parent.js line 120 registers 'User', so the
      collection is "users" -- matching the hand DFD's DS1 "MongoDB users collection". The local
      name coincidentally equals the model name in both of KidsTube's route files, which is
      exactly why a shortcut through it would look like it works and then break silently on a
      codebase where it doesn't.

  Which process serves a frontend call?
      server.js mounts routes/children.js at '/api/subprofiles' -- the mount path matches neither
      the filename nor any string inside children.js. And the frontend calls '/subprofiles', not
      '/api/subprofiles': the '/api' prefix lives in frontend/src/api/config.js's axios baseURL,
      which is a ternary over NODE_ENV with two literal branches. So the join is two levels, and
      the resolver takes the path suffix every branch agrees on rather than picking a deployment.

  Which handler does a path hit?
      routes/children.js registers GET '/approved-videos' at line 10 and GET '/:id' at line 132.
      Express is first-match-wins in registration order, so the literal call
      GET /api/subprofiles/approved-videos hits the former at runtime. A matcher that canonicalises
      both to '/subprofiles/{p}' unifies them and attributes the call to the wrong handler --
      hence the wrong db_operation set, hence a wrong flow. Not hypothetical; live in this repo.

Derived facts (derived=True) are emitted for values no source line contains -- the collection name
above all. See CodeFact's docstring: the verifier can re-parse a literal but cannot confirm an
inference, and that distinction has to stay visible.
"""
from __future__ import annotations
import re
from dataclasses import dataclass
from pathlib import Path

from adapters.schema import CodeFact

# mongoose-legacy-pluralize's rule table, in its order. Mongoose applies the FIRST matching rule
# (rules.filter(...)[0]), then lowercases the whole thing (utils.toCollectionName). Reproduced
# faithfully rather than approximated with "+s", because an approximation that is right for
# KidsTube's three models would be quietly wrong for the next codebase and nothing downstream
# would catch it -- a wrong collection surfaces only as an alignment miss, which reads as an LLM
# failure rather than as our bug.
_PLURALIZE_RULES: list[tuple[str, str]] = [
    (r"(m)en$", r"\1en"),
    (r"(pe)ople$", r"\1ople"),
    (r"(child)ren$", r"\1ren"),
    (r"([ti])a$", r"\1a"),
    (r"((a)naly|(b)a|(d)iagno|(p)arenthe|(p)rogno|(s)ynop|(t)he)sis$", r"\1ses"),
    (r"(hive)$", r"\1s"),
    (r"(buffal|tomat|txt|carg|her|potat|mosquit)o$", r"\1oes"),
    (r"^(m|l)ouse$", r"\1ice"),
    (r"(matr|vert|ind|d)(ix|ex)$", r"\1ices"),
    (r"(x|ch|ss|sh)$", r"\1es"),
    (r"([^aeiouy]|qu)y$", r"\1ies"),
    (r"(?:([^f])fe|([lr])f)$", r"\1\2ves"),
    (r"sis$", "ses"),
    (r"([ti])um$", r"\1a"),
    (r"(bu)s$", r"\1ses"),
    (r"(alias|status)$", r"\1es"),
    (r"(octop|vir)us$", r"\1i"),
    (r"(gen)us$", r"\1era"),
    (r"(ax|test)is$", r"\1es"),
    (r"s$", "s"),
    (r"$", "s"),
]

_UNCOUNTABLES = {
    "advice", "energy", "excretion", "digestion", "cooperation", "health", "justice",
    "labour", "machinery", "equipment", "information", "pollution", "sewage", "paper",
    "money", "species", "series", "rice", "fish", "sheep", "moose", "deer", "news",
}

# The regular "+s" rule and the terminal "s$" no-op are unremarkable. Anything else means an
# English irregularity was applied, and those are where a re-implementation is most likely to
# drift from the real library -- so they get flagged rather than trusted silently.
_REGULAR_RULES = {r"$", r"s$"}


@dataclass(frozen=True)
class CollectionInfo:
    model_name: str
    collection: str
    file: str
    model_fact_id: str
    source: str          # explicit_arg | schema_option | pluralization_rule
    rule: str
    confidence: str


@dataclass(frozen=True)
class Route:
    fact_id: str
    method: str
    router_path: str
    router_file: str
    mount_path: str
    full_path: str
    line: int


def pluralize(model_name: str) -> tuple[str, str]:
    """Mongoose's model-name -> collection-name rule. Returns (collection, rule_applied)."""
    if model_name.lower() in _UNCOUNTABLES:
        return model_name.lower(), "uncountable"
    for pattern, replacement in _PLURALIZE_RULES:
        if re.search(pattern, model_name, flags=re.IGNORECASE):
            return re.sub(pattern, replacement, model_name, flags=re.IGNORECASE).lower(), pattern
    return model_name.lower(), "identity"


def resolve_mongoose_collections(facts: list[CodeFact]) -> dict[str, CollectionInfo]:
    """file -> the collection that file's exported model writes to.

    Precedence is Mongoose's own: mongoose.model(name, schema, 'explicitCollection') beats
    new Schema({}, {collection: 'x'}) beats the pluralisation rule. KidsTube uses neither
    override, but silently pluralising over one would be a wrong answer no downstream check
    catches, so we look.
    """
    schema_options: dict[tuple[str, str], str] = {}
    for f in facts:
        if f.construct == "mongoose_schema" and f.fields.get("collection_option"):
            schema_options[(f.file, f.fields["schema_var"])] = f.fields["collection_option"]

    out: dict[str, CollectionInfo] = {}
    for f in facts:
        if f.construct != "mongoose_model":
            continue
        model_name = f.fields["model_name"]
        explicit = f.fields.get("explicit_collection")
        schema_var = f.fields.get("schema_var")
        option = schema_options.get((f.file, schema_var))

        if explicit:
            info = CollectionInfo(model_name, explicit, f.file, f.id, "explicit_arg",
                                  "mongoose.model arg 3", "high")
        elif option:
            info = CollectionInfo(model_name, option, f.file, f.id, "schema_option",
                                  "new Schema({}, {collection})", "high")
        else:
            collection, rule = pluralize(model_name)
            confidence = "high" if rule in _REGULAR_RULES else "low"
            info = CollectionInfo(model_name, collection, f.file, f.id, "pluralization_rule",
                                  rule, confidence)
        out[f.file] = info
    return out


def model_binding_index(facts: list[CodeFact],
                        collections: dict[str, CollectionInfo]) -> dict[tuple[str, str], CollectionInfo]:
    """(file, local_name) -> collection, via the full binding chain.

    This is the function that refuses the filename shortcut. It goes local name -> module_path ->
    resolved_file -> that file's registered model -> collection.
    """
    index: dict[tuple[str, str], CollectionInfo] = {}
    for f in facts:
        if f.construct not in ("require_binding", "es_import_binding"):
            continue
        resolved = f.fields.get("resolved_file")
        if resolved and resolved in collections:
            index[(f.file, f.fields["local_name"])] = collections[resolved]
    return index


def resolve_fs_path(raw: str | None, file: str) -> str | None:
    """'@dirname/../uploads/images' in backend/middleware/imageUpload.js -> 'backend/uploads/images'."""
    if not raw:
        return None
    parts: list[str] = []
    segments = raw.split("/")
    if segments and segments[0] == "@dirname":
        parts = list(Path(file).parent.parts)
        segments = segments[1:]
    for seg in segments:
        if seg in ("", "."):
            continue
        if seg == "..":
            if parts:
                parts.pop()
            continue
        parts.append(seg)
    return "/".join(parts)


def base_path(facts: list[CodeFact]) -> tuple[str, str]:
    """The URL path prefix every axios baseURL branch agrees on, and a confidence.

    config.js's baseURL is a ternary over NODE_ENV: 'http://kidstubepe.andrew.cmu.edu:5000/api'
    or 'http://127.0.0.1:5000/api'. Both end in '/api', so '/api' is safe -- and their agreement
    is itself the evidence. If branches ever disagreed, returning "" with low confidence beats
    picking one, because the source genuinely does not say which deployment is in force.
    """
    branches: list[str] = []
    for f in facts:
        if f.construct == "http_client_config":
            branches.extend(f.fields.get("base_url_branches") or [])
    if not branches:
        return "", "low"
    paths = []
    for b in branches:
        m = re.match(r"^[a-z]+://[^/]+(/.*)$", b)
        paths.append(m.group(1).rstrip("/") if m else "")
    return (paths[0], "high") if len(set(paths)) == 1 else ("", "low")


def canonical_path(path: str) -> str:
    """Normalise a URL path for comparison: `:param` and `${expr}` both become `{p}`.

    Applied to both sides, so Express's '/:id' and the frontend's template literal
    '/subprofiles/${childId}' meet in the middle. Used only for param segments -- literal
    segments still have to match exactly, which is what keeps '/approved-videos' from being
    unified with '/:id'.
    """
    path = re.sub(r"\$\{[^}]*\}", "{p}", path)
    path = re.sub(r":[A-Za-z_][A-Za-z0-9_]*", "{p}", path)
    path = "/" + path.strip("/")
    return path


class MountTable:
    """Express's routing table, resolved across server.js and the route modules.

    resolve() reproduces Express's actual dispatch: first registered route whose method and
    segments match wins. Not "prefer literals" -- Express has no such preference, and modelling a
    preference it doesn't have would mis-predict a codebase that registers '/:id' first. Here the
    literal IS registered first, so the two agree; being faithful means we stay right when they
    don't.
    """

    def __init__(self, routes: list[Route]):
        self.routes = routes

    @staticmethod
    def build(facts: list[CodeFact]) -> "MountTable":
        mounts = {f.fields["router_file"]: f.fields["mount_path"]
                  for f in facts
                  if f.construct == "express_mount" and f.fields.get("router_file")}
        routes = []
        for f in facts:
            if f.construct != "express_route":
                continue
            mount = mounts.get(f.file)
            if mount is None:
                continue  # a router nothing mounts serves no traffic
            full = "/" + "/".join(p for p in (mount.strip("/"), f.fields["router_path"].strip("/")) if p)
            routes.append(Route(fact_id=f.id, method=f.fields["method"],
                                router_path=f.fields["router_path"], router_file=f.file,
                                mount_path=mount, full_path=full, line=f.line))
        routes.sort(key=lambda r: (r.router_file, r.line))
        return MountTable(routes)

    def resolve(self, method: str, path: str) -> Route | None:
        want = canonical_path(path).strip("/").split("/")
        for route in self.routes:
            if route.method != method.upper():
                continue
            have = canonical_path(route.full_path).strip("/").split("/")
            if len(have) != len(want):
                continue
            if all(h == "{p}" or h == w for h, w in zip(have, want)):
                return route
        return None

    def by_mount(self) -> dict[str, list[Route]]:
        out: dict[str, list[Route]] = {}
        for r in self.routes:
            out.setdefault(r.mount_path, []).append(r)
        return out


def resolve_facts(facts: list[CodeFact]) -> list[CodeFact]:
    """Return `facts` plus the derived facts cross-file resolution produces.

    Every derived fact carries derived=True and cites the literal fact it was computed from, so a
    reader can always get back to a real source line -- and so verify_dfd can report honestly that
    it re-parsed the literal but only recomputed the inference.
    """
    collections = collection_facts = resolve_mongoose_collections(facts)
    bindings = model_binding_index(facts, collections)
    mounts = MountTable.build(facts)
    prefix, prefix_confidence = base_path(facts)

    derived: list[CodeFact] = []

    for file, info in sorted(collection_facts.items()):
        fields = {"model_name": info.model_name, "collection": info.collection,
                  "resolved_via": info.source, "rule": info.rule,
                  "from_fact_id": info.model_fact_id, "model_file": file}
        derived.append(CodeFact(
            id=CodeFact.make_id("mongo_collection", file, 0, fields),
            construct="mongo_collection", file=file, line=0, end_line=0, fields=fields,
            derived=True, confidence=info.confidence))

    for f in facts:
        if f.construct != "db_operation":
            continue
        info = bindings.get((f.file, f.fields["local_name"]))
        if info is None:
            continue
        fields = {"collection": info.collection, "model_name": info.model_name,
                  "op": f.fields["op"], "access": f.fields["access"],
                  "route_fact_id": f.fields.get("route_fact_id"),
                  "from_fact_id": f.id, "model_file": info.file}
        derived.append(CodeFact(
            id=CodeFact.make_id("db_access", f.file, f.line, fields),
            construct="db_access", file=f.file, line=f.line, end_line=f.end_line,
            fields=fields, derived=True, confidence=info.confidence))

    for f in facts:
        if f.construct not in ("fs_write", "express_static_mount"):
            continue
        resolved = resolve_fs_path(f.fields.get("fs_path"), f.file)
        if not resolved:
            continue
        fields = {"fs_path": resolved, "from_fact_id": f.id,
                  "mechanism": f.fields.get("mechanism", "express.static")}
        derived.append(CodeFact(
            id=CodeFact.make_id("fs_location", f.file, f.line, fields),
            construct="fs_location", file=f.file, line=f.line, end_line=f.end_line,
            fields=fields, derived=True))

    for f in facts:
        if f.construct != "http_client_call":
            continue
        literal = f.fields.get("path_literal") or f.fields.get("path_expr", "")
        raw = literal.strip("`'\"")
        absolute = prefix + ("/" + raw.strip("/") if raw.strip("/") else "")
        route = mounts.resolve(f.fields["method"], absolute)
        fields = {"absolute_path": canonical_path(absolute), "method": f.fields["method"],
                  "route_fact_id": route.fact_id if route else None,
                  "mount_path": route.mount_path if route else None,
                  "router_file": route.router_file if route else None,
                  "from_fact_id": f.id, "base_path": prefix}
        derived.append(CodeFact(
            id=CodeFact.make_id("http_route_binding", f.file, f.line, fields),
            construct="http_route_binding", file=f.file, line=f.line, end_line=f.end_line,
            fields=fields, derived=True,
            confidence=prefix_confidence if route else "low"))

    out = facts + derived
    out.sort(key=lambda f: (f.file, f.line, f.construct, f.id))
    return out
