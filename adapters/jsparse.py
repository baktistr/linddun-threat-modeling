"""Thin tree-sitter layer: the only module in this repo that imports tree_sitter.

Isolated for two reasons. First, dependency containment: tree-sitter is an *optional* dependency
(requirements.txt keeps it in the same commented block as sbert/anthropic), because
adapters/data/kidstube_code_facts.json is committed. Extraction is the only stage that needs a
parser or a source checkout -- synthesis, verification, alignment, adapter eval, and the
end-to-end threat run all read the committed facts and work from a clean clone with no new deps
and no network. Same shape as scripts/data/genomic_figure11_raw.json: the raw transcription is
committed as an audit trail, and you don't need to re-OCR the NIST PDF to run the pipeline.
Second, API churn: tree-sitter's Python binding changed shape across 0.21->0.23 (Language
construction, query capture return types), so the blast radius of a version bump is one file.

Why tree-sitter and not regex: regex handles ~80% of KidsTube's facts -- mongoose.model and
app.use are one-liners -- but breaks on exactly the four that matter. Route handler *spans* (a
db_operation must be attributed to the route whose handler encloses it), template-literal paths,
the ternary baseURL in frontend/src/api/config.js, and path.join(__dirname, '../uploads/images').
Beyond that: a project whose thesis is "derive, don't guess" using pattern-matching for its
derivation pass is an argument a reviewer will make for you.
"""
from __future__ import annotations
from pathlib import Path

_IMPORT_ERROR = (
    "source extraction needs the optional adapter dependencies:\n"
    '    pip install "tree-sitter==0.23.*" "tree-sitter-javascript==0.23.*"\n'
    "These are NOT needed to run the adapter from committed facts "
    "(adapters/data/*_code_facts.json) -- only to regenerate them from a source checkout."
)

try:
    import tree_sitter_javascript as _tsjs
    from tree_sitter import Language as _Language, Node, Parser as _Parser
    _AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only on a machine without the optional deps
    Node = object  # type: ignore
    _AVAILABLE = False


def available() -> bool:
    return _AVAILABLE


_PARSER = None


def parser():
    global _PARSER
    if not _AVAILABLE:
        raise ImportError(_IMPORT_ERROR)
    if _PARSER is None:
        _PARSER = _Parser(_Language(_tsjs.language()))
    return _PARSER


def parse(source: bytes):
    """Parse to a root node. tree-sitter is error-tolerant, so a syntax error yields a partial
    tree with ERROR nodes rather than an exception -- a file we can't fully parse still yields
    the facts we could read, and never silently yields zero."""
    return parser().parse(source).root_node


def parse_file(path: Path):
    source = path.read_bytes()
    return parse(source), source


def line(node) -> int:
    """1-indexed, to match how humans and every other tool in this repo cite source locations."""
    return node.start_point[0] + 1


def end_line(node) -> int:
    return node.end_point[0] + 1


def text(node, source: bytes) -> str:
    return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def walk(node):
    """Depth-first pre-order over every node."""
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(reversed(n.children))


def string_literal(node, source: bytes) -> str | None:
    """The content of a string/template literal, or None if this node isn't a static string.

    Template literals with `${...}` substitutions return None deliberately: their runtime value
    isn't knowable from the source, and guessing one would put a fabricated value behind a
    file:line citation -- precisely the failure mode this whole project exists to refuse. Callers
    that need to handle `/subprofiles/${childId}` canonicalise it separately (see
    resolve.canonical_path), where the guess is explicit and labelled.
    """
    if node is None:
        return None
    if node.type == "string":
        parts = [c for c in node.children if c.type == "string_fragment"]
        if not parts:
            return ""  # an empty literal '' is a real, static value
        return "".join(text(p, source) for p in parts)
    if node.type == "template_string":
        if any(c.type == "template_substitution" for c in node.children):
            return None
        parts = [c for c in node.children if c.type == "string_fragment"]
        return "".join(text(p, source) for p in parts)
    return None


def callee(node, source: bytes) -> str | None:
    """Dotted callee of a call_expression: `mongoose.model` -> "mongoose.model", `require` ->
    "require". Returns None for anything not a call."""
    if node.type != "call_expression":
        return None
    fn = node.child_by_field_name("function")
    return text(fn, source) if fn is not None else None


def call_args(node) -> list:
    args = node.child_by_field_name("arguments")
    if args is None:
        return []
    return [c for c in args.children if c.type not in ("(", ")", ",")]


def calls(root, source: bytes, name: str):
    """Every call_expression whose dotted callee is exactly `name`."""
    for n in walk(root):
        if n.type == "call_expression" and callee(n, source) == name:
            yield n


def calls_matching(root, source: bytes, predicate):
    for n in walk(root):
        if n.type == "call_expression":
            c = callee(n, source)
            if c is not None and predicate(c):
                yield n


def declarations(root, source: bytes):
    """Yield (name, value_node, decl_node) for every `const x = ...` / `let x = ...`."""
    for n in walk(root):
        if n.type != "variable_declarator":
            continue
        name_node = n.child_by_field_name("name")
        value = n.child_by_field_name("value")
        if name_node is not None and name_node.type == "identifier" and value is not None:
            yield text(name_node, source), value, n


def object_property(node, source: bytes, key: str):
    """Value node of `{ key: value }`, or None. Matches both `key:` and `'key':`."""
    if node is None or node.type != "object":
        return None
    for pair in node.children:
        if pair.type != "pair":
            continue
        k = pair.child_by_field_name("key")
        if k is None:
            continue
        k_text = string_literal(k, source) if k.type in ("string", "template_string") else text(k, source)
        if k_text == key:
            return pair.child_by_field_name("value")
    return None


def array_string_elements(node, source: bytes) -> list[str]:
    """Static string elements of an array literal: `['parent', 'admin']` -> ["parent", "admin"].
    Non-static elements are skipped rather than guessed at."""
    if node is None or node.type != "array":
        return []
    out = []
    for c in node.children:
        s = string_literal(c, source)
        if s is not None:
            out.append(s)
    return out


def enclosing_span(node, spans: list[tuple[int, int, str]]) -> str | None:
    """Which of `spans` (start_line, end_line, id) encloses `node`. Innermost wins.

    This is what regex cannot do and why the parser is here: attributing a db_operation to the
    route handler it sits inside is a containment question about the tree, not a textual one.
    """
    ln = line(node)
    best = None
    for start, end, sid in spans:
        if start <= ln <= end and (best is None or (end - start) < (best[1] - best[0])):
            best = (start, end, sid)
    return best[2] if best else None
