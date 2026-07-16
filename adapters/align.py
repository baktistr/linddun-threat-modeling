"""Align a derived DFD against a hand-authored one, so the adapter can be scored.

The problem: a derived DFD's element named "Auth Service" and the hand DFD's "Authentication
Service" are the same thing, and "MongoDB users collection" is the same store an LLM might call
"User Records". Matching those by name -- fuzzy, embedding, or otherwise -- is unreliable,
unreviewable, and silently re-breaks every time the model rephrases. So names are never compared
here.

Instead both sides compute a *provenance key* and the keys are compared exactly:

  hand side    -- adapters/data/<scenario>_hand_keys.json, authored once by hand against the
                  immutable dfd.json. Reviewable in a diff.
  derived side -- computed deterministically from the code facts an element cites (M1;
                  derived_element_keys() lands with adapters/extract.py). A DataStore citing
                  mongoose_model(model_name="User") keys to mongo_collection:users whatever the
                  LLM decided to call it.

A key is (kind, key): mongo_collection:users, route_mount:/api/auth, actor_role:parent,
fs_path:backend/uploads, web_storage:localStorage. Two elements are the same element iff their
keys match. That reduces "did the adapter find DS1?" from a judgement call to a set lookup.

Flow identity is NOT a function of (source, destination). The hand DFD has two distinct flows on
the same pair -- DF7 (P3->DS2, "store/update child profile") and DF10 (P3->DS2, "store child
search and watch history") -- and the gold standard anchors 4 threats to each. Deduplicating by
pair would silently merge them and destroy 8 gold anchors, so align_flows() disambiguates
same-pair buckets by description similarity and flags every flow it resolved that way.
"""
from __future__ import annotations
import json
import re
from collections import defaultdict
from dataclasses import dataclass, field

import config

# fs_path keys match by prefix rather than equality: the adapter sees the concrete directory a
# writer targets (backend/uploads/images, from middleware/imageUpload.js), while the hand DFD
# models the coarser store it belongs to (backend/uploads). Same store, finer view.
PREFIX_MATCHED_KINDS = {"fs_path"}

# "none" means no provenance key is computable for this element -- nothing in any codebase could
# produce it. Distinct from "the adapter missed it": see adapters/evaluate.py's unresolved_key.
NO_KEY = "none"

_TOKEN_RE = re.compile(r"[a-z0-9]+")
_STOPWORDS = {"the", "a", "an", "to", "of", "and", "or", "for", "in", "on", "from", "with", "by"}


@dataclass(frozen=True)
class ElementKey:
    kind: str
    key: str

    def __str__(self) -> str:
        return f"{self.kind}:{self.key}" if self.key else self.kind


@dataclass(frozen=True)
class HandKey:
    element_id: str
    kind: str
    key: str
    implemented: bool = True

    @property
    def computable(self) -> bool:
        """False when no code, in any repository, could produce a key for this element."""
        return self.kind != NO_KEY

    @property
    def element_key(self) -> ElementKey | None:
        return ElementKey(self.kind, self.key) if self.computable else None


@dataclass
class ElementAlignment:
    derived_to_hand: dict[str, str] = field(default_factory=dict)
    hand_to_derived: dict[str, list[str]] = field(default_factory=dict)
    unmatched_derived: list[str] = field(default_factory=list)
    unmatched_hand: list[str] = field(default_factory=list)

    @property
    def granularity_ratio(self) -> float:
        """Derived elements per matched hand element. >1 means the adapter models at a finer
        grain than the analyst did -- reported, never scored, same as for flows."""
        n = len(self.hand_to_derived)
        return len(self.derived_to_hand) / n if n else 0.0


@dataclass
class FlowAlignment:
    derived_to_hand: dict[str, str] = field(default_factory=dict)
    hand_to_derived: dict[str, list[str]] = field(default_factory=dict)
    unmatched_derived: list[str] = field(default_factory=list)
    unmatched_hand: list[str] = field(default_factory=list)
    ambiguous: set[str] = field(default_factory=set)

    @property
    def granularity_ratio(self) -> float:
        """Derived flows per matched hand flow. A code-driven adapter sees route-level flows where
        a human analyst draws one arrow, so this is expected to exceed 1. Reported, never scored --
        it is a difference in modeling granularity, not an error."""
        n_matched_hand = len(self.hand_to_derived)
        return len(self.derived_to_hand) / n_matched_hand if n_matched_hand else 0.0


def _key_from_facts(element: dict, facts: list[dict],
                    file_to_mount: dict[str, str]) -> ElementKey | None:
    """The provenance key an element's cited facts imply, or None if they imply none.

    Keyed off the element's declared type, so evidence is read the way the element claims to use
    it. A DataStore citing a mongo_collection fact keys to that collection whatever the model
    decided to name the element -- which is the entire point: "MongoDB users collection", "User
    Records" and "Accounts DB" all key to mongo_collection:users, and none of them are ever
    compared as strings.
    """
    by_construct: dict[str, list[dict]] = {}
    for f in facts:
        by_construct.setdefault(f["construct"], []).append(f)

    etype = element.get("type")
    if etype == "DataStore":
        for f in by_construct.get("mongo_collection", []):
            return ElementKey("mongo_collection", f["fields"]["collection"])
        for f in by_construct.get("fs_location", []):
            return ElementKey("fs_path", f["fields"]["fs_path"])
        for f in by_construct.get("web_storage_access", []):
            return ElementKey("web_storage", f["fields"]["store"])
    elif etype == "Process":
        for f in by_construct.get("express_mount", []):
            return ElementKey("route_mount", f["fields"]["mount_path"])
        # No mount cited (an LLM may cite only the routes): fall back to the mount those routes
        # actually hang off, via the router file they live in. Majority rather than first, so an
        # element citing routes from several routers keys to the one it mostly is.
        mounts: dict[str, int] = {}
        for f in by_construct.get("express_route", []):
            m = file_to_mount.get(f["file"])
            if m:
                mounts[m] = mounts.get(m, 0) + 1
        if mounts:
            return ElementKey("route_mount", max(sorted(mounts), key=lambda m: mounts[m]))
    elif etype == "ExternalEntity":
        for f in by_construct.get("role_check", []):
            roles = f["fields"].get("roles") or []
            if roles:
                return ElementKey("actor_role", sorted(roles)[0])
    return None


def derived_element_keys(dfd: dict, facts: list[dict]) -> dict[str, ElementKey]:
    """Compute every derived element's provenance key from the facts it cites.

    Elements citing no resolvable fact get no key and therefore cannot match anything. That is
    deliberate: an element with no evidence behind it has nothing to be aligned *by*, and
    silently matching it on its name would reintroduce exactly the self-report this design
    refuses. Such elements surface as unmatched derived elements and go to adjudication.
    """
    facts_by_id = {f["id"]: f for f in facts}
    file_to_mount = {f["fields"]["router_file"]: f["fields"]["mount_path"]
                     for f in facts
                     if f["construct"] == "express_mount" and f["fields"].get("router_file")}
    out: dict[str, ElementKey] = {}
    for e in dfd["elements"]:
        cited = [facts_by_id[p["fact_id"]] for p in e.get("provenance", [])
                 if p.get("fact_id") in facts_by_id]
        key = _key_from_facts(e, cited, file_to_mount)
        if key is not None:
            out[e["id"]] = key
    return out


def load_hand_keys(scenario: str) -> dict[str, HandKey]:
    path = config.ROOT / "adapters" / "data" / f"{scenario}_hand_keys.json"
    if not path.exists():
        raise FileNotFoundError(
            f"no hand key map for scenario {scenario!r} at {path}. Every scenario the adapter is "
            f"evaluated against needs one -- without it the derivability ceiling cannot be "
            f"computed, and a silently-wrong ceiling is worse than no number.")
    raw = json.loads(path.read_text())["elements"]
    return {eid: HandKey(element_id=eid, kind=v["kind"], key=v.get("key", ""),
                         implemented=v.get("implemented", True))
            for eid, v in raw.items()}


def keys_match(derived: ElementKey, hand: ElementKey) -> bool:
    if derived.kind != hand.kind:
        return False
    if derived.kind in PREFIX_MATCHED_KINDS:
        d, h = derived.key.strip("/"), hand.key.strip("/")
        return d == h or d.startswith(h + "/")
    return derived.key == hand.key


def align_elements(derived_keys: dict[str, ElementKey],
                   hand_keys: dict[str, HandKey]) -> ElementAlignment:
    """derived_keys: derived element id -> its computed provenance key.

    Iterates derived ids in sorted order so the result is deterministic across runs -- synthesis
    is stochastic and element ids differ run to run, which is exactly why the hand side (stable)
    owns the vocabulary and the derived side is matched into it.

    Exact-keyed kinds match 1:1: two derived elements keying to mongo_collection:users are a
    genuine duplicate, and the second must surface as unmatched for a human to judge rather than
    be quietly absorbed into a match.

    Prefix-keyed kinds (fs_path) match many-to-one, because that is what the evidence says. The
    hand DFD's DS4 is one store, "File System (backend/uploads/)"; the code writes to
    backend/uploads (express.static, video uploads) AND backend/uploads/images (multer, via
    middleware/imageUpload.js). Both are genuinely that store, seen at a finer grain. Forcing 1:1
    here made the second an unmatched "false positive" and -- worse -- silently cost DF15 (store
    government ID images), whose flow projects through the directory that lost. A real flow
    disappearing because of a tie-break in the scorer is precisely the kind of measurement bug M0
    exists to keep out of the numbers. The granularity is recorded in `granularity_ratio` instead.
    """
    alignment = ElementAlignment()
    for hid, hk in sorted(hand_keys.items()):
        hkey = hk.element_key
        if hkey is None:
            continue
        for did in sorted(derived_keys):
            if did in alignment.derived_to_hand:
                continue
            if not keys_match(derived_keys[did], hkey):
                continue
            alignment.derived_to_hand[did] = hid
            alignment.hand_to_derived.setdefault(hid, []).append(did)
            if hkey.kind not in PREFIX_MATCHED_KINDS:
                break

    alignment.unmatched_derived = sorted(set(derived_keys) - set(alignment.derived_to_hand))
    alignment.unmatched_hand = sorted(set(hand_keys) - set(alignment.hand_to_derived))
    return alignment


def _tokens(text: str) -> set[str]:
    return {t for t in _TOKEN_RE.findall(text.lower()) if t not in _STOPWORDS and len(t) > 1}


def _jaccard(a: set[str], b: set[str]) -> float:
    union = a | b
    return len(a & b) / len(union) if union else 0.0


def align_flows(derived_dfd: dict, hand_dfd: dict, elements: ElementAlignment) -> FlowAlignment:
    """Project each derived flow's endpoints through the element alignment, then match by the
    resulting (hand_source, hand_destination) pair.

    A pair holding more than one hand flow (KidsTube's DF7/DF10, both P3->DS2) is disambiguated
    by greedy bipartite matching on description-token Jaccard: pass 1 gives each hand flow one
    distinct derived flow best-first, pass 2 lets leftover derived flows join their best hand
    flow. Ties break on sorted ids, so it is deterministic and seedless. Every hand flow resolved
    this way is recorded in `ambiguous` -- it is a heuristic, and a heuristic that isn't labeled
    one eventually gets read as a measurement.
    """
    derived_by_id = {f["id"]: f for f in derived_dfd["flows"]}
    hand_by_pair: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for f in hand_dfd["flows"]:
        hand_by_pair[(f["source"], f["destination"])].append(f)

    projected: dict[str, tuple[str, str]] = {}
    for f in derived_dfd["flows"]:
        hs = elements.derived_to_hand.get(f["source"])
        hd = elements.derived_to_hand.get(f["destination"])
        if hs and hd:
            projected[f["id"]] = (hs, hd)

    alignment = FlowAlignment()

    for pair, hflows in sorted(hand_by_pair.items()):
        candidates = sorted(fid for fid, p in projected.items() if p == pair)
        if not candidates:
            continue

        if len(hflows) == 1:
            hid = hflows[0]["id"]
            for cid in candidates:
                alignment.derived_to_hand[cid] = hid
            alignment.hand_to_derived[hid] = candidates
            continue

        scored = []
        for h in hflows:
            ht = _tokens(h["description"])
            for cid in candidates:
                ct = _tokens(derived_by_id[cid]["description"])
                scored.append((_jaccard(ht, ct), h["id"], cid))
        scored.sort(key=lambda x: (-x[0], x[1], x[2]))

        taken_hand: set[str] = set()
        taken_derived: set[str] = set()
        for _score, hid, cid in scored:
            if hid in taken_hand or cid in taken_derived:
                continue
            taken_hand.add(hid)
            taken_derived.add(cid)
            alignment.derived_to_hand[cid] = hid
            alignment.hand_to_derived.setdefault(hid, []).append(cid)
            alignment.ambiguous.add(hid)

        for cid in candidates:
            if cid in taken_derived:
                continue
            best = max(((s, h) for s, h, c in scored if c == cid), default=(0.0, None))
            if best[1] is not None:
                alignment.derived_to_hand[cid] = best[1]
                alignment.hand_to_derived.setdefault(best[1], []).append(cid)

    alignment.unmatched_derived = sorted(set(derived_by_id) - set(alignment.derived_to_hand))
    alignment.unmatched_hand = sorted({f["id"] for f in hand_dfd["flows"]}
                                      - set(alignment.hand_to_derived))
    return alignment
