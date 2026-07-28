"""Tests for the source-code -> DFD adapter.

Run: PYTHONPATH=. python3 tests/test_adapter.py
Plain asserts (no pytest dependency), matching tests/test_kb.py and tests/test_generation.py.

M0's tests are deliberately about the *metric*, not the adapter: they run before any code has
been parsed, and they exist so that when there finally is something to measure, the thing doing
the measuring is already known-good. If the derivability ceiling arithmetic is wrong here, every
number the adapter ever reports is wrong and nothing downstream would reveal it.
"""
from __future__ import annotations
import copy
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config
from adapters.align import (ElementKey, align_elements, align_flows, keys_match, load_hand_keys)
from adapters.evaluate import (ceiling_elements, ceiling_flows, element_derivability,
                               flow_derivability, score)
from adapters.schema import schema_version, validate_dfd

PASS, FAIL = 0, 0


def check(cond: bool, msg: str):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ok   {msg}")
    else:
        FAIL += 1
        print(f"  FAIL {msg}")


def _hand_dfd(scenario: str = "kidstube") -> dict:
    return json.loads((config.KB_DIR / "scenarios" / scenario / "dfd.json").read_text())


def test_schema_backward_compatible():
    """The four hand-authored DFDs are ground truth and are never migrated. v1 is a strict subset
    of v2, so they must validate untouched -- that IS the compatibility proof."""
    print("\n[canonical DFD schema: v1 files validate unmodified]")
    paths = sorted((config.KB_DIR / "scenarios").glob("*/dfd.json"))
    check(len(paths) >= 4, f"found >=4 scenario DFDs (got {len(paths)})")
    for p in paths:
        dfd = json.loads(p.read_text())
        errors = validate_dfd(dfd)
        check(not errors, f"{p.parent.name}/dfd.json conforms (v{schema_version(dfd)})"
                          + (f" -- {errors[:2]}" if errors else ""))


def test_schema_rejects_broken_dfds():
    """A validator that never fails isn't validating."""
    print("\n[canonical DFD schema: violations are caught]")
    base = _hand_dfd()

    d = copy.deepcopy(base)
    d["elements"][0]["type"] = "Datastore"          # real trap: correct spelling is DataStore
    check(any("not one of" in e for e in validate_dfd(d)), "bad element type is rejected")

    d = copy.deepcopy(base)
    d["flows"][0]["source"] = "EE99"
    check(any("not a declared element" in e for e in validate_dfd(d)),
          "flow endpoint that isn't a declared element is rejected")

    d = copy.deepcopy(base)
    d["elements"][1]["id"] = d["elements"][0]["id"]
    check(any("duplicate element id" in e for e in validate_dfd(d)), "duplicate element id is rejected")

    d = copy.deepcopy(base)
    d["elements"][0]["provenance"] = [{"fact_id": "F0001", "file": "a.js", "line": 3}]
    check(any("more than one vocabulary" in e for e in validate_dfd(d)),
          "provenance citing both vocabularies at once is rejected")

    d = copy.deepcopy(base)
    d["elements"][0]["provenance"] = [{"note": "trust me"}]
    check(any("cites no vocabulary" in e for e in validate_dfd(d)),
          "provenance citing nothing is rejected")

    d = copy.deepcopy(base)
    d["elements"][0]["trust_boundary"] = "TB1"      # no trust_boundaries declared in v1 kidstube
    check(any("not a declared trust boundary" in e for e in validate_dfd(d)),
          "dangling trust_boundary reference is rejected")


def test_key_matching():
    print("\n[provenance key matching]")
    check(keys_match(ElementKey("mongo_collection", "users"),
                     ElementKey("mongo_collection", "users")), "identical keys match")
    check(not keys_match(ElementKey("mongo_collection", "users"),
                         ElementKey("mongo_collection", "parents")),
          "'users' does not match 'parents' (the models/Parent.js filename trap)")
    check(not keys_match(ElementKey("route_mount", "/api/auth"),
                         ElementKey("mongo_collection", "/api/auth")), "kind must agree")
    check(keys_match(ElementKey("fs_path", "backend/uploads/images"),
                     ElementKey("fs_path", "backend/uploads")),
          "fs_path matches by prefix (imageUpload.js writes the finer backend/uploads/images)")
    check(not keys_match(ElementKey("fs_path", "backend/uploads_public"),
                         ElementKey("fs_path", "backend/uploads")),
          "fs_path prefix match respects path segments (uploads_public is not under uploads)")


def test_hand_keys_cover_the_hand_dfd():
    print("\n[kidstube hand key map]")
    hand = _hand_dfd()
    keys = load_hand_keys("kidstube")
    dfd_ids = {e["id"] for e in hand["elements"]}
    check(set(keys) == dfd_ids,
          f"key map covers exactly the hand DFD's elements (missing: {sorted(dfd_ids - set(keys))}, "
          f"extra: {sorted(set(keys) - dfd_ids)})")
    check(keys["DS1"].key == "users",
          "DS1 keys to collection 'users' -- models/Parent.js exports mongoose.model('User', ...)")
    check(keys["DS2"].key == "childprofiles",
          "DS2 keys to 'childprofiles' -- models/Child.js exports mongoose.model('ChildProfile', ...)")
    check(keys["P3"].key == "/api/subprofiles",
          "P3 keys to mount /api/subprofiles -- server.js mounts routes/children.js there")
    check(not keys["P4"].implemented and not keys["EE3"].implemented,
          "P4 and EE3 are flagged unimplemented (system_description.md marks both '(planned)')")
    check(not keys["P4"].computable,
          "P4 has no computable key -- no code implements an AI recommendation engine")


def test_ceiling_is_computed_from_data():
    """The ceiling must fall out of the key map's `implemented` flags, not a constant in the
    scoring code -- otherwise adding a scenario silently reports someone else's ceiling."""
    print("\n[derivability ceiling]")
    hand = _hand_dfd()
    keys = load_hand_keys("kidstube")

    ce = ceiling_elements(keys)
    check(ce == {"EE3", "P4"}, f"ceiling elements are exactly EE3/P4 (got {sorted(ce)})")
    cf = ceiling_flows(hand, ce)
    check(cf == {"DF13", "DF14"}, f"ceiling flows are exactly DF13/DF14 (got {sorted(cf)})")
    check(len(hand["elements"]) - len(ce) == 10, "element ceiling is 10/12")
    check(len(hand["flows"]) - len(cf) == 15, "flow ceiling is 15/17")


def test_self_alignment_identity():
    """Align the hand DFD against itself. Nothing is measured yet -- this asserts the matcher is
    reflexive, which every later number silently assumes."""
    print("\n[self-alignment: identity]")
    hand = _hand_dfd()
    keys = load_hand_keys("kidstube")
    derived_keys = {eid: hk.element_key for eid, hk in keys.items() if hk.computable}

    ea = align_elements(derived_keys, keys)
    check(all(d == h for d, h in ea.derived_to_hand.items()),
          "every element with a computable key aligns to itself")
    check(len(ea.hand_to_derived) == 11, f"11 of 12 hand elements matched (got {len(ea.hand_to_derived)})")
    check(ea.unmatched_hand == ["P4"], f"only P4 is unmatched (got {ea.unmatched_hand})")

    counts = element_derivability(keys, ea)
    check(counts.derivable_but_missed == 0,
          f"identity alignment misses nothing derivable (got {counts.derivable_but_missed})")
    check(counts.derivable_recall == 1.0, f"derivable_recall 1.00 (got {counts.derivable_recall:.2f})")

    fa = align_flows(hand, hand, ea)
    check(all(d == h for d, h in fa.derived_to_hand.items()), "every flow aligns to itself")
    # 15, not 17: DF13 (DS2->P4) and DF14 (P4->EE3) both have P4 as an endpoint, and P4 has no
    # computable key, so neither flow can project onto the hand side even under identity. The
    # ceiling test below arrives at the same 15 by a different route (P4 is unimplemented) --
    # they agree because "no code implements it" and "no key can be computed for it" are the same
    # fact seen from two directions.
    check(len(fa.hand_to_derived) == 15,
          f"15 of 17 flows matched -- DF13/DF14 hang off keyless P4 (got {len(fa.hand_to_derived)})")
    check(fa.unmatched_hand == ["DF13", "DF14"],
          f"the two unmatched flows are exactly DF13/DF14 (got {fa.unmatched_hand})")


def test_self_alignment_reproduces_the_ceiling():
    """The real M0 gate. Simulate a perfect adapter -- one that finds everything the code
    implements and nothing it doesn't -- and confirm the metric reports a clean ceiling rather
    than blaming the adapter for the two planned elements."""
    print("\n[self-alignment: a perfect adapter hits the ceiling, not an error]")
    hand = _hand_dfd()
    keys = load_hand_keys("kidstube")
    ce = ceiling_elements(keys)

    derived_dfd = copy.deepcopy(hand)
    derived_dfd["elements"] = [e for e in hand["elements"] if e["id"] not in ce]
    derived_dfd["flows"] = [f for f in hand["flows"]
                            if f["source"] not in ce and f["destination"] not in ce]
    derived_keys = {eid: hk.element_key for eid, hk in keys.items()
                    if hk.computable and hk.implemented}

    ea = align_elements(derived_keys, keys)
    fa = align_flows(derived_dfd, hand, ea)
    s = score(derived_dfd, hand, keys, ea, fa)

    check(s.elements.matched == 10, f"10 elements matched (got {s.elements.matched})")
    check(s.elements.structurally_underivable == 2,
          f"EE3/P4 counted as ceiling, not error (got {s.elements.structurally_underivable})")
    check(s.elements.derivable_but_missed == 0,
          f"no derivable element missed (got {s.elements.derivable_but_missed})")
    check(s.elements.unresolved_key == 0, f"no unresolved keys (got {s.elements.unresolved_key})")
    check(abs(s.elements.raw_recall - 10 / 12) < 1e-9, f"raw element recall 0.83 (got {s.elements.raw_recall:.2f})")
    check(s.elements.derivable_recall == 1.0,
          f"derivability-adjusted element recall 1.00 (got {s.elements.derivable_recall:.2f})")

    check(s.flows.matched == 15, f"15 flows matched (got {s.flows.matched})")
    check(s.flows.structurally_underivable == 2,
          f"DF13/DF14 counted as ceiling, not error (got {s.flows.structurally_underivable})")
    check(s.flows.derivable_but_missed == 0, f"no derivable flow missed (got {s.flows.derivable_but_missed})")
    check(s.flows.derivable_recall == 1.0,
          f"derivability-adjusted flow recall 1.00 (got {s.flows.derivable_recall:.2f})")
    check(s.element_precision_raw == 1.0, f"element precision 1.00 (got {s.element_precision_raw:.2f})")


def test_same_pair_flows_stay_distinct():
    """DF7 and DF10 are both P3->DS2 and carry 4 gold threats each. Collapsing them by pair would
    silently destroy 8 gold anchors, so the disambiguator has to keep them apart."""
    print("\n[DF7/DF10: same-pair flows are not merged]")
    hand = _hand_dfd()
    pairs = [(f["source"], f["destination"]) for f in hand["flows"]]
    check(pairs.count(("P3", "DS2")) == 2, "the hand DFD really does have two P3->DS2 flows")

    keys = load_hand_keys("kidstube")
    derived_keys = {eid: hk.element_key for eid, hk in keys.items() if hk.computable}
    ea = align_elements(derived_keys, keys)
    fa = align_flows(hand, hand, ea)

    check(fa.derived_to_hand.get("DF7") == "DF7" and fa.derived_to_hand.get("DF10") == "DF10",
          "DF7 and DF10 align to themselves, not to each other")
    check(fa.hand_to_derived.get("DF7") != fa.hand_to_derived.get("DF10"),
          "DF7 and DF10 resolve to distinct derived flows")
    check("DF7" in fa.ambiguous and "DF10" in fa.ambiguous,
          "both are flagged ambiguous -- resolved by a description heuristic, not by evidence")


def test_m0_gate_scenario_name_does_not_change_the_score():
    """The M0 gate: an identical DFD + gold must score identically under a DIFFERENT scenario name.

    The bug this pins was silent and total. eval/match.py chose its anchoring strategy with
    `scenario == "kidstube"`, so any other scenario -- including a byte-identical copy -- went
    down the location-anchored path, looked for dfd_source_id fields that 0 of KidsTube's 41 gold
    threats have, resolved every one to None, and returned P=R=F1=0.00 with no error. A broken
    matcher is indistinguishable from a broken adapter in that output.

    Deliberately built in-memory from the HAND scenario rather than read off
    knowledge_base/scenarios/kidstube_derived/. That directory used to hold an identity copy and
    now holds real adapter output, so reading it made this test pass for a coincidental reason:
    both DFDs number their flows DF1..DFn, so the ids collided numerically while meaning entirely
    different things (hand DF7 is "store/update child profile"; derived DF7 is "parent requests
    /api/users"). A gate that keeps reporting green after the thing it measures has been replaced
    is worse than no gate.
    """
    print("\n[M0 gate: the scenario's NAME must not change the score]")
    generated_path = config.ROOT / "storage" / "generated" / "kidstube_grounded.json"
    if not generated_path.exists():
        print("  skip  storage/generated/kidstube_grounded.json not present")
        return

    from eval.match import match_threats
    from generation.generate import load_generated

    generated = load_generated(str(generated_path))
    gold = json.loads((config.KB_DIR / "scenarios" / "kidstube" /
                        "gold_standard_threats.json").read_text())["threats"]
    dfd = _hand_dfd()

    results = {}
    for name in ("kidstube", "kidstube_derived", "some_other_name"):
        m = match_threats(generated, gold, scenario=name, dfd=dfd)
        results[name] = (m.tp, m.fp, m.fn)

    check(results["kidstube"] == (32, 86, 9),
          f"hand baseline is the published 32/86/9 (got {results['kidstube']})")
    check(len(set(results.values())) == 1,
          f"the same data scores the same under every name (got {results})")
    check(results["some_other_name"][0] > 0,
          "a differently-named scenario scores non-zero (0/x/x means anchoring broke silently)")


def _facts():
    path = config.ROOT / "adapters" / "data" / "kidstube_code_facts.json"
    if not path.exists():
        return None, None
    raw = json.loads(path.read_text())
    from adapters.schema import CodeFact
    return [CodeFact.from_dict(f) for f in raw["facts"]], raw["_meta"]


def test_extraction_resolves_the_filename_trap():
    """The four resolutions that separate real extraction from filename guessing.

    Runs off the COMMITTED facts, not a source checkout -- which is the point of committing them:
    these assertions hold on a clean clone with no tree-sitter installed and no network.
    """
    print("\n[extraction: the resolutions that filename heuristics get wrong]")
    facts, meta = _facts()
    if facts is None:
        print("  skip  adapters/data/kidstube_code_facts.json not present (run cli.py extract)")
        return

    from adapters.resolve import MountTable, base_path, pluralize, resolve_mongoose_collections

    check(meta.get("commit") is not None, f"facts pin a source commit ({meta.get('commit', '')[:8]})")

    cols = resolve_mongoose_collections(facts)
    parent = cols.get("backend/models/Parent.js")
    check(parent is not None and parent.model_name == "User",
          f"models/Parent.js registers model 'User', not 'Parent' (got {parent and parent.model_name})")
    check(parent is not None and parent.collection == "users",
          f"model 'User' -> collection 'users' == hand DS1 (got {parent and parent.collection})")
    child = cols.get("backend/models/Child.js")
    check(child is not None and child.collection == "childprofiles",
          f"models/Child.js -> model 'ChildProfile' -> 'childprofiles' == hand DS2 "
          f"(got {child and child.collection})")

    # The shortcut isn't merely risky here, it is demonstrably wrong: routes/auth.js binds
    # `const Child = require('../models/Child')`, but that module exports model 'ChildProfile'.
    # Pluralising the local name gives 'childs'; only the full chain gives 'childprofiles'.
    check(pluralize("Child")[0] == "childs" and pluralize("ChildProfile")[0] == "childprofiles",
          "local-name shortcut would yield 'childs'; the binding chain yields 'childprofiles'")

    mounts = MountTable.build(facts)
    subprofiles = [r for r in mounts.routes if r.mount_path == "/api/subprofiles"]
    check(subprofiles and all(r.router_file == "backend/routes/children.js" for r in subprofiles),
          "mount /api/subprofiles -> routes/children.js (the mount path is not the filename)")

    check(base_path(facts) == ("/api", "high"),
          f"both axios baseURL branches agree on the /api prefix (got {base_path(facts)})")


def test_express_dispatch_matches_registration_order():
    """routes/children.js registers GET /approved-videos (line 10) before GET /:id (line 132).
    Express is first-match-wins, so the literal call hits the literal route at runtime. A matcher
    that canonicalises both to /subprofiles/{p} attributes it to the wrong handler -- and
    therefore to the wrong db_operations, and therefore to a wrong flow."""
    print("\n[extraction: Express dispatch is first-match-wins, literal beats /:id]")
    facts, _ = _facts()
    if facts is None:
        print("  skip  no committed facts")
        return
    from adapters.resolve import MountTable
    mt = MountTable.build(facts)

    r = mt.resolve("GET", "/api/subprofiles/approved-videos")
    check(r is not None and r.router_path == "/approved-videos",
          f"GET /api/subprofiles/approved-videos -> /approved-videos, not /:id (got {r and r.router_path})")
    r = mt.resolve("GET", "/api/subprofiles/507f1f77bcf86cd799439011")
    check(r is not None and r.router_path == "/:id",
          f"GET /api/subprofiles/<oid> -> /:id (got {r and r.router_path})")
    r = mt.resolve("GET", "/api/videos/my-videos")
    check(r is not None and r.router_path == "/my-videos",
          f"GET /api/videos/my-videos -> /my-videos, not /:id (got {r and r.router_path})")
    r = mt.resolve("GET", "/api/users")
    check(r is not None and r.router_file == "backend/routes/users.js",
          "GET /api/users resolves (the admin-only bulk user listing)")


def test_facts_only_derivation_finds_everything_implemented():
    """The facts_only arm: no LLM, no API spend. This number is the bar the LLM has to clear."""
    print("\n[facts_only: deterministic derivation from committed facts]")
    facts, _ = _facts()
    if facts is None:
        print("  skip  no committed facts")
        return
    from adapters.align import align_elements, align_flows, derived_element_keys, load_hand_keys
    from adapters.evaluate import score
    from adapters.synthesize import synthesize_facts_only

    dfd = synthesize_facts_only(facts)
    check(not validate_dfd(dfd), f"the derived DFD conforms to the canonical schema "
                                 f"{validate_dfd(dfd)[:2]}")
    check(all(e.get("provenance") for e in dfd["elements"]),
          "every derived element cites at least one code fact")
    check(all(f.get("provenance") for f in dfd["flows"]),
          "every derived flow cites at least one code fact")

    fact_ids = {f.id for f in facts}
    cited = {p["fact_id"] for e in dfd["elements"] for p in e["provenance"]}
    check(cited <= fact_ids, "every cited fact id exists (closed vocabulary, by construction)")

    hand = _hand_dfd()
    hand_keys = load_hand_keys("kidstube")
    ea = align_elements(derived_element_keys(dfd, [f.to_dict() for f in facts]), hand_keys)
    fa = align_flows(dfd, hand, ea)
    s = score(dfd, hand, hand_keys, ea, fa)

    check(s.elements.derivable_but_missed == 0,
          f"finds every element the code implements (missed {s.elements.derivable_but_missed})")
    check(s.elements.derivable_recall == 1.0,
          f"element derivability-adjusted recall 1.00 (got {s.elements.derivable_recall:.2f})")
    # The ceiling must survive contact with a real derivation. If this ever reads 0, something
    # invented P4/EE3 out of thin air and the ceiling analysis is silently destroyed -- in the
    # direction that flatters the adapter. facts_only cannot do that (it only assembles facts);
    # the llm arm can, which is why this assertion outlives M1.
    check(s.elements.structurally_underivable == 2,
          f"EE3/P4 remain ceiling, not invented (got {s.elements.structurally_underivable})")
    check(s.flows.structurally_underivable == 2,
          f"DF13/DF14 remain ceiling (got {s.flows.structurally_underivable})")

    # The findings worth writing up: an admin actor and a user-management service that the
    # hand-authored DFD has no element for. Pinned so a later change can't quietly lose them.
    keys = derived_element_keys(dfd, [f.to_dict() for f in facts])
    unmatched = {str(keys[e]) for e in ea.unmatched_derived if e in keys}
    check("actor_role:admin" in unmatched,
          f"surfaces the admin actor the hand DFD lacks (unmatched: {sorted(unmatched)})")
    check("route_mount:/api/users" in unmatched,
          "surfaces /api/users, the service the hand DFD lacks")


def test_prefix_matched_stores_are_many_to_one():
    """backend/uploads and backend/uploads/images are both hand DS4 'File System
    (backend/uploads/)', at a finer grain. Forcing 1:1 made the loser a false positive AND
    silently cost DF15, whose flow projects through it."""
    print("\n[alignment: one hand store can cover several code directories]")
    facts, _ = _facts()
    if facts is None:
        print("  skip  no committed facts")
        return
    from adapters.align import align_elements, derived_element_keys, load_hand_keys
    from adapters.synthesize import synthesize_facts_only

    dfd = synthesize_facts_only(facts)
    keys = derived_element_keys(dfd, [f.to_dict() for f in facts])
    ea = align_elements(keys, load_hand_keys("kidstube"))

    ds4 = ea.hand_to_derived.get("DS4", [])
    paths = sorted(keys[d].key for d in ds4)
    check(len(ds4) == 2 and paths == ["backend/uploads", "backend/uploads/images"],
          f"both upload directories align to hand DS4 (got {paths})")
    check(len(ea.hand_to_derived.get("DS1", [])) == 1,
          "exact-keyed stores stay 1:1 (a second element on mongo_collection:users is a duplicate)")


def test_verifier_rejects_bad_citations():
    """A verifier that never fails isn't verifying. Each case here is a way a model could be
    wrong that the closed vocabulary alone would not catch."""
    print("\n[verify_dfd: bad citations are caught]")
    facts, _ = _facts()
    if facts is None:
        print("  skip  no committed facts")
        return
    from adapters.verify_dfd import NOT_CHECKED, verify_dfd
    from adapters.synthesize import synthesize_facts_only

    base = synthesize_facts_only(facts)
    mount = next(f for f in facts if f.construct == "express_mount")
    collection = next(f for f in facts if f.construct == "mongo_collection")

    # 1. a fabricated fact id -- the failure the closed vocabulary is designed to make impossible
    d = {"elements": [{"id": "P1", "type": "Process", "name": "Invented",
                       "provenance": [{"fact_id": "Fdeadbeef"}]}], "flows": []}
    ev, _ = verify_dfd(d, facts)
    check(not ev[0].citations_resolvable and not ev[0].all_valid,
          "a fabricated fact id is rejected")

    # 2. real citation, wrong evidence for the claimed type. The analogue of the mapping table's
    #    type_applicable check: naming a store but pointing at routing code.
    d = {"elements": [{"id": "DS1", "type": "DataStore", "name": "Not a store",
                       "provenance": [{"fact_id": mount.id}]}], "flows": []}
    ev, _ = verify_dfd(d, facts)
    check(ev[0].citations_resolvable and not ev[0].evidence_type_consistent,
          "a DataStore citing only an express_mount is rejected (citation real, evidence wrong)")

    # 3. every citation real and type-consistent, but the cited fact evidences a DIFFERENT edge.
    #    This is the check that makes the verifier falsifiable rather than a formality.
    d = {"elements": [{"id": "P1", "type": "Process", "name": "Auth",
                       "provenance": [{"fact_id": mount.id}]},
                      {"id": "DS1", "type": "DataStore", "name": "Store",
                       "provenance": [{"fact_id": collection.id}]}],
         "flows": [{"id": "DF1", "source": "P1", "destination": "DS1",
                    "description": "unevidenced edge",
                    "provenance": [{"fact_id": mount.id}]}]}
    _, fv = verify_dfd(d, facts)
    check(not fv[0].evidence_connects_endpoints,
          "a flow whose cited fact does not join its own endpoints is rejected")

    # 4. an unavailable check must never read as a pass -- the easiest way to fake a 1.00
    ev, _ = verify_dfd(base, facts, source_root=None)
    check(all(e.facts_present is NOT_CHECKED for e in ev),
          "without --source-root, facts_present is not_checked, not True")


def test_llm_arm_drops_uncitable_elements():
    """The confabulation guard, tested offline with a stubbed model response (no API call).

    The model knows this is a children's video platform. Asked for a DFD, it will want to emit an
    "AI Recommendation Engine" and "Third-Party Advertisers" -- the exact two elements that exist
    in no line of KidsTube. If it does and they survive, structurally_underivable silently drops
    from 2 to 0 and the ceiling analysis is destroyed *in the direction that flatters the
    adapter*. Prompt instructions are a request; dropping uncited elements is an invariant. No
    fact mentions those features, so in the closed-vocabulary arm they are literally uncitable.
    """
    print("\n[llm arm: an element nothing evidences cannot survive]")
    facts, _ = _facts()
    if facts is None:
        print("  skip  no committed facts")
        return
    from adapters.synthesize import _accept_elements, _accept_flows

    real = next(f for f in facts if f.construct == "express_mount")
    fact_ids = {f.id for f in facts}

    raw = [
        {"id": "P1", "type": "Process", "name": "Authentication Service",
         "fact_ids": [real.id]},
        # the two the model will want to invent -- with no citation, because none exists
        {"id": "P4", "type": "Process", "name": "AI Recommendation Engine", "fact_ids": []},
        {"id": "EE3", "type": "ExternalEntity", "name": "Third-Party Advertisers",
         "fact_ids": ["Fnotreal1"]},
    ]
    kept, rejected = _accept_elements(raw, fact_ids)
    names = {e["name"] for e in kept}
    check(names == {"Authentication Service"}, f"only the citable element survives (got {names})")
    check(len(rejected) == 2, f"both invented elements are rejected (got {len(rejected)})")
    check(any("AI Recommendation Engine" in r for r in rejected),
          "the uncited AI engine is rejected by name")
    check(any("Fnotreal1" in r for r in rejected),
          "an element citing a fabricated id is rejected, not kept with a warning")

    # A flow may not smuggle in an element that was rejected.
    flows, fl_rejected = _accept_flows(
        [{"id": "DF1", "source": "P1", "destination": "P4", "description": "to the AI engine",
          "fact_ids": [real.id]}], {e["id"] for e in kept}, fact_ids)
    check(not flows and fl_rejected, "a flow touching a rejected element is itself rejected")


def test_m4_anchorable_subset_and_restricted_recall():
    """M4: the hand baseline restricted to the anchorable subset, so the derived DFD is never
    blamed for flows it structurally lacks. Pins the subset accounting and the restricted recall
    against the committed hand output, so neither the re-anchoring nor the matcher can silently
    move the comparison.
    """
    print("\n[M4: hand baseline restricted to the anchorable subset]")
    from scripts.compare_derived_threats import anchorable_subset, score_recall

    hand_gold = json.loads((config.KB_DIR / "scenarios" / "kidstube" /
                            "gold_standard_threats.json").read_text())["threats"]
    derived_meta = json.loads((config.KB_DIR / "scenarios" / "kidstube_derived" /
                               "gold_standard_threats.json").read_text())["_meta"]
    hand_dfd = _hand_dfd()

    anchorable = anchorable_subset(hand_gold, derived_meta)
    check(len(anchorable) == 27,
          f"27 of 41 gold threats anchor to a flow the derived DFD has (got {len(anchorable)})")
    check({t["id"] for t in hand_gold} - anchorable == set(derived_meta["unanchored_threat_ids"]),
          "the excluded ids are exactly the derived gold's deliberately-unanchored 14")

    gen_path = config.ROOT / "storage" / "generated" / "kidstube_grounded.json"
    if not gen_path.exists():
        print("  skip  no committed kidstube_grounded.json to score")
        return
    from generation.generate import load_generated
    gen = load_generated(str(gen_path))
    full = score_recall(gen, hand_gold, "kidstube", hand_dfd)
    restricted = score_recall(gen, [t for t in hand_gold if t["id"] in anchorable],
                              "kidstube", hand_dfd)
    check(full.matched == 32, f"hand baseline recalls the published 32/41 (got {full.matched})")
    check(restricted.n_gold == 27 and restricted.matched <= full.matched,
          f"restriction scores on 27 and cannot add matches (got gold={restricted.n_gold}, "
          f"match={restricted.matched})")
    check(restricted.matched == 19,
          f"19 of the 27 anchorable gold threats are recalled by grounded (got {restricted.matched})")


def test_naive_arm_has_no_confabulation_guard():
    """The llm_naive arm's defining property: it drops the confabulation guard the `llm` arm relies
    on. An element citing nothing, or a hallucinated line, SURVIVES here -- that absence is what the
    open-vocabulary ablation measures. Structural well-formedness (unique ids, valid types, declared
    endpoints) is still enforced, because a malformed graph is broken in any vocabulary.
    """
    print("\n[llm_naive: no confabulation guard, by design]")
    from adapters.synthesize import _accept_elements, _accept_elements_naive, _accept_flows_naive

    raw = [
        {"id": "P1", "type": "Process", "name": "Authentication Service",
         "citations": [{"file": "backend/routes/auth.js", "line": 12}]},
        # the two the model's world-knowledge wants to invent -- one uncited, one citing a ghost line
        {"id": "P4", "type": "Process", "name": "AI Recommendation Engine", "citations": []},
        {"id": "EE3", "type": "ExternalEntity", "name": "Third-Party Advertisers",
         "citations": [{"file": "backend/nope.js", "line": 999}]},
        {"id": "P1", "type": "Process", "name": "dup id"},          # rejected: duplicate
        {"id": "Z", "type": "Widget", "name": "bad type"},          # rejected: not an element type
    ]
    kept, rejected = _accept_elements_naive(raw)
    check({e["id"] for e in kept} == {"P1", "P4", "EE3"},
          f"uncited / ghost-cited elements SURVIVE -- the absent guard is the measurement "
          f"(kept {sorted(e['id'] for e in kept)})")
    check(any("duplicate" in r for r in rejected) and any("malformed" in r for r in rejected),
          "structural well-formedness is still enforced (dup id, bad type rejected)")
    check(next(e for e in kept if e["id"] == "EE3")["provenance"] == [{"file": "backend/nope.js",
                                                                       "line": 999}],
          "the ghost citation is kept verbatim, for verify_dfd to catch -- not silently dropped")

    # The contrast the whole ablation rests on: the closed arm DROPS exactly these two.
    closed_kept, _ = _accept_elements(raw, {"Fsomethingreal"})
    check("P4" not in {e["id"] for e in closed_kept} and "EE3" not in {e["id"] for e in closed_kept},
          "the closed `llm` arm drops P4/EE3 -- so the two arms differ in exactly the guard")

    flows, frej = _accept_flows_naive(
        [{"id": "DF1", "source": "P1", "destination": "P4", "description": "to the AI engine",
          "citations": [{"file": "a.js", "line": 1}]},
         {"id": "DF2", "source": "P1", "destination": "GHOST", "description": "dangling",
          "citations": []}],
        {e["id"] for e in kept})
    check([f["id"] for f in flows] == ["DF1"] and any("GHOST" in r for r in frej),
          "a flow to a non-emitted element is still rejected (graph well-formedness, not grounding)")


def test_naive_prompts_build_without_format_errors():
    """Both naive prompts are assembled with str.format, and the instructions legitimately contain
    literal braces ('{file, line}'). A single unescaped brace raises KeyError at prompt-build time
    -- AFTER the elements LLM call has already been billed. Building them offline here catches that
    whole class of bug before it can burn a live call."""
    print("\n[llm_naive: prompts assemble offline, no str.format KeyError]")
    from adapters.synthesize import _elements_prompt_naive, _flows_prompt_naive

    src = "--- a.js\n    1| const x = 1;"
    ep = _elements_prompt_naive(src)
    check("{file, line}" in ep and src in ep,
          "elements prompt renders the literal {file, line} guidance and the source")
    fp = _flows_prompt_naive(src, [{"id": "P1", "type": "Process", "name": "Auth Service"}])
    check("{file, line}" in fp and "P1" in fp and src in fp,
          "flows prompt renders {file, line}, the accepted elements, and the source")


def test_naive_open_citations_verified_against_source():
    """The finding this arm exists to produce: an OPEN file:line citation can fail to verify, where
    the closed arm's fact-id citation is resolvable ~1.00 by construction. Driven with committed
    facts standing in for a re-parse (same commit), so it needs no live source checkout.
    """
    print("\n[llm_naive: open file:line citations are independently re-derived]")
    facts, _ = _facts()
    if facts is None:
        print("  skip  no committed facts")
        return
    from adapters.verify_dfd import (NOT_CHECKED, _loc_index, _resolve_item_facts, verify_element,
                                     verify_flow)
    from adapters.resolve import MountTable

    facts_by_id = {f.id: f for f in facts}
    loc_index = _loc_index(facts_by_id)          # committed facts == a re-parse at the pinned commit
    max_line: dict[str, int] = {}
    for f in facts:
        max_line[f.file] = max(max_line.get(f.file, 0), f.line)
    line_counts = {file: n + 50 for file, n in max_line.items()}
    reextracted = facts_by_id                    # non-None => facts_present is actually checked

    mount = next(f for f in facts if f.construct == "express_mount")
    collection = next(f for f in facts if f.construct == "mongo_collection")

    def open_el(etype, loc):
        e = {"id": "E", "type": etype, "name": "E", "provenance": [{"file": loc[0], "line": loc[1]}]}
        return verify_element(e, facts_by_id, _resolve_item_facts(e, facts_by_id, loc_index),
                              reextracted, loc_index, line_counts)

    good = open_el("Process", (mount.file, mount.line))
    check(good.citations_resolvable is True and good.evidence_type_consistent is True
          and good.facts_present is True and good.all_valid is True,
          "an open citation landing on a real matching construct verifies clean")

    ghost_line = (mount.file, line_counts[mount.file] - 1)   # a real file, a line with no construct
    ghost = open_el("Process", ghost_line)
    check(ghost.citations_resolvable is True and ghost.facts_present is False
          and not ghost.all_valid,
          "a real line holding no construct: location resolves, facts_present fails (the drop)")

    hallucinated = open_el("Process", ("backend/nope.js", 999))
    check(hallucinated.citations_resolvable is False and not hallucinated.all_valid,
          "a hallucinated file:line is caught -- an open vocabulary can point anywhere")

    no_source = verify_element(
        {"id": "E", "type": "Process", "name": "E",
         "provenance": [{"file": mount.file, "line": mount.line}]},
        facts_by_id, [], None, None, None)
    check(no_source.citations_resolvable is NOT_CHECKED and no_source.all_valid is NOT_CHECKED,
          "without a source to re-parse, an open citation is not_checked -- never a fake 1.00")

    # A flow whose open citation genuinely links its endpoints reuses the closed arm's connection
    # check unchanged, once the file:line resolves to the same fact.
    route_to_mount = {r.fact_id: r.mount_path for r in MountTable.build(facts).routes}
    triple = None
    for f in facts:
        if (f.construct == "db_access"
                and route_to_mount.get(f.fields.get("route_fact_id")) == mount.fields["mount_path"]):
            col = next((c for c in facts if c.construct == "mongo_collection"
                        and c.fields["collection"] == f.fields.get("collection")), None)
            if col:
                triple = (f, col)
                break
    if triple is not None:
        dba, col = triple
        proc = {"id": "P1", "type": "Process", "name": "P1",
                "provenance": [{"file": mount.file, "line": mount.line}]}
        store = {"id": "DS1", "type": "DataStore", "name": "DS1",
                 "provenance": [{"file": col.file, "line": col.line}]}
        flow = {"id": "DF1", "source": "P1", "destination": "DS1", "description": "db op",
                "provenance": [{"file": dba.file, "line": dba.line}]}
        elements_by_id = {"P1": proc, "DS1": store}
        element_facts = {"P1": _resolve_item_facts(proc, facts_by_id, loc_index),
                         "DS1": _resolve_item_facts(store, facts_by_id, loc_index)}
        fv = verify_flow(flow, elements_by_id, element_facts,
                         _resolve_item_facts(flow, facts_by_id, loc_index), facts_by_id,
                         route_to_mount, reextracted, loc_index, line_counts)
        check(fv.evidence_connects_endpoints is True and fv.all_valid is True,
              "a naive flow whose open citation truly links its endpoints verifies clean")


def test_verifier_takes_no_llm_and_no_network():
    """generation/verify.py's contract, restated one level up: the verifier is deterministic.
    A verifier that asked a model whether the model was right would relocate the self-report
    problem, not solve it."""
    print("\n[verify_dfd: deterministic by construction]")
    src = (config.ROOT / "adapters" / "verify_dfd.py").read_text()
    for forbidden in ("llm_backend", "get_llm_backend", "anthropic", "openai", "requests"):
        check(forbidden not in src, f"verify_dfd.py never imports/mentions {forbidden!r}")


def test_vision_arm_has_no_confabulation_guard():
    """The image arm's absent guard, mirroring test_naive_arm_has_no_confabulation_guard.

    An element citing a box that lands nowhere -- or citing nothing at all -- must be KEPT, so
    that verify_vision.py gets to report it. If acceptance quietly dropped it, the arm would
    measure the guard instead of the model.
    """
    print("\n[vision arm: no confabulation guard]")
    from adapters.vision import _accept_elements, _accept_flows

    raw = [{"id": "P1", "type": "Process", "name": "Invented Service",
            "citations": [{"x": 999999, "y": 999999, "w": 10, "h": 10, "label_text": "nope"}]},
           {"id": "EE1", "type": "ExternalEntity", "name": "Uncited Actor", "citations": []}]
    kept, rejected = _accept_elements(raw)
    check(len(kept) == 2, "an element citing an off-image box is kept, not dropped")
    check(rejected == [], "and nothing is rejected for citing badly")
    check(kept[1]["provenance"] == [], "an element citing nothing keeps empty provenance")

    malformed = [{"id": "P2", "type": "Process", "name": "Bad Box",
                  "citations": [{"x": "a", "y": 1, "w": 1, "h": 1, "label_text": "x"}]}]
    kept2, _ = _accept_elements(malformed)
    check(kept2[0]["provenance"] == [],
          "a malformed box is dropped so the DFD stays schema-valid, but the element survives")

    flows, fl_rejected = _accept_flows(
        [{"id": "DF1", "source": "P1", "destination": "GHOST", "description": "x",
          "citations": []}], {"P1", "EE1"})
    check(flows == [] and len(fl_rejected) == 1,
          "a flow to a non-emitted element IS rejected (malformed in any vocabulary)")


def test_vision_provenance_is_a_third_vocabulary():
    """bbox provenance validates, and mixing vocabularies does not."""
    print("\n[schema: bbox is a third citation vocabulary]")
    dfd = {"_meta": {"schema_version": 2},
           "elements": [{"id": "P1", "type": "Process", "name": "S",
                         "provenance": [{"bbox": [1, 2, 3, 4], "label_text": "S"}]}],
           "flows": []}
    check(validate_dfd(dfd) == [], "a bbox-cited element is schema-valid")

    mixed = copy.deepcopy(dfd)
    mixed["elements"][0]["provenance"] = [{"bbox": [1, 2, 3, 4], "fact_id": "F1"}]
    check(any("more than one vocabulary" in e for e in validate_dfd(mixed)),
          "citing a bbox AND a fact_id is rejected")

    bad = copy.deepcopy(dfd)
    bad["elements"][0]["provenance"] = [{"bbox": [1, 2, "3"]}]
    check(any("bbox" in e for e in validate_dfd(bad)),
          "a bbox that is not four ints is rejected")

    none = copy.deepcopy(dfd)
    none["elements"][0]["provenance"] = [{"label_text": "S"}]
    check(any("no vocabulary" in e for e in validate_dfd(none)),
          "provenance citing no vocabulary at all is still rejected")


def test_vision_verifier_takes_no_llm_and_no_network():
    """Same rule as verify_dfd: a verifier that asks a model whether the model was right is not a
    verifier. This one only ever does arithmetic over pixels."""
    print("\n[verify_vision: deterministic by construction]")
    src = (config.ROOT / "adapters" / "verify_vision.py").read_text()
    for forbidden in ("llm_backend", "get_llm_backend", "anthropic", "openai", "requests"):
        check(forbidden not in src, f"verify_vision.py never imports/mentions {forbidden!r}")


def test_vision_scale_calibration_is_reported_not_hidden():
    """A citation in the wrong coordinate frame must not silently pass, and the frame correction
    must be visible in the report either way -- the gap between the two rates IS the finding."""
    print("\n[verify_vision: scale calibration]")
    import numpy as np
    from adapters.verify_vision import calibrate_scale, ink_coverage, verify_element_or_flow

    # Two small blobs, each exactly 2x where its citation says. Kept tight on purpose: with big
    # boxes many scales overlap and the fixture would not discriminate between them.
    grey = np.full((400, 400), 255, dtype=np.uint8)
    grey[200:204, 200:204] = 0
    grey[300:304, 100:104] = 0
    dfd = {"elements": [{"id": "P1", "type": "Process", "name": "S",
                         "provenance": [{"bbox": [100, 100, 2, 2]}]},
                        {"id": "P2", "type": "Process", "name": "T",
                         "provenance": [{"bbox": [50, 150, 2, 2]}]}], "flows": []}

    check(ink_coverage(dfd, grey, 1.0) == 0.0, "at stated coordinates the boxes land on nothing")
    scale, cov = calibrate_scale(dfd, grey)
    check(scale == 2.0 and cov == 1.0, f"calibration recovers the 2.0 frame (got {scale}, {cov})")

    v = verify_element_or_flow(dfd["elements"][0], "element", grey, 400, 400, scale=1.0)
    check(v.citations_resolvable is True, "the box is in bounds -- resolvable passes")
    check(v.region_has_content is False, "but it lands on no content -- that check fails")
    check(v.all_valid is False, "so all_valid is False, not a quiet pass")

    empty = {"elements": [{"id": "P1", "type": "Process", "name": "S", "provenance": []}],
             "flows": []}
    ve = verify_element_or_flow(empty["elements"][0], "element", grey, 400, 400)
    check(ve.all_valid is False and "cites no image region" in ve.reasons[0],
          "an item citing no region at all fails rather than vacuously passing")


def test_vision_image_content_is_only_built_when_an_image_is_given():
    """The text-only path must stay byte-identical over the wire now that images exist -- every
    existing generation run depends on it."""
    print("\n[llm_backend: image is opt-in]")
    from generation.llm_backend import ImageInput, _anthropic_content, _openai_content

    check(_openai_content("hi", None) == "hi", "openai content with no image is a bare string")
    check(_anthropic_content("hi", None) == "hi", "anthropic content with no image is a bare string")

    img = ImageInput("QUJD", "image/png")
    o = _openai_content("hi", img)
    check(isinstance(o, list) and o[1]["image_url"]["url"].startswith("data:image/png;base64,"),
          "openai wraps the image as a data: URL part")
    a = _anthropic_content("hi", img)
    check(isinstance(a, list) and a[1]["source"]["media_type"] == "image/png",
          "anthropic wraps the image as a base64 source block")


def test_vision_prompts_build_without_format_errors():
    """The llm_naive lesson: a literal {x, y, w, h} in a prompt is a str.format KeyError that only
    fires AFTER the first call has been billed. Assemble both prompts with no model."""
    print("\n[vision prompts build offline]")
    from adapters.vision import _elements_prompt, _flows_prompt

    ep = _elements_prompt(800, 600)
    check("800 x 600" in ep, "the elements prompt states the real pixel dimensions")
    fp = _flows_prompt(800, 600, [{"id": "P1", "type": "Process", "name": "Auth"}])
    check("P1" in fp and "Auth" in fp, "the flows prompt carries the accepted elements")
    check("{x, y, w, h}" in fp, "and the literal brace example survives formatting")


def test_run_condition_keys_round_trip():
    """A condition key must survive being written to a path and read back, because the run index
    reads keys off the filesystem rather than re-deriving them from metadata older artifacts
    may not carry."""
    print("\n[runs: condition keys]")
    import runs

    check(runs.slug("gpt-5.4") == "gpt-5-4", "model ids are path-sanitised (dots -> dashes)")
    check(runs.slug("anthropic/claude-sonnet-5") == "anthropic-claude-sonnet-5",
          "slashes too -- they would otherwise become directory separators")
    check(runs.slug(None) == "none" and runs.slug("") == "none",
          "a missing model is 'none', never empty")

    cond = runs.condition("image", "vision_naive", "gpt-5.4")
    check(cond == "image_vision-naive_gpt-5-4", f"condition key is <input>_<arm>_<model> ({cond})")
    parsed = runs.parse_condition(cond)
    check(parsed == {"input": "image", "arm": "vision-naive", "model": "gpt-5-4"},
          "and parses back to its three parts")
    check(runs.parse_condition(runs.condition("source", "llm_naive", None))["model"] == "none",
          "a model-free arm round-trips as 'none'")

    try:
        runs.condition("diagram", "x", "y")
        check(False, "an unknown input kind is rejected")
    except ValueError:
        check(True, "an unknown input kind is rejected")


def test_run_aggregation_never_fakes_a_spread():
    """n=1 must report sd as unknown, not 0.00. Zero spread and unknown spread are different
    claims, and the llm arm's 0.33-0.87 range is exactly why the difference matters."""
    print("\n[runs: aggregation]")
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
    import summarize_runs as sr

    one = sr._stat([0.71])
    check(one["n"] == 1 and one["mean"] == 0.71 and one["sd"] is None,
          "a single run reports sd=None, not 0.00")
    check("n=1" in sr._fmt(one), "and renders as an explicit point estimate")

    three = sr._stat([0.33, 0.73, 0.87])
    check(three["n"] == 3 and abs(three["mean"] - 0.6433) < 0.001, "means are computed over runs")
    check(three["sd"] is not None and three["sd"] > 0.2,
          "and the llm arm's real spread survives aggregation")
    check(sr._stat([])["mean"] is None, "no runs reports nothing rather than zero")


def test_run_index_parses_a_real_eval_report():
    """The index reads committed eval reports; if the ALL row moves, every row goes blank."""
    print("\n[runs: eval report parsing]")
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
    import summarize_runs as sr

    report = (config.ROOT / "storage" / "generated"
              / "kidstube_image_derived_grounded_eval.txt")
    if not report.exists():
        check(True, "(committed image eval report absent -- skipped)")
        return
    parsed = sr.parse_eval(report.read_text())
    check(parsed is not None, "the ALL row is found in a real report")
    check((parsed["tp"], parsed["fp"], parsed["fn"]) == (29, 89, 12),
          f"TP/FP/FN read correctly {(parsed['tp'], parsed['fp'], parsed['fn'])}")
    check(parsed["recall"] == 0.71 and parsed["precision"] == 0.25, "P/R read correctly")
    check(parsed["citation_all_valid"] == 1.00, "citation all_valid_rate read correctly")
    check(parsed["n_generated"] == 118, "n_generated read correctly")


def test_explicit_dfd_and_gold_overrides():
    """--dfd/--gold must load the same content the scenario defaults do, or every experiment run
    is scored against something other than what it was generated from."""
    print("\n[generate/eval: explicit path overrides]")
    from eval.run_eval import _load_dfd, _load_gold

    scen_dfd = _load_dfd("kidstube_image_derived")
    path_dfd = _load_dfd("ignored", config.KB_DIR / "scenarios" / "kidstube_image_derived"
                         / "dfd.json")
    check(scen_dfd == path_dfd, "an explicit --dfd loads exactly the scenario's own DFD")

    scen_gold = _load_gold("kidstube")
    path_gold = _load_gold("ignored", config.KB_DIR / "scenarios" / "kidstube"
                           / "gold_standard_threats.json")
    check(scen_gold == path_gold, "an explicit --gold loads exactly the scenario's own gold")

    import json as _json
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        bare = Path(d) / "gold.json"
        bare.write_text(_json.dumps(scen_gold))
        check(_load_gold("ignored", bare) == scen_gold,
              "a bare-list gold (what a re-anchoring script may emit) loads too")


def test_gold_rebuild_guards_its_own_precondition():
    """Re-anchoring keys derived elements by the CODE FACTS they cite, so it is inapplicable to a
    DFD that cites pixel boxes. And an id-overlap test must be exact, not a subset: kidstube_derived
    numbers its 27 flows DF1..DF27, which CONTAINS the hand DFD's DF1..DF17 while meaning entirely
    different flows. A subset test would skip the re-anchoring that DFD absolutely needs."""
    print("\n[gold rebuild: preconditions]")
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
    import build_kidstube_derived_gold as bg

    hand = _hand_dfd("kidstube")
    image = json.loads((config.KB_DIR / "scenarios" / "kidstube_image_derived"
                        / "dfd.json").read_text())
    source = json.loads((config.KB_DIR / "scenarios" / "kidstube_derived"
                         / "dfd.json").read_text())

    check(bg.cites_code_facts(source), "the source-derived DFD cites fact_ids -- re-anchorable")
    check(not bg.cites_code_facts(image),
          "the image-derived DFD cites bboxes, not fact_ids -- NOT re-anchorable this way")

    check(bg.flow_ids_identical(image, hand),
          "the image DFD's flow ids are exactly the hand DFD's -- hand gold applies verbatim")
    check(not bg.flow_ids_identical(source, hand),
          "the source DFD's are not, despite DF1..DF17 being a SUBSET of its DF1..DF27")
    check({f["id"] for f in hand["flows"]} <= {f["id"] for f in source["flows"]},
          "...and that subset really does hold -- which is exactly why the test must be equality")


def test_every_derived_artifact_is_attributable():
    """Which model produced a derived DFD is the axis the experiment varies. An artifact that
    does not say is not comparable, and 'absent' must not be usable as 'deterministic'."""
    print("\n[metadata: model attribution]")
    for scen in ("kidstube_derived", "kidstube_image_derived"):
        meta = json.loads((config.KB_DIR / "scenarios" / scen / "dfd.json").read_text())["_meta"]
        df = meta.get("derived_from", {})
        check("model" in df and df["model"], f"{scen} records which model produced it")
        check("backend" in df and df["backend"], f"{scen} records which backend produced it")
    facts_only = json.loads((config.KB_DIR / "scenarios" / "kidstube_derived"
                             / "dfd.json").read_text())["_meta"]
    check(facts_only["derived_from"]["model"] == "none",
          "facts_only records model='none' EXPLICITLY -- it is deterministic, not unrecorded")


if __name__ == "__main__":
    test_schema_backward_compatible()
    test_schema_rejects_broken_dfds()
    test_key_matching()
    test_hand_keys_cover_the_hand_dfd()
    test_ceiling_is_computed_from_data()
    test_self_alignment_identity()
    test_self_alignment_reproduces_the_ceiling()
    test_same_pair_flows_stay_distinct()
    test_m0_gate_scenario_name_does_not_change_the_score()
    test_extraction_resolves_the_filename_trap()
    test_express_dispatch_matches_registration_order()
    test_facts_only_derivation_finds_everything_implemented()
    test_prefix_matched_stores_are_many_to_one()
    test_verifier_rejects_bad_citations()
    test_verifier_takes_no_llm_and_no_network()
    test_llm_arm_drops_uncitable_elements()
    test_naive_arm_has_no_confabulation_guard()
    test_naive_prompts_build_without_format_errors()
    test_naive_open_citations_verified_against_source()
    test_m4_anchorable_subset_and_restricted_recall()
    test_vision_arm_has_no_confabulation_guard()
    test_vision_provenance_is_a_third_vocabulary()
    test_vision_verifier_takes_no_llm_and_no_network()
    test_vision_scale_calibration_is_reported_not_hidden()
    test_vision_image_content_is_only_built_when_an_image_is_given()
    test_vision_prompts_build_without_format_errors()
    test_run_condition_keys_round_trip()
    test_run_aggregation_never_fakes_a_spread()
    test_run_index_parses_a_real_eval_report()
    test_explicit_dfd_and_gold_overrides()
    test_gold_rebuild_guards_its_own_precondition()
    test_every_derived_artifact_is_attributable()
    print(f"\n{PASS} passed, {FAIL} failed")
    sys.exit(1 if FAIL else 0)
