"""Parity: verify_certificate_chain against the vendored verifier parity corpus.

The corpus (testdata/parity-corpus, vendored at the commit in SOURCE.json,
format lucairn-parity-corpus/v1.2.1) carries, per case, the result every Lucairn
verifier must return under every policy — every field, ``verified`` compared
as canonical JSON — and the pinned-key policy vectors (key-policy.json). The
TS (ts/src/verify-chain/parityCorpus.test.ts) and Go (go/parity_corpus_test.go)
SDKs run the same cases against the same expectations.

The corpus keys are TEST keys (their private keys follow from a public seed):
this harness is the only place that loads them, with ``allow_test_keys=True``.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from lucairn import (
    CertificateChainKeys,
    PinnedKeyError,
    verify_certificate_chain,
)
from lucairn.errors import LucairnCertificateError
from lucairn.types import VerifyCertificateKeys
from lucairn.verify_certificate import canonical_json
from lucairn.verify_certificate import chain as chain_mod
from lucairn.verify_certificate import verify_certificate

CORPUS_ROOT = Path(__file__).resolve().parents[2] / "testdata" / "parity-corpus"
CORPUS = CORPUS_ROOT / "v1"
SOURCE = json.loads((CORPUS_ROOT / "SOURCE.json").read_text())
MANIFEST = json.loads((CORPUS / "manifest.json").read_text())
KEYS = json.loads((CORPUS / "keys.json").read_text())
KEY_POLICY = json.loads((CORPUS / "key-policy.json").read_text())

FORMAT = "lucairn-parity-corpus/v1.2.1"
EXPECTED_CASES = 84
# SOURCE.json records no hash for key-policy.json; pin it here so a changed
# vector file cannot pass silently.
V2_SIGNABLE_KEYS = {
    "certificate_id", "claim_ids", "issued_at", "overall_verdict", "protocol_version", "request_id", "witness_key_id",
}
V3_SIGNABLE_KEYS = V2_SIGNABLE_KEYS | {
    "api_key_id", "byok_exempt", "client_id", "redaction_manifest_hash", "sanitized_fields_body_hash", "tms_manifest_hash",
}
RESULT_FIELDS = [
    "verdict", "reason", "egress_attestation", "user_unredacted", "signed_cert_tier",
    "signable_version", "request_binding", "verified",
]


def _sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def _load_case(p: Path) -> Any:
    """A case file: plain JSON with number lexemes kept (a case carries a
    5,000-digit integer token), WITHOUT the verifier-input rules — a case file
    wraps inputs that break them on purpose."""
    return json.loads(p.read_text(encoding="utf-8"), parse_int=chain_mod._Num, parse_float=chain_mod._Num)


CASES = {mc["id"]: _load_case(CORPUS / mc["file"]) for mc in MANIFEST["cases"]}


def _keys(*, allow_test_keys: bool = True) -> CertificateChainKeys:
    return CertificateChainKeys(
        witness_key_id=KEYS["witness"]["key_id"],
        witness_public_key=KEYS["witness"]["public_key_base64"],
        service_public_keys={s: v["public_key_base64"] for s, v in KEYS["services"].items()},
        allow_test_keys=allow_test_keys,
    )


def _raw(case: Any) -> bytes:
    """The verifier input: `certificate_text` verbatim when present, else the
    certificate's JSON text with every number lexeme kept."""
    if "certificate_text" in case:
        return case["certificate_text"].encode("utf-8")
    return chain_mod._canonical(case["certificate"]).encode()


def _policy_arg(policy: dict) -> str | None:
    return None if policy["minimum_signable_version"] == "v2" else policy["minimum_signable_version"]


def _inputs(case: Any) -> dict[str, str]:
    return dict(case.get("inputs") or {})


def _parity_form(result: dict[str, Any], canon) -> dict[str, Any]:
    return dict(result, verified=canon(result["verified"]))


def _got_canon(v: Any) -> str:
    """The SDK's result, canonicalised by the SDK's public canonical_json (an
    independent serializer from the verifier's internal one)."""
    return "null" if v is None else canonical_json(v).decode("ascii")


def _want_canon(v: Any) -> str:
    return chain_mod._canonical(v)


# --- the vendored copy is exactly the recorded one ---------------------------


def test_vendored_corpus_matches_recorded_hashes() -> None:
    assert SOURCE["format"] == MANIFEST["format"] == KEYS["format"] == KEY_POLICY["format"] == FORMAT
    assert _sha(CORPUS / "manifest.json") == SOURCE["manifest_sha256"], "manifest drifted: re-run testdata/parity-corpus/sync.sh"
    assert _sha(CORPUS / "keys.json") == SOURCE["keys_sha256"], "keys drifted: re-run testdata/parity-corpus/sync.sh"
    assert _sha(CORPUS_ROOT / "recipe-table.md") == SOURCE["recipe_table_sha256"], "recipe-table.md drifted: re-run testdata/parity-corpus/sync.sh"
    assert _sha(CORPUS / "key-policy.json") == SOURCE["key_policy_sha256"], "key-policy.json drifted"
    assert (MANIFEST["keys"], MANIFEST["key_policy"]) == ("keys.json", "key-policy.json")
    assert sorted(p.name for p in CORPUS.iterdir()) == ["cases", "key-policy.json", "keys.json", "manifest.json"]
    on_disk = sorted(p.name for p in (CORPUS / "cases").iterdir())
    listed = sorted(Path(c["file"]).name for c in MANIFEST["cases"])
    assert on_disk == listed
    for c in MANIFEST["cases"]:
        assert _sha(CORPUS / c["file"]) == c["sha256"], f"{c['id']} drifted from its manifest sha256"
        case = CASES[c["id"]]
        assert (case["format"], case["id"], case["class"], case["surface"]) == (FORMAT, c["id"], c["class"], c["surface"])
        assert case.get("inputs") == c.get("inputs")


def test_manifest_bounds_are_the_sdks() -> None:
    assert MANIFEST["max_input_bytes"] == chain_mod.MAX_INPUT_BYTES == 32 << 20
    assert MANIFEST["max_depth"] == chain_mod.MAX_DEPTH == 256
    assert MANIFEST["max_values_pointer_bytes"] == chain_mod.MAX_VALUES_POINTER_BYTES == 64 << 20


# --- the recipe table is the spec's ------------------------------------------


def test_step_table_equals_spec() -> None:
    spec = (CORPUS_ROOT / "recipe-table.md").read_text()
    table = spec.split("<!-- recipe-table:begin -->")[1].split("<!-- recipe-table:end -->")[0]
    rows = []
    for line in table.strip().splitlines()[2:]:
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        m = re.fullmatch(r"(\S+) `(\S+)`", cells[2])
        assert m, line
        rows.append((cells[0], m.group(1), m.group(2)))
    assert tuple(rows) == chain_mod.STEPS


def test_reason_vocabulary_is_the_manifests() -> None:
    assert sorted({r for _, _, r in chain_mod.STEPS}) == sorted(MANIFEST["reasons"])
    assert sorted({v for _, v, _ in chain_mod.STEPS}) == sorted(MANIFEST["verdicts"])
    # every reason is some case's expected reason
    exercised = {c["expected"][p["name"]]["reason"] for c in MANIFEST["cases"] for p in MANIFEST["policies"]}
    assert exercised == set(MANIFEST["reasons"])


# --- parity: every case × every policy, every field ---------------------------


def test_every_case_every_policy_matches_expected() -> None:
    keys = _keys()
    assert len(MANIFEST["cases"]) == EXPECTED_CASES
    assert [p["name"] for p in MANIFEST["policies"]] == ["default", "minimum_v3"]
    passed = {p["name"]: 0 for p in MANIFEST["policies"]}
    mismatches = []
    for mc in MANIFEST["cases"]:
        case = CASES[mc["id"]]
        raw = _raw(case)
        assert set(case["expected"]) == {p["name"] for p in MANIFEST["policies"]}
        for policy in MANIFEST["policies"]:
            want = case["expected"][policy["name"]]
            # the manifest carries the same expectation without `verified`
            assert {k: v for k, v in want.items() if k != "verified"} == mc["expected"][policy["name"]]
            assert list(want) == RESULT_FIELDS

            result = verify_certificate_chain(raw, keys, minimum_signable_version=_policy_arg(policy), **_inputs(case))
            got = result.to_dict()
            assert list(got) == RESULT_FIELDS
            if _parity_form(got, _got_canon) == _parity_form(want, _want_canon):
                passed[policy["name"]] += 1
            else:
                mismatches.append((mc["id"], policy["name"], got, want))

            # closed vocabularies
            assert got["verdict"] in MANIFEST["verdicts"]
            assert got["reason"] in MANIFEST["reasons"]
            assert got["egress_attestation"] in MANIFEST["egress_states"]
            assert got["user_unredacted"] in MANIFEST["user_unredacted"]
            assert got["signed_cert_tier"] in MANIFEST["signed_cert_tiers"]
            assert got["signable_version"] in MANIFEST["signable_versions"]
            assert got["request_binding"] in MANIFEST["request_bindings"]
            assert mc["class"] in MANIFEST["classes"]
            # FAILED <=> unknown / not_evaluated / none / not_evaluated / verified null
            failed_shape = (
                got["user_unredacted"] == "unknown"
                and got["egress_attestation"] == "not_evaluated"
                and got["signed_cert_tier"] == "not_evaluated"
                and got["signable_version"] == "none"
                and got["request_binding"] == "not_evaluated"
                and got["verified"] is None
            )
            assert (got["verdict"] == "FAILED") == failed_shape, (mc["id"], policy["name"])
            # request_binding is `matched` exactly on the non-FAILED cases with inputs
            if got["verdict"] != "FAILED":
                assert (got["request_binding"] == "matched") == bool(case.get("inputs")), mc["id"]
            # class rules
            if mc["class"] == "tamper" and not (mc["id"] == "tamper_v3_stripped_metadata_forged" and policy["name"] == "default"):
                assert got["verdict"] == "FAILED", (mc["id"], policy["name"])
            if mc["class"] == "edge":
                assert got["verdict"] != "VERIFIED", mc["id"]
            # `verified` shape: the signable that verified, one entry per claim
            if got["verified"] is not None:
                v = got["verified"]
                assert set(v) == {"certificate", "claims"}
                want_keys = V3_SIGNABLE_KEYS if got["signable_version"] == "v3" else V2_SIGNABLE_KEYS
                assert set(v["certificate"]) == want_keys, mc["id"]
                assert len(v["claims"]) == len(case["certificate"]["claims"])
                for entry in v["claims"].values():
                    assert set(entry) == {"canonical", "values"}
                    assert isinstance(entry["canonical"], str)
                    for val in entry["values"].values():
                        assert isinstance(val, (str, bool, int))
    print(f"python parity: default {passed['default']}/{EXPECTED_CASES}, minimum_v3 {passed['minimum_v3']}/{EXPECTED_CASES}")
    assert not mismatches, "\n".join(f"{i} [{p}]\n  got  {g}\n  want {w}" for i, p, g, w in mismatches)
    assert passed == {"default": EXPECTED_CASES, "minimum_v3": EXPECTED_CASES}


def test_verified_claims_are_the_signed_bytes() -> None:
    """Every `verified` claim entry is keyed <index>:<service_id>:<signed
    claim_type> and carries exactly the bytes the claim signed."""
    keys = _keys()
    checked = 0
    for cid, case in CASES.items():
        if case.get("certificate") is None:
            continue
        got = verify_certificate_chain(_raw(case), keys, **_inputs(case))
        if got.verified is None:
            continue
        claims = case["certificate"]["claims"]
        assert got.verified["certificate"]["claim_ids"] == [c["claim_id"] for c in claims]
        for key, entry in got.verified["claims"].items():
            index, svc = key.split(":", 1)[0], key.split(":", 1)[1].rsplit(":", 1)[0]
            claim_type = key.rsplit(":", 1)[1]
            claim = claims[int(index)]
            assert svc == claim["service_id"], cid
            signed = base64.b64decode(claim["canonical_payload"])
            assert entry["canonical"].encode("utf-8") == signed, cid
            assert entry["values"].get("/claim_type", "") == claim_type, cid
            assert entry["values"]["/claim_id"] == claim["claim_id"], cid
            checked += 1
    assert checked > 0


def test_str_and_bytes_inputs_agree() -> None:
    keys = _keys()
    for case in CASES.values():
        raw = _raw(case)
        for policy in (None, "v3"):
            a = verify_certificate_chain(raw, keys, minimum_signable_version=policy, **_inputs(case))
            b = verify_certificate_chain(raw.decode("utf-8"), keys, minimum_signable_version=policy, **_inputs(case))
            c = verify_certificate_chain(bytearray(raw), keys, minimum_signable_version=policy, **_inputs(case))
            assert a == b == c


# --- request binding (step 5e) --------------------------------------------------


def test_request_binding() -> None:
    keys = _keys()
    case = CASES["honest_full_chain_egress"]
    raw = _raw(case)
    req, cert_id = case["certificate"]["request_id"], case["certificate"]["certificate_id"]

    def run(**kw: Any) -> tuple[str, str, str]:
        r = verify_certificate_chain(raw, keys, **kw)
        return r.verdict, r.reason, r.request_binding

    assert run() == ("VERIFIED", "ok", "not_checked")
    assert run(expected_request_id=req) == ("VERIFIED", "ok", "matched")
    assert run(expected_certificate_id=cert_id) == ("VERIFIED", "ok", "matched")
    assert run(expected_request_id=req, expected_certificate_id=cert_id) == ("VERIFIED", "ok", "matched")
    assert run(expected_request_id="req_other") == ("FAILED", "request_mismatch", "not_evaluated")
    assert run(expected_request_id="") == ("FAILED", "request_mismatch", "not_evaluated")  # empty = supplied
    assert run(expected_request_id=req, expected_certificate_id="veil_other") == ("FAILED", "request_mismatch", "not_evaluated")
    assert run(expected_request_id=req.upper()) == ("FAILED", "request_mismatch", "not_evaluated")  # exact compare
    # 5e runs after the witness signatures: an earlier failure keeps its reason
    tampered = _raw(CASES["tamper_sealed_verdict_upgraded"])
    r = verify_certificate_chain(tampered, keys, expected_request_id="req_other")
    assert (r.verdict, r.reason) == ("FAILED", "witness_signature_invalid")
    for bad in (1, b"req", ["req"]):
        with pytest.raises(TypeError):
            verify_certificate_chain(raw, keys, expected_request_id=bad)  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            verify_certificate_chain(raw, keys, expected_certificate_id=bad)  # type: ignore[arg-type]


# --- pinned-key policy --------------------------------------------------------


def _key_code(key: Any, allow_test_keys: bool, *, as_service: bool) -> str:
    """Load ONE key (as the witness key, or as a service key beside a valid
    witness key) and return `ok` or the refusal code."""
    if as_service:
        k = CertificateChainKeys("w", _NON_TEST_KEY, {"dsa-ai": key}, allow_test_keys=allow_test_keys)
    else:
        k = CertificateChainKeys("w", key, {}, allow_test_keys=allow_test_keys)
    try:
        verify_certificate_chain(b"{}", k)
    except PinnedKeyError as exc:
        return exc.code
    return "ok"


_NON_TEST_KEY = next(v["public_key"] for v in KEY_POLICY["vectors"] if v["id"] == "ok")


def test_key_policy_vectors() -> None:
    assert KEY_POLICY["codes"] == ["ok", "key_malformed", "key_small_order", "key_invalid_point", "key_test_key"]
    seen: dict[str, int] = {}
    for v in KEY_POLICY["vectors"]:
        for as_service in (False, True):
            got = _key_code(v["public_key"], v["allow_test_keys"], as_service=as_service)
            assert got == v["expected"], (v["id"], as_service, got)
        seen[v["expected"]] = seen.get(v["expected"], 0) + 1
    assert seen["key_small_order"] == 15
    assert seen["key_test_key"] == len(chain_mod.CORPUS_TEST_PUBLIC_KEYS) == 10
    assert seen["key_malformed"] >= 10 and seen["key_invalid_point"] >= 4


def test_test_key_denylist_is_every_corpus_key() -> None:
    corpus = {KEYS["witness"]["public_key_base64"]}
    corpus |= {v["public_key_base64"] for v in KEYS["services"].values()}
    corpus |= {v["public_key_base64"] for v in KEYS["not_pinned"].values()}
    assert set(chain_mod.CORPUS_TEST_PUBLIC_KEYS) == corpus
    for entry in [KEYS["witness"], *KEYS["services"].values(), *KEYS["not_pinned"].values()]:
        assert base64.b64decode(entry["public_key_base64"]).hex() == entry["public_key_hex"]


def test_corpus_keys_load_only_with_allow_test_keys() -> None:
    assert CertificateChainKeys("w", b"\x00" * 32).allow_test_keys is False
    raw = _raw(CASES["honest_full_chain_egress"])
    with pytest.raises(PinnedKeyError) as exc:
        verify_certificate_chain(raw, _keys(allow_test_keys=False))
    assert exc.value.code == "key_test_key"
    assert isinstance(exc.value, ValueError)
    # one test key among production keys is enough to refuse the set
    k = CertificateChainKeys("w", _NON_TEST_KEY, {"dsa-ai": KEYS["services"]["dsa-ai"]["public_key_base64"]})
    with pytest.raises(PinnedKeyError) as exc:
        verify_certificate_chain(raw, k)
    assert exc.value.code == "key_test_key"
    # the raw-bytes form of a test key is refused the same way
    with pytest.raises(PinnedKeyError) as exc:
        verify_certificate_chain(raw, CertificateChainKeys("w", base64.b64decode(KEYS["witness"]["public_key_base64"])))
    assert exc.value.code == "key_test_key"


def test_raw_byte_keys_follow_the_same_policy() -> None:
    good = base64.b64decode(_NON_TEST_KEY)
    for key, code in (
        (good, "ok"),
        (bytearray(good), "ok"),
        (good[:31], "key_malformed"),
        (good + b"\x00", "key_malformed"),
        (b"", "key_malformed"),
        (b"\x00" * 32, "key_small_order"),
        (b"\x01" + b"\x00" * 30 + b"\x80", "key_small_order"),
        (b"\x02" + b"\x00" * 31, "key_invalid_point"),
    ):
        assert _key_code(key, False, as_service=False) == code, key.hex()
        assert _key_code(key, False, as_service=True) == code, key.hex()
    for bad in (None, 7, ["x"]):
        with pytest.raises(TypeError):
            verify_certificate_chain(b"{}", CertificateChainKeys("w", bad))  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        verify_certificate_chain(b"{}", CertificateChainKeys("w", good, allow_test_keys="yes"))  # type: ignore[arg-type]


# --- the store-cap export (the input size bound) --------------------------------

STORE_CAP_BODY_BYTES = 8 << 20
STORE_CAP_INPUT_BYTES = 22377772
STORE_CAP_INPUT_SHA256 = "3b1a18920801e20f239a42ab25fde44ed5bc741e947eb5af8872d24d6cb5469d"
STORE_CAP_VERIFIED_SHA256 = "8d1c784e2d7d2d5b1df7875a7406350169cdac07924ebfbdf806de0623890ebd"


def _store_cap_export() -> bytes:
    """honest_full_chain_egress_export with the dsa-ai claim's signed digests
    replaced by those of two 8 MiB bodies, re-signed with the dsa-ai TEST key
    (seed sha256("lucairn-parity-corpus|<seed>|dsa-ai")), the bodies attached,
    the certificate serialised as canonical JSON."""
    cert = _load_case(CORPUS / "cases" / "honest_full_chain_egress_export.json")["certificate"]
    bodies = [b"a" * STORE_CAP_BODY_BYTES, b"b" * STORE_CAP_BODY_BYTES]
    digests = [hashlib.sha256(b).hexdigest() for b in bodies]
    seed = hashlib.sha256(f"lucairn-parity-corpus|{MANIFEST['seed']}|dsa-ai".encode()).digest()
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    done = 0
    for c in cert["claims"]:
        if c["service_id"] != "dsa-ai":
            continue
        doc = chain_mod._loads(base64.b64decode(c["canonical_payload"]))
        doc["payload"]["upstream_body_sha256"] = digests
        cp = chain_mod._canonical(doc).encode()
        c["canonical_payload"] = base64.b64encode(cp).decode()
        c["signature"] = base64.b64encode(priv.sign(cp)).decode()
        c["inference"]["upstream_request_bodies"] = [base64.b64encode(b).decode() for b in bodies]
        done += 1
    assert done == 1
    return chain_mod._canonical(cert).encode()


def test_store_cap_export_verified() -> None:
    data = _store_cap_export()
    assert 16 << 20 < len(data) <= chain_mod.MAX_INPUT_BYTES
    assert len(data) == STORE_CAP_INPUT_BYTES
    assert hashlib.sha256(data).hexdigest() == STORE_CAP_INPUT_SHA256
    got = verify_certificate_chain(data, _keys())
    assert (got.verdict, got.reason, got.egress_attestation) == ("VERIFIED", "ok", "signed_digests")
    assert hashlib.sha256(canonical_json(got.verified)).hexdigest() == STORE_CAP_VERIFIED_SHA256


# --- consumer rules over `verified` ---------------------------------------------


def test_bodies_hash_to_signed_digests() -> None:
    """A displayed upstream body is hashed first and must equal the VERIFIED
    digest at the same index of the egress claim's values."""
    case = CASES["honest_full_chain_egress_export"]
    got = verify_certificate_chain(_raw(case), _keys())
    assert got.verdict == "VERIFIED"
    checked = 0
    for i, c in enumerate(case["certificate"]["claims"]):
        bodies = (c.get("inference") or {}).get("upstream_request_bodies") or []
        if not bodies:
            continue
        values = got.verified["claims"][f"{i}:{c['service_id']}:INFERENCE_COMPLETED"]["values"]
        for j, b in enumerate(bodies):
            assert values[f"/payload/upstream_body_sha256/{j}"] == hashlib.sha256(base64.b64decode(b)).hexdigest()
            checked += 1
    assert checked == 2


def test_values_bound_case_is_bound_plus_one() -> None:
    case = CASES["tamper_values_bound_exceeded"]
    total = sum(
        chain_mod._values_bytes(chain_mod._loads(base64.b64decode(c["canonical_payload"])), 0, 1 << 40)
        for c in case["certificate"]["claims"]
    )
    assert total == chain_mod.MAX_VALUES_POINTER_BYTES + 1


def test_edge_values_keep_integer_and_code_point_order() -> None:
    got = verify_certificate_chain(_raw(CASES["edge_values_integer_above_2_53"]), _keys())
    ints = [v for e in got.verified["claims"].values() for v in e["values"].values() if isinstance(v, int) and not isinstance(v, bool)]
    assert 2**53 + 1 in ints
    want = CASES["edge_values_key_order_above_u_e000"]["expected"]["default"]["verified"]
    got = verify_certificate_chain(_raw(CASES["edge_values_key_order_above_u_e000"]), _keys())
    assert canonical_json(got.verified).decode() == _want_canon(want)


# --- RED-PROOF ------------------------------------------------------------------


def test_red_proof_edited_claim_body_same_id() -> None:
    """The witness-signature-only verify_certificate accepts a certificate
    whose claim body was edited under the same claim id (by design: the
    witness signs the claim-id list); the chain verifier FAILS it."""
    raw = _raw(CASES["tamper_claim_body_edited_same_id"])
    witness_only = verify_certificate(
        json.loads(raw),
        VerifyCertificateKeys(
            witness_key_id=KEYS["witness"]["key_id"],
            witness_public_key=KEYS["witness"]["public_key_base64"],
        ),
    )
    assert witness_only.overall_verdict == "VERDICT_VERIFIED"
    for policy in (None, "v3"):
        got = verify_certificate_chain(raw, _keys(), minimum_signable_version=policy)
        assert (got.verdict, got.reason, got.verified) == ("FAILED", "claim_signature_invalid", None)


# --- programmer errors raise; certificate problems never do --------------------


def test_bad_inputs() -> None:
    keys = _keys()
    with pytest.raises(TypeError):
        verify_certificate_chain({"a": 1}, keys)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        verify_certificate_chain(b"{}", keys, minimum_signable_version="v4")
    with pytest.raises(TypeError):
        verify_certificate_chain(b"{}", object())  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        verify_certificate_chain(b"{}", CertificateChainKeys("", _NON_TEST_KEY))
    with pytest.raises(PinnedKeyError) as exc:
        verify_certificate_chain(b"{}", CertificateChainKeys("w", b"\x00" * 31, {}))
    assert exc.value.code == "key_malformed"
    with pytest.raises(PinnedKeyError) as exc:
        verify_certificate_chain(b"{}", CertificateChainKeys("w", _NON_TEST_KEY, {"dsa-ai": "not base64!"}))
    assert exc.value.code == "key_malformed"
    with pytest.raises(TypeError):
        verify_certificate_chain(b"{}", CertificateChainKeys("w", _NON_TEST_KEY, {"": _NON_TEST_KEY}))
    for junk in (b"", b"[]", b"\xff", b"{" * 5000, "﻿{}", "{\"a\":\"\ud800\"}", b"{}" + b" " * (32 << 20)):
        got = verify_certificate_chain(junk, keys)
        assert (got.verdict, got.reason, got.user_unredacted, got.verified) == ("FAILED", "malformed", "unknown", None)


def test_witness_only_function_unchanged_for_failures() -> None:
    """verify_certificate keeps raising on witness-level failures (additive API)."""
    raw = _raw(CASES["tamper_witness_key_id_changed"])
    with pytest.raises(LucairnCertificateError):
        verify_certificate(
            json.loads(raw),
            VerifyCertificateKeys(
                witness_key_id=KEYS["witness"]["key_id"],
                witness_public_key=KEYS["witness"]["public_key_base64"],
            ),
        )


# --- grammar vectors (the SAME vectors as the corpus references) ----------------


def _nested(n: int) -> str:
    return "[" * n + "]" * n


GRAMMAR_TIMESTAMPS = [
    ("2026-09-25T12:00:02.5Z", "2026-09-25T12:00:02.5Z"),
    ("2026-09-25T12:00:02.500000000Z", "2026-09-25T12:00:02.5Z"),
    ("2026-09-25T12:00:02.5000000000Z", None),
    ("2026-09-25T12:00:00.123456789-00:30", "2026-09-25T12:30:00.123456789Z"),
    ("2026-09-25T14:00:00+02:00", "2026-09-25T12:00:00Z"),
    ("2024-02-29T00:00:00Z", "2024-02-29T00:00:00Z"),
    ("0001-01-01T00:00:00-01:00", "0001-01-01T01:00:00Z"),
    ("2026-09-25T12:00:00+24:00", None),
    ("2026-09-25T12:00:00+23:60", None),
    ("2026-09-25T12:00:00+99:00", None),
    ("2026-09-25T12:00:60Z", None),
    ("2026-09-25T24:00:00Z", None),
    ("2026-02-30T12:00:00Z", None),
    ("0000-01-01T00:00:00Z", None),
    ("0001-01-01T00:00:00+01:00", None),
    ("9999-12-31T23:59:59-01:00", None),
    ("2026-09-25t12:00:00z", None),
    ("2026-09-25T12:00:00.Z", None),
    ("2026-09-25T12:00:00", None),
    ("２026-09-25T12:00:00Z", None),
]
GRAMMAR_DOCUMENTS = [
    (b'{"a":1}', True),
    (b'{"a":1} \n\t\r', True),
    (b'{"a":1}]', False),
    (b'{"a":1}}', False),
    (b'{"a":1} x', False),
    (b'{"a":1}{"b":2}', False),
    (b'{"a":NaN}', False),
    (b'{"a":Infinity}', False),
    (b'{"a":-Infinity}', False),
    (b'\xef\xbb\xbf{"a":1}', False),
    (b'{"a":"\xff"}', False),
    (b'{"a":1]', False),
    (b"[1,]", False),
    (b'{"a":1,}', False),
    # duplicate keys, compared after escape decoding
    (b'{"a":1,"a":1}', False),
    (b'{"a":1,"a":2}', False),
    (b'{"a":1,"\\u0061":2}', False),
    (b'{"a":{"b":1},"c":{"b":1}}', True),
    (b'[{"a":1},{"a":1}]', True),
    # surrogate escapes: a high + low pair only
    (b'{"a":"\\ud83d\\ude00"}', True),
    (b'{"a":"\\uD83D\\uDE00"}', True),
    (b'{"a":"\\ud800"}', False),
    (b'{"a":"\\udc00"}', False),
    (b'{"a":"\\ud800A"}', False),
    (b'{"a":"\\ud800\\ud800"}', False),
    (b'{"a":"\\ud800\\\\udc00"}', False),
    (b'{"\\ud800":1}', False),
    (b'{"a":"\\\\ud800"}', True),
    # depth: at most 256 nested arrays / objects; brackets in strings do not count
    (_nested(256).encode(), True),
    (_nested(257).encode(), False),
    (('{"a":' + _nested(255) + "}").encode(), True),
    (('{"a":' + _nested(256) + "}").encode(), False),
    (('{"a":"' + "[" * 257 + '"}').encode(), True),
]
GRAMMAR_CERTIFICATE_KEYS = [
    ("byok_exempt", False),
    ("BYOK_EXEMPT", True),
    ("Client_Id", True),
    ("byoK_exempt", True),  # U+212A KELVIN SIGN
    ("ſervice_id", True),  # U+017F LATIN SMALL LETTER LONG S
    ("upstream_model", False),  # not read by the recipe
    ("UPSTREAM_MODEL", False),
    ("PERSON", False),
    ("byok_exempt ", False),
    ("İssued_at", False),  # U+0130 folds to no ASCII letter
    # protojson JSON names of spec keys, and their case variants
    ("byokExempt", True),
    ("ByokExempt", True),
    ("byokexempt", True),
    ("clientId", True),
    ("upstreamRequestBodies", True),
    ("upstreamBodySha256", True),
    ("kAnonymity", True),
    ("model_uſed", True),
    ("upstreamModel", False),  # upstream_model is not a spec key
    ("certificate_id_", False),
]
GRAMMAR_BLANK = [
    ("", True),
    (" \t\n\v\f\r", True),
    ("  　\u0085", True),
    ("\u001c", False),
    ("\u001f", False),
    ("​", False),
    ("x", False),
]
GRAMMAR_QI_VERDICTS = [
    ("PASS", "QI_VERDICT_PASS"),
    (" pass ", "QI_VERDICT_PASS"),
    ("generalized", "QI_VERDICT_GENERALIZED"),
    ("paſs", "QI_VERDICT_UNKNOWN"),
    ("generalızed", "QI_VERDICT_UNKNOWN"),
    ("\u001cPASS", "QI_VERDICT_UNKNOWN"),
]
GRAMMAR_INTEGERS = [
    ("0", True),
    ("2", True),
    ("18446744073709551615", True),
    ("18446744073709551616", False),
    ("00", False),
    ("2.0", False),
    ("2e0", False),
    ("-1", False),
    ("1" + "0" * 4999, False),
]
GRAMMAR_FLOAT32 = [
    ("0.25", True),
    ("1e-50", True),
    ("3.4028235e38", True),
    ("3.4028236e38", False),
    ("1e39", False),
    ("-1e39", False),
    ("1e400", False),
]


def _parses(fn, doc: Any) -> bool:
    try:
        fn(doc)
    except (ValueError, RecursionError):
        return False
    return True


def test_grammar_vectors() -> None:
    for s, want in GRAMMAR_TIMESTAMPS:
        assert chain_mod._rfc3339nano_utc(s) == want, s
    for doc, ok in GRAMMAR_DOCUMENTS:
        assert _parses(chain_mod._loads, doc) == ok, doc[:80]
    for key, refused in GRAMMAR_CERTIFICATE_KEYS:
        doc = json.dumps({key: True}).encode()
        assert _parses(chain_mod._load_certificate, doc) == (not refused), key
    for s, blank in GRAMMAR_BLANK:
        assert (chain_mod._trim_space(s) == "") == blank, repr(s)
    for s, want in GRAMMAR_QI_VERDICTS:
        assert chain_mod._qi_verdict(s) == want, repr(s)
    for text, ok in GRAMMAR_INTEGERS:
        assert (chain_mod._integer(chain_mod._Num(text), 2**64 - 1) is not None) == ok, text[:30]
    for text, ok in GRAMMAR_FLOAT32:
        assert (chain_mod._f32(chain_mod._Num(text), False) is not None) == ok, text


def test_input_size_bound() -> None:
    """Exactly MAX_INPUT_BYTES passes the bound; one more byte is malformed
    (whitespace padding keeps the document valid)."""
    doc = b'{"a":1}'
    at_cap = doc + b" " * (chain_mod.MAX_INPUT_BYTES - len(doc))
    assert _parses(chain_mod._load_certificate, at_cap)
    assert not _parses(chain_mod._load_certificate, at_cap + b" ")
    # through the public API: the over-bound input is FAILED malformed as bytes and as str
    for over in (at_cap + b" ", (at_cap + b" ").decode("ascii")):
        got = verify_certificate_chain(over, _keys())
        assert (got.verdict, got.reason) == ("FAILED", "malformed")


# --- SDK-local: the two-signer input-shield tier (NOT a corpus vector) -----------
#
# Corpus v1.2.1 vendors the honest and three label-tamper vectors for the
# unsigned label `input_shield_two_signer` (an input-shield chain sealed with
# only the sanitizer and gateway claims, no dsa-ai claim). This wider label x
# shape matrix is kept alongside them; its certificates are constructed here
# from honest_input_shield and re-sealed with the corpus TEST witness key.

TWO_SIGNER = "input_shield_two_signer"


def _test_witness_key() -> Ed25519PrivateKey:
    seed = hashlib.sha256(f"lucairn-parity-corpus|{MANIFEST['seed']}|witness".encode()).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


def _reseal(cert: dict[str, Any]) -> bytes:
    """Re-sign the v2 and v3 witness signatures over the edited claim list,
    the way the witness builds its signables."""
    ver = cert["verification"]
    v2 = {
        "certificate_id": cert["certificate_id"],
        "request_id": cert["request_id"],
        "protocol_version": 2,
        "claim_ids": [c["claim_id"] for c in cert["claims"]],
        "issued_at": chain_mod._rfc3339nano_utc(cert["issued_at"]),
        "overall_verdict": ver["overall_verdict"].removeprefix("VERDICT_"),
        "witness_key_id": cert["witness_key_id"],
    }
    v3 = dict(
        v2,
        client_id=cert.get("client_id"),
        api_key_id=cert.get("api_key_id"),
        byok_exempt=bool(ver.get("byok_exempt")),
        redaction_manifest_hash=chain_mod._sanitizer_hash(cert["claims"], "redaction_manifest_hash"),
        sanitized_fields_body_hash=chain_mod._sanitizer_hash(cert["claims"], "sanitized_fields_hash"),
        tms_manifest_hash=chain_mod._sanitizer_hash(cert["claims"], "tms_manifest_hash"),
    )
    w = _test_witness_key()
    cert["witness_signature"] = base64.b64encode(w.sign(canonical_json(v2))).decode()
    cert["signable_v3_signature"] = base64.b64encode(w.sign(canonical_json(v3))).decode()
    return chain_mod._canonical(cert).encode()


def _two_signer_cert(label: str, sealed: str = "VERDICT_VERIFIED", drop: tuple[str, ...] = ("dsa-ai",)) -> bytes:
    cert = _load_case(CORPUS / "cases" / "honest_input_shield.json")["certificate"]
    cert["claims"] = [c for c in cert["claims"] if c["service_id"] not in drop]
    assert [c["service_id"] for c in cert["claims"]] == [
        s for s in ("dsa-sanitizer", "dsa-gateway", "dsa-ai") if s not in drop
    ]
    cert["verification"]["cert_tier"] = label
    cert["verification"]["overall_verdict"] = sealed
    return _reseal(cert)


def _summary(raw: bytes, policy: str | None = None) -> tuple[str, str, str, str]:
    r = verify_certificate_chain(raw, _keys(), minimum_signable_version=policy)
    return r.verdict, r.reason, r.egress_attestation, r.signed_cert_tier


def test_two_signer_tier_pairs_only_with_its_shape() -> None:
    assert _test_witness_key().public_key().public_bytes_raw() == base64.b64decode(KEYS["witness"]["public_key_base64"])
    raw = _two_signer_cert(TWO_SIGNER)
    for policy in (None, "v3"):
        assert _summary(raw, policy) == ("EGRESS_UNATTESTED", "egress_unattested", "unattested", TWO_SIGNER)
    got = verify_certificate_chain(raw, _keys())
    assert got.signable_version == "v3" and got.user_unredacted == "false"
    assert sorted(got.verified["claims"]) == ["0:dsa-sanitizer:PII_SANITIZED", "1:dsa-gateway:INFERENCE_COMPLETED"]
    assert got.verified["claims"]["1:dsa-gateway:INFERENCE_COMPLETED"]["values"]["/payload/cert_tier"] == "input-shield"

    # sealed PARTIAL: the seal caps it, the tier is still reported
    for policy in (None, "v3"):
        assert _summary(_two_signer_cert(TWO_SIGNER, "VERDICT_PARTIAL"), policy) == (
            "PARTIAL", "sealed_partial", "unattested", TWO_SIGNER)

    # no sanitizer claim: not the two-signer shape, whatever the seal
    for sealed in ("VERDICT_VERIFIED", "VERDICT_PARTIAL"):
        no_sanitizer = _two_signer_cert(TWO_SIGNER, sealed, drop=("dsa-ai", "dsa-sanitizer"))
        for policy in (None, "v3"):
            assert _summary(no_sanitizer, policy)[:2] == ("FAILED", "cert_tier_mismatch"), sealed

    # the same two-signer shape under any other label: unchanged rules (the
    # lone gateway copy is `inconsistent`, which a sealed VERIFIED refuses)
    for label in ("", "full_chain", "input_shield"):
        assert _summary(_two_signer_cert(label))[:2] == ("FAILED", "cert_tier_mismatch"), label

    # the label on any other shape stays a mismatch, whatever the seal
    for case_id in (
        "honest_input_shield",  # a dsa-ai claim is present
        "honest_input_shield_partial",  # sealed PARTIAL
        "honest_input_shield_gateway_claim_lost",  # only the dsa-ai copy
        "honest_input_shield_sanitizer_claim_lost",
        "honest_full_chain_egress",  # no signed copy at all
        "legacy_no_egress_hash",
    ):
        cert = CASES[case_id]["certificate"]
        edited = dict(cert, verification=dict(cert["verification"], cert_tier=TWO_SIGNER))
        assert _summary(chain_mod._canonical(edited).encode())[:2] == ("FAILED", "cert_tier_mismatch"), case_id


# --- the canonical walk never depends on the caller's stack depth ----------


def _depth_256_claim_cert() -> bytes:
    """honest_full_chain_egress with a signed claim document of exactly
    MAX_DEPTH (256) nested containers, re-signed with the dsa-ai TEST key and
    the witness re-sealed."""
    cert = _load_case(CORPUS / "cases" / "honest_full_chain_egress.json")["certificate"]
    seed = hashlib.sha256(f"lucairn-parity-corpus|{MANIFEST['seed']}|dsa-ai".encode()).digest()
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    done = 0
    for c in cert["claims"]:
        if c["service_id"] != "dsa-ai":
            continue
        doc = chain_mod._loads(base64.b64decode(c["canonical_payload"]))
        # document = 1, payload = 2, then 254 more arrays = 256
        doc["payload"]["deep"] = json.loads("[" * 254 + '"x"' + "]" * 254)
        cp = chain_mod._canonical(doc).encode()
        c["canonical_payload"] = base64.b64encode(cp).decode()
        c["signature"] = base64.b64encode(priv.sign(cp)).decode()
        done += 1
    assert done == 1
    return _reseal(cert)


def _call_from_depth(depth: int, fn):
    if depth == 0:
        return fn()
    return _call_from_depth(depth - 1, fn)


def test_result_does_not_depend_on_caller_stack_depth() -> None:
    import sys

    raw = _depth_256_claim_cert()
    want = verify_certificate_chain(raw, _keys())
    assert want.reason != "claim_canonical_mismatch"  # not refused for depth
    # Default recursion limit (1000): the caller sits deep in the stack, well
    # past where the old recursive canonical walk gave up.
    assert sys.getrecursionlimit() >= 1000
    room = sys.getrecursionlimit() - len(__import__("inspect").stack(0))
    for depth in (0, 300, 500, 600, room - 120):
        got = _call_from_depth(depth, lambda: verify_certificate_chain(raw, _keys()))
        assert (got.verdict, got.reason) == (want.verdict, want.reason), depth


def test_two_signer_tier_is_not_capped_by_step_8d() -> None:
    """Corpus v1.2.1: the two-signer label is NOT capped by the tier step
    itself (the EGRESS_UNATTESTED ceiling comes from the absent dsa-ai
    egress digests). TS and Go assert the same on their step-8d helpers."""
    cert = _load_case(CORPUS / "cases" / "honest_input_shield.json")["certificate"]
    claims = [c for c in cert["claims"] if c["service_id"] != "dsa-ai"]
    canon = [chain_mod._loads(base64.b64decode(c["canonical_payload"]))["payload"] for c in claims]
    tier, ok, capped = chain_mod._cert_tier_check(claims, canon, TWO_SIGNER, "VERDICT_VERIFIED")
    assert (tier, ok, capped) == (TWO_SIGNER, True, False)
