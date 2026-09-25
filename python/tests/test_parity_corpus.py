"""T-935 S3 parity: verify_certificate_chain against the vendored corpus.

The corpus (testdata/parity-corpus, vendored from Declade/dual-sandbox-
architecture tools/parity-corpus at the commit in SOURCE.json) carries, per
case, the result every Lucairn verifier must return under every policy. The
TS (ts/src/verify-chain/parityCorpus.test.ts) and Go (go/parity_corpus_test.go)
SDKs run the same cases against the same expectations.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import pytest

from lucairn import CertificateChainKeys, verify_certificate_chain
from lucairn.errors import LucairnCertificateError
from lucairn.types import VerifyCertificateKeys
from lucairn.verify_certificate import chain as chain_mod
from lucairn.verify_certificate import verify_certificate

CORPUS_ROOT = Path(__file__).resolve().parents[2] / "testdata" / "parity-corpus"
CORPUS = CORPUS_ROOT / "v1"
SOURCE = json.loads((CORPUS_ROOT / "SOURCE.json").read_text())
MANIFEST = json.loads((CORPUS / "manifest.json").read_text())
KEYS = json.loads((CORPUS / "keys.json").read_text())

EXPECTED_CASES = 54


def _sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def _keys() -> CertificateChainKeys:
    return CertificateChainKeys(
        witness_key_id=KEYS["witness"]["key_id"],
        witness_public_key=KEYS["witness"]["public_key_base64"],
        service_public_keys={s: v["public_key_base64"] for s, v in KEYS["services"].items()},
    )


def _raw_certificate(case_file: Path) -> bytes:
    """The verifier input: `certificate_text` verbatim when present, else the
    certificate's JSON text with every number lexeme kept."""
    doc = chain_mod._loads(case_file.read_bytes())
    if "certificate_text" in doc:
        return doc["certificate_text"].encode("utf-8")
    return chain_mod._canonical(doc["certificate"]).encode()


def _policy_arg(policy: dict) -> str | None:
    return None if policy["minimum_signable_version"] == "v2" else policy["minimum_signable_version"]


# --- the vendored copy is exactly the recorded one ---------------------------


def test_vendored_corpus_matches_recorded_hashes() -> None:
    assert SOURCE["format"] == MANIFEST["format"] == "lucairn-parity-corpus/v1.1"
    assert _sha(CORPUS / "manifest.json") == SOURCE["manifest_sha256"], "manifest drifted: re-run testdata/parity-corpus/sync.sh"
    assert _sha(CORPUS / "keys.json") == SOURCE["keys_sha256"], "keys drifted: re-run testdata/parity-corpus/sync.sh"
    assert _sha(CORPUS_ROOT / "recipe-table.md") == SOURCE["recipe_table_sha256"], "recipe-table.md drifted: re-run testdata/parity-corpus/sync.sh"
    on_disk = sorted(p.name for p in (CORPUS / "cases").iterdir())
    listed = sorted(Path(c["file"]).name for c in MANIFEST["cases"])
    assert on_disk == listed
    for c in MANIFEST["cases"]:
        assert _sha(CORPUS / c["file"]) == c["sha256"], f"{c['id']} drifted from its manifest sha256"


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


# --- parity: every case × every policy ----------------------------------------


def test_every_case_every_policy_matches_expected() -> None:
    keys = _keys()
    assert len(MANIFEST["cases"]) == EXPECTED_CASES
    assert [p["name"] for p in MANIFEST["policies"]] == ["default", "minimum_v3"]
    passed = {p["name"]: 0 for p in MANIFEST["policies"]}
    mismatches = []
    for mc in MANIFEST["cases"]:
        case_file = CORPUS / mc["file"]
        raw = _raw_certificate(case_file)
        case = chain_mod._loads(case_file.read_bytes())  # a case may carry a 5,000-digit token
        assert case["expected"] == mc["expected"]
        for policy in MANIFEST["policies"]:
            got = verify_certificate_chain(raw, keys, minimum_signable_version=_policy_arg(policy)).to_dict()
            want = mc["expected"][policy["name"]]
            if got == want:
                passed[policy["name"]] += 1
            else:
                mismatches.append((mc["id"], policy["name"], got, want))
            assert got["verdict"] in MANIFEST["verdicts"]
            assert got["reason"] in MANIFEST["reasons"]
            assert got["egress_attestation"] in MANIFEST["egress_states"]
            assert got["user_unredacted"] in MANIFEST["user_unredacted"]
            assert got["signed_cert_tier"] in MANIFEST["signed_cert_tiers"]
            assert got["signable_version"] in MANIFEST["signable_versions"]
    print(f"python parity: default {passed['default']}/{EXPECTED_CASES}, minimum_v3 {passed['minimum_v3']}/{EXPECTED_CASES}")
    assert not mismatches, "\n".join(f"{i} [{p}]\n  got  {g}\n  want {w}" for i, p, g, w in mismatches)
    assert passed == {"default": EXPECTED_CASES, "minimum_v3": EXPECTED_CASES}


def test_str_and_bytes_inputs_agree() -> None:
    keys = _keys()
    for mc in MANIFEST["cases"]:
        raw = _raw_certificate(CORPUS / mc["file"])
        assert verify_certificate_chain(raw, keys) == verify_certificate_chain(raw.decode("utf-8"), keys)


# --- RED-PROOF (PRD § RED-PROOF) ----------------------------------------------


def test_red_proof_edited_claim_body_same_id() -> None:
    """The witness-signature-only verify_certificate accepts a certificate
    whose claim body was edited under the same claim id (the T-794 gap, still
    true of that function by design); the chain verifier FAILS it."""
    raw = _raw_certificate(CORPUS / "cases" / "tamper_claim_body_edited_same_id.json")
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
        assert (got.verdict, got.reason) == ("FAILED", "claim_signature_invalid")


# --- programmer errors raise; certificate problems never do --------------------


def test_bad_inputs() -> None:
    keys = _keys()
    with pytest.raises(TypeError):
        verify_certificate_chain({"a": 1}, keys)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        verify_certificate_chain(b"{}", keys, minimum_signable_version="v4")
    with pytest.raises(TypeError):
        verify_certificate_chain(b"{}", CertificateChainKeys("w", b"\x00" * 31, {}))
    with pytest.raises(TypeError):
        verify_certificate_chain(b"{}", CertificateChainKeys("w", b"\x00" * 32, {"dsa-ai": "not base64!"}))
    for junk in (b"", b"[]", b"\xff", b"{" * 5000, "\ufeff{}"):
        got = verify_certificate_chain(junk, keys)
        assert (got.verdict, got.reason, got.user_unredacted) == ("FAILED", "malformed", "unknown")


def test_witness_only_function_unchanged_for_failures() -> None:
    """verify_certificate keeps raising on witness-level failures (additive API)."""
    raw = _raw_certificate(CORPUS / "cases" / "tamper_witness_key_id_changed.json")
    with pytest.raises(LucairnCertificateError):
        verify_certificate(
            json.loads(raw),
            VerifyCertificateKeys(
                witness_key_id=KEYS["witness"]["key_id"],
                witness_public_key=KEYS["witness"]["public_key_base64"],
            ),
        )


# --- grammar vectors (the SAME vectors as the DSA references) ------------------

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


def test_grammar_vectors() -> None:
    for s, want in GRAMMAR_TIMESTAMPS:
        assert chain_mod._rfc3339nano_utc(s) == want, s
    for doc, ok in GRAMMAR_DOCUMENTS:
        try:
            chain_mod._loads(doc)
            parsed = True
        except ValueError:
            parsed = False
        assert parsed == ok, doc
    for text, ok in GRAMMAR_INTEGERS:
        assert (chain_mod._integer(chain_mod._Num(text), 2**64 - 1) is not None) == ok, text[:30]
    for text, ok in GRAMMAR_FLOAT32:
        assert (chain_mod._f32(chain_mod._Num(text), False) is not None) == ok, text


def test_cross_sdk_rules_beyond_the_corpus() -> None:
    """Rules the three SDKs pin identically where the corpus is silent."""
    # nesting bound
    chain_mod._loads(b"[" * 256 + b"]" * 256)
    with pytest.raises(ValueError):
        chain_mod._loads(b"[" * 257 + b"]" * 257)
    chain_mod._loads(b'["' + b"[" * 300 + b'"]')  # brackets inside a string do not count
    # unpaired surrogate escapes read as U+FFFD (Go encoding/json); pairs join
    assert chain_mod._loads(b'{"\\udc00":"\\ud800x\\ud83d\\ude00"}') == {"\ufffd": "\ufffdx\U0001f600"}
    # qi verdict: ASCII-only upper-casing
    assert chain_mod._qi_verdict(" pass\n") == "QI_VERDICT_PASS"
    assert chain_mod._qi_verdict("pa\u00df") == "QI_VERDICT_UNKNOWN"
    # step 4 "non-blank" uses Go's unicode.IsSpace set
    assert "\u001c".strip(chain_mod._GO_SPACE) == "\u001c"
    assert "\u3000\u0085 ".strip(chain_mod._GO_SPACE) == ""
