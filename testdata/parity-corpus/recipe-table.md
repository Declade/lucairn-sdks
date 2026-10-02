<!-- Extracted by sync.sh from Declade/dual-sandbox-architecture tools/parity-corpus/README.md @ a46d8db6641d430a0961c56d3a1e21383a4cd261 — do not edit. -->
<!-- recipe-table:begin -->
| step | check (fails when …) | verdict + reason |
|---|---|---|
| 1 | the certificate shape is wrong (list below) | FAILED `malformed` |
| 2 | `protocol_version` is not `2` | FAILED `unsupported_protocol_version` |
| 3 | `witness_key_id` is not the pinned witness `key_id` | FAILED `witness_key_mismatch` |
| 4 | `signable_protocol_version_emitted >= 3` and "`signable_v3_signature` is non-blank" disagree | FAILED `version_downgrade_detected` |
| 5a | `issued_at` is outside the timestamp grammar (step 5a below) | FAILED `malformed` |
| 5b | `witness_signature` is missing, not base64, or not a valid signature (§ Signatures) over the v2 signable | FAILED `witness_signature_invalid` |
| 5c | `signable_v3_signature` is present and not a valid signature (§ Signatures) over the v3 signable | FAILED `witness_signature_invalid` |
| 5d | the policy requires v3 and only the v2 signature exists | FAILED `signable_version_insufficient` |
| 5e | a supplied `expected_request_id` / `expected_certificate_id` differs from the witness-signed value | FAILED `request_mismatch` |
| 6a | the sealed `overall_verdict` is `VERDICT_FAILED` | FAILED `sealed_failed` |
| 6b | the sealed verdict is neither `VERDICT_VERIFIED` nor `VERDICT_PARTIAL` | FAILED `malformed` |
| 6c | a claim id occurs twice in the witness-signed claim id list | FAILED `duplicate_claim_id` |
| 7a | no key is pinned for the claim's `service_id` | FAILED `unknown_service` |
| 7b | `canonical_payload` or `signature` is not canonical standard base64 | FAILED `malformed` |
| 7c | the signature (§ Signatures) fails under the claim's service key but verifies under another pinned service key | FAILED `service_key_mismatch` |
| 7d | the signature (§ Signatures) fails under the claim's service key | FAILED `claim_signature_invalid` |
| 7e | the signed bytes are not a JSON object (§ Input document, case-variant rule included), or their `values` take the running total past `max_values_pointer_bytes` | FAILED `claim_canonical_mismatch` |
| 7f | the signed `claim_id` is not in the witness-signed claim id list | FAILED `claim_not_witness_listed` |
| 7g | the canonical bytes rebuilt from the outer fields differ from the signed bytes | FAILED `claim_canonical_mismatch` |
| 7h | the signed `request_id` differs from the certificate's `request_id` | FAILED `request_id_splice` |
| 7i | a typed (unsigned) mirror disagrees with the signed payload | FAILED `typed_payload_mismatch` |
| 8a | a signed digest list is malformed, or more than one dsa-ai claim signs one | FAILED `egress_digest_malformed` |
| 8b | stored upstream bodies sit on any claim other than the one that signs the digest list | FAILED `egress_body_unbound` |
| 8c | the stored bodies do not match the signed digests (count or hash) | FAILED `egress_body_hash_mismatch` |
| 8d | the unsigned `cert_tier` is not allowed beside the signed copies (rules below) | FAILED `cert_tier_mismatch` |
| 9a | ceiling: any signed payload carries `inference_outcome` | PARTIAL `inference_unfinished` |
| 9b | ceiling: `user_unredacted` is true | PARTIAL `user_sent_unredacted` |
| 9c | ceiling: the sealed verdict is `VERDICT_PARTIAL` | PARTIAL `sealed_partial` |
| 9d | ceiling: `egress_attestation` is `unattested`, or step 8d capped the result (fix A) | EGRESS_UNATTESTED `egress_unattested` |
| 9e | otherwise | VERIFIED `ok` |
<!-- recipe-table:end -->
