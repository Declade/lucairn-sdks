package bundle

import "crypto/ed25519"

// SetSignedBytesOfForTest swaps the second signature-pipeline run that
// recovers the signed bytes and signed issued_at; it returns a restore func.
// failRecovery makes that run fail after the signature check passed.
func SetSignedBytesOfForTest(failRecovery bool) func() {
	prev := signedBytesOfFn
	if failRecovery {
		signedBytesOfFn = func([]byte, string, ed25519.PublicKey, string) signedInput { return signedInput{} }
	}
	return func() { signedBytesOfFn = prev }
}

// FormNameForTest classifies a recorded hash_algorithm the way the anchor
// steps do: "legacy", "v1" or "unknown".
func FormNameForTest(hashAlgorithm any) string {
	v := &certVerifier{}
	switch v.bindingOf(map[string]any{"timestamp": map[string]any{"hash_algorithm": hashAlgorithm}}, signedInput{}).form {
	case formLegacy:
		return "legacy"
	case formV1:
		return "v1"
	}
	return "unknown"
}

// QuotedShortForTest exposes quotedShort.
func QuotedShortForTest(s string) string { return quotedShort(s) }

// AuditCounterStepForTest runs check A (matchAuditClaim) for one counter
// entry against one audit-signed claim: its event_hash and, when claimSeq > 0
// / claimConv != "", the counter the claim itself signs (design D3).
func AuditCounterStepForTest(claimHash string, claimSeq uint64, claimConv string, e AuditEvent) (Status, string) {
	c := auditClaim{eventHash: claimHash, conversationID: claimConv, hasSeq: claimSeq > 0, seq: claimSeq}
	return matchAuditClaim([]auditClaim{c}, &e, 1)
}

// AuditClaimsForTest reads the audit claims out of verified claim values and
// reports (number of claims, the counted seq a claim signs or 0, malformed).
func AuditClaimsForTest(claims map[string]map[string]any) (int, uint64, bool) {
	cs := auditClaimsOf(claims)
	seq, _ := certAudit{claims: cs}.countedSeq()
	bad := false
	for _, c := range cs {
		bad = bad || c.seqMalformed
	}
	return len(cs), seq, bad
}
