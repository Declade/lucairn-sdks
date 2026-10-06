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

// AuditClaimForTest is one audit-signed claim as check A sees it: its
// event_hash and, when Seq > 0, the counter it signs (design D3).
type AuditClaimForTest struct {
	Hash string
	Seq  uint64
	Conv string
}

// AuditCounterStepForTest runs check A (matchAuditClaim) for one counter
// entry against the audit-signed claims of its certificate.
func AuditCounterStepForTest(e AuditEvent, claims ...AuditClaimForTest) (Status, string) {
	cs := make([]auditClaim, len(claims))
	for i, c := range claims {
		cs[i] = auditClaim{requestID: e.RequestID, eventHash: c.Hash, conversationID: c.Conv, hasSeq: c.Seq > 0, seq: c.Seq}
	}
	return matchAuditClaim(cs, &e, 1)
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
