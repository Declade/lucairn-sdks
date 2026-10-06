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
