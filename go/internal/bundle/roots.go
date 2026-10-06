package bundle

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"fmt"

	"github.com/declade/lucairn-sdks/go/internal/anchor"
)

// TrustRoots are the keys a bundle is checked against. They come from the
// tool (built in, or the auditor's own flags) — NEVER from the bundle.
type TrustRoots struct {
	// WitnessKeys by witness_key_id.
	WitnessKeys map[string]ed25519.PublicKey
	// ServiceKeys by claim service_id. Empty = claim signatures cannot be
	// checked (the claims and binding steps are then SKIPPED, blocking VALID).
	ServiceKeys map[string]ed25519.PublicKey
	TSARoots    *x509.CertPool
	Rekor       *anchor.RekorKey
	// RequireAnchors: a certificate without a timestamp token or Rekor entry
	// makes the result INCOMPLETE. True for the built-in Lucairn-hosted pins
	// (every hosted certificate is anchored); false for a self-hosted
	// deployment given with its own witness key (an air-gapped kit has no
	// anchors), unless --require-anchors. --allow-unanchored turns it off.
	// The certificate's own anchor_status is never trusted to relax this.
	RequireAnchors bool
	// Label is printed on every run ("Lucairn-hosted pins" or "CUSTOM …").
	Label string
}

// Production pins of the Lucairn-hosted deployment. Source of truth:
// https://lucairn.eu/.well-known/lucairn-service-keys.json (theveil-website
// src/lib/service-keys/production-service-keys.ts, read 2026-09-29), which
// mirrors the desktop app's build-time pins. Verify the fingerprints out of
// band; never fetch them at verify time.
const productionWitnessKeyID = "witness_v1"

const productionWitnessKeyHex = "00ba189d1db11259e6ae803eef5739e600be01f23db5cdc8f4f4aff7dfaabcc5"

var productionServiceKeyHex = map[string]string{
	"dsa-sanitizer":           "43023c149f85e67f259c50ac028091cf2d1b0e6ff12181fe88ba417c7ba28739",
	"dsa-sanitizer-streaming": "43023c149f85e67f259c50ac028091cf2d1b0e6ff12181fe88ba417c7ba28739",
	"dsa-ai":                  "e02cf93fff3f9e121e8862df30236fba4a691fc8ab50fbffc448f82188819195",
	"dsa-gateway":             "8c80ee8f6b4c48494133d2b2c3e413f3ca445b2978162ad31e640dd2a69ebb5a",
	"dsa-bridge":              "a8392518ea0fefe479fd21feaa62a73b6fa121d7b92d8bd72d740609ed378da0",
	"dsa-audit":               "ced685266076d80c6452861b96f4f6b5139fbac8c385ffe33c8a9d0792971022",
}

func mustKey(h string) ed25519.PublicKey {
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != ed25519.PublicKeySize {
		panic(fmt.Sprintf("bundle: bad pinned key %q", h))
	}
	return ed25519.PublicKey(b)
}

// ProductionRoots returns the built-in pins of the Lucairn-hosted
// deployment: witness_v1, the six claim-signing service keys, the FreeTSA
// root and the Sigstore public-good Rekor key.
func ProductionRoots() (TrustRoots, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(anchor.FreeTSARootPEM) {
		return TrustRoots{}, fmt.Errorf("built-in FreeTSA root does not load")
	}
	rk, err := anchor.ParseRekorKeyPEM(anchor.RekorPublicGoodPEM)
	if err != nil {
		return TrustRoots{}, err
	}
	svc := map[string]ed25519.PublicKey{}
	for id, h := range productionServiceKeyHex {
		svc[id] = mustKey(h)
	}
	return TrustRoots{
		WitnessKeys:    map[string]ed25519.PublicKey{productionWitnessKeyID: mustKey(productionWitnessKeyHex)},
		ServiceKeys:    svc,
		TSARoots:       pool,
		Rekor:          rk,
		RequireAnchors: true,
		Label:          "built-in Lucairn-hosted pins (witness_v1, 6 service keys, FreeTSA root, Rekor public-good key)",
	}, nil
}
