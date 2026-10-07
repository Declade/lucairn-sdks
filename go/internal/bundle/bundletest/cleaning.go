package bundletest

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/declade/lucairn-sdks/go/internal/verify"
)

// CleaningOptions bends the signed cleaning inputs for negative tests.
// The zero value makes an ordinary two-claim cleaning certificate.
type CleaningOptions struct {
	IssuedAt              time.Time // Optional scenario start, independent of the wall clock.
	DuplicateService      string
	InferenceFailed       bool // Add a signed dsa-ai INFERENCE_COMPLETED claim with FAILED outcome.
	AuditSeq              any  // Signed audit counter claim for precedence tests.
	GatewayConversationID *string
	OmitMarker            bool
	ExtraClaim            bool
	EventType             string
	SealedPartial         bool
	UnsignedTier          string
}

func (w *World) cleaningClaims(o CertOptions, n int, reqID, ts string) ([]map[string]any, error) {
	services := []string{"dsa-sanitizer", "dsa-gateway"}
	if o.Cleaning.ExtraClaim {
		services = append(services, "dsa-bridge")
	}
	if o.Cleaning.DuplicateService != "" {
		services = append(services, o.Cleaning.DuplicateService)
	}
	if o.Cleaning.InferenceFailed {
		services = append(services, "dsa-ai")
	}
	var claims []map[string]any
	for i, svc := range services {
		id := fmt.Sprintf("clm_cleaning-%04d-%s-%d", n, svc, i)
		payload := map[string]any{"conversation_id": o.ConversationID, "customer_id": o.CustomerID}
		if svc == "dsa-gateway" {
			if !o.Cleaning.OmitMarker {
				payload["cert_tier"] = "input-shield"
			}
			if o.Cleaning.GatewayConversationID != nil {
				payload["conversation_id"] = *o.Cleaning.GatewayConversationID
			}
		}
		seen, unseen := []string{"customer_id"}, []string{"inference_result"}
		claimType := "PII_SANITIZED"
		if svc == "dsa-ai" {
			claimType = "INFERENCE_COMPLETED"
		}
		signable := map[string]any{
			"claim_id": id, "request_id": reqID, "service_id": svc, "claim_type": claimType,
			"data_seen": seen, "data_not_seen": unseen, "payload": payload, "timestamp": ts,
		}
		if svc == "dsa-ai" && o.Cleaning.InferenceFailed {
			payload["inference_outcome"] = "FAILED"
		}
		canon, err := verify.CanonicalLexeme(signable)
		if err != nil {
			return nil, err
		}
		claim := map[string]any{
			"claim_id": id, "request_id": reqID, "service_id": svc, "claim_type": "CLAIM_TYPE_" + claimType,
			"data_seen": seen, "data_not_seen": unseen, "timestamp": ts,
			"canonical_payload": base64.StdEncoding.EncodeToString(canon),
			"signature":         base64.StdEncoding.EncodeToString(ed25519.Sign(w.Services[svc], canon)),
		}
		if svc == "dsa-ai" {
			claim["inference"] = map[string]any{}
		}
		claims = append(claims, claim)
	}
	if o.Cleaning.AuditSeq != nil {
		c, err := w.signAuditClaim(fmt.Sprintf("clm_cleaning-audit-%04d", n), reqID, ts, map[string]any{
			"conversation_id": o.ConversationID, "conv_seq": o.Cleaning.AuditSeq, "event_hash": strings.Repeat("a", 64),
		})
		if err != nil {
			return nil, err
		}
		claims = append(claims, c)
	}
	return claims, nil
}
