package bundletest

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

// RekorHandler serves the corpus's synthetic log entries as a Rekor v1 API
// (GET /api/v1/log/entries?logIndex=N), so --online runs on the BUILT binary
// without any network. Synthetic only.
func (co *Corpus) RekorHandler() http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		idx, err := strconv.ParseInt(r.URL.Query().Get("logIndex"), 10, 64)
		e, ok := co.Entries[idx]
		if r.URL.Path != "/api/v1/log/entries" || err != nil || !ok {
			http.NotFound(rw, r)
			return
		}
		rw.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(rw).Encode(map[string]any{"synthetic-" + strconv.FormatInt(idx, 10): map[string]any{
			"body": base64.StdEncoding.EncodeToString(e.Body), "integratedTime": e.IntegratedTime, "logIndex": e.LogIndex,
			"verification": map[string]any{
				"inclusionProof":       json.RawMessage(e.InclusionProof),
				"signedEntryTimestamp": base64.StdEncoding.EncodeToString(e.SignedEntryTimestamp),
			},
		}})
	})
}

// ExpandFlags replaces RekorURLPlaceholder in a case's flags with url.
func ExpandFlags(flags []string, url string) []string {
	out := make([]string, len(flags))
	for i, f := range flags {
		out[i] = strings.ReplaceAll(f, RekorURLPlaceholder, url)
	}
	return out
}
