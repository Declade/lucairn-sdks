package bundle

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// PublicRekorURL is the only log the built-in --online mode contacts. The
// bundle's own log_url is never followed (a bundle is untrusted input).
const PublicRekorURL = "https://rekor.sigstore.dev"

// HTTPRekorFetcher re-fetches entries from a Rekor v1 API.
type HTTPRekorFetcher struct {
	BaseURL string
	Client  *http.Client
}

// NewHTTPRekorFetcher returns a fetcher for baseURL with a 20 s timeout.
func NewHTTPRekorFetcher(baseURL string) *HTTPRekorFetcher {
	return &HTTPRekorFetcher{BaseURL: baseURL, Client: &http.Client{Timeout: 20 * time.Second}}
}

// Fetch implements RekorFetcher.
func (f *HTTPRekorFetcher) Fetch(logIndex int64) (*FetchedEntry, error) {
	resp, err := f.Client.Get(f.BaseURL + "/api/v1/log/entries?logIndex=" + strconv.FormatInt(logIndex, 10))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("log answered HTTP %d", resp.StatusCode)
	}
	var env map[string]struct {
		Body           string `json:"body"`
		IntegratedTime int64  `json:"integratedTime"`
		LogIndex       int64  `json:"logIndex"`
		Verification   struct {
			InclusionProof       json.RawMessage `json:"inclusionProof"`
			SignedEntryTimestamp string          `json:"signedEntryTimestamp"`
		} `json:"verification"`
	}
	if err := json.Unmarshal(b, &env); err != nil {
		return nil, fmt.Errorf("log response does not parse: %w", err)
	}
	if len(env) != 1 {
		return nil, errors.New("log response must hold exactly one entry")
	}
	for _, e := range env {
		body, err := base64.StdEncoding.DecodeString(e.Body)
		if err != nil {
			return nil, errors.New("log entry body is not base64")
		}
		set, err := base64.StdEncoding.DecodeString(e.Verification.SignedEntryTimestamp)
		if err != nil {
			return nil, errors.New("log entry SET is not base64")
		}
		return &FetchedEntry{Body: body, IntegratedTime: e.IntegratedTime, LogIndex: e.LogIndex,
			SignedEntryTimestamp: set, InclusionProof: e.Verification.InclusionProof}, nil
	}
	return nil, errors.New("unreachable")
}
