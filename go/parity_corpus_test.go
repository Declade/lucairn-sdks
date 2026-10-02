package lucairn

// Certificate verifier parity: VerifyCertificateChain against the vendored
// corpus (testdata/parity-corpus, format lucairn-parity-corpus/v1.2.2, source
// commit in SOURCE.json). The TS (ts/src/verify-chain/parityCorpus.test.ts)
// and Python (python/tests/test_parity_corpus.py) SDKs run the same cases
// against the same expectations: every result field, `verified` compared as
// canonical JSON, under both policies, with each case's request-binding
// inputs, plus the pinned-key policy vectors.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/declade/lucairn-sdks/go/internal/verify"
)

const (
	parityFormat        = "lucairn-parity-corpus/v1.2.2"
	parityExpectedCases = 93
)

var parityRoot = filepath.Join("..", "testdata", "parity-corpus")

type paritySummary struct {
	Verdict           string `json:"verdict"`
	Reason            string `json:"reason"`
	EgressAttestation string `json:"egress_attestation"`
	UserUnredacted    string `json:"user_unredacted"`
	SignedCertTier    string `json:"signed_cert_tier"`
	SignableVersion   string `json:"signable_version"`
	RequestBinding    string `json:"request_binding"`
}

type parityInputs struct {
	ExpectedRequestID     *string `json:"expected_request_id,omitempty"`
	ExpectedCertificateID *string `json:"expected_certificate_id,omitempty"`
}

type parityPolicy struct {
	Name                   string `json:"name"`
	MinimumSignableVersion string `json:"minimum_signable_version"`
}

type parityManifest struct {
	Format           string         `json:"format"`
	Seed             string         `json:"seed"`
	Keys             string         `json:"keys"`
	KeyPolicy        string         `json:"key_policy"`
	MaxInputBytes    int            `json:"max_input_bytes"`
	MaxDepth         int            `json:"max_depth"`
	MaxValuesPointer int            `json:"max_values_pointer_bytes"`
	Policies         []parityPolicy `json:"policies"`
	Verdicts         []string       `json:"verdicts"`
	Reasons          []string       `json:"reasons"`
	EgressStates     []string       `json:"egress_states"`
	UserUnredacted   []string       `json:"user_unredacted"`
	SignedCertTiers  []string       `json:"signed_cert_tiers"`
	SignableVersions []string       `json:"signable_versions"`
	RequestBindings  []string       `json:"request_bindings"`
	Classes          []string       `json:"classes"`
	Cases            []struct {
		ID       string                   `json:"id"`
		File     string                   `json:"file"`
		SHA256   string                   `json:"sha256"`
		Class    string                   `json:"class"`
		Surface  string                   `json:"surface"`
		Inputs   *parityInputs            `json:"inputs"`
		Expected map[string]paritySummary `json:"expected"`
	} `json:"cases"`
}

// parityCase is one case file. The certificate is kept as its exact bytes
// (json.RawMessage): a case nests up to 257 levels and carries a 5,000-digit
// integer token, so it is never decoded into Go values before the verifier
// sees it.
type parityCase struct {
	Format          string                     `json:"format"`
	ID              string                     `json:"id"`
	Class           string                     `json:"class"`
	Surface         string                     `json:"surface"`
	Certificate     json.RawMessage            `json:"certificate"`
	CertificateText *string                    `json:"certificate_text"`
	Inputs          *parityInputs              `json:"inputs"`
	Expected        map[string]json.RawMessage `json:"expected"`
}

type parityKeysFile struct {
	Format  string `json:"format"`
	Witness struct {
		KeyID  string `json:"key_id"`
		Base64 string `json:"public_key_base64"`
	} `json:"witness"`
	Services map[string]struct {
		Base64 string `json:"public_key_base64"`
	} `json:"services"`
	NotPinned map[string]struct {
		Base64 string `json:"public_key_base64"`
	} `json:"not_pinned"`
}

func parityRead(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(parityRoot, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return b
}

func paritySHA(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func parityKeys(t *testing.T) parityKeysFile {
	t.Helper()
	var k parityKeysFile
	if err := json.Unmarshal(parityRead(t, "v1/keys.json"), &k); err != nil {
		t.Fatal(err)
	}
	return k
}

// parityLoad reads the manifest and the corpus keys. The parity harness is
// the ONE place AllowTestKeys is set.
func parityLoad(t *testing.T) (parityManifest, CertificateChainKeys) {
	t.Helper()
	var m parityManifest
	if err := json.Unmarshal(parityRead(t, "v1/manifest.json"), &m); err != nil {
		t.Fatal(err)
	}
	if m.Format != parityFormat {
		t.Fatalf("manifest format %q, want %q", m.Format, parityFormat)
	}
	k := parityKeys(t)
	keys := CertificateChainKeys{WitnessKeyID: k.Witness.KeyID, WitnessPublicKey: k.Witness.Base64, ServicePublicKeys: map[string]any{}, AllowTestKeys: true}
	for s, v := range k.Services {
		keys.ServicePublicKeys[s] = v.Base64
	}
	return m, keys
}

func parityLoadCase(t *testing.T, file string) parityCase {
	t.Helper()
	var c parityCase
	if err := json.Unmarshal(parityRead(t, filepath.Join("v1", file)), &c); err != nil {
		t.Fatalf("%s: %v", file, err)
	}
	return c
}

// input is the verifier input: certificate_text verbatim when present, else
// the certificate's exact bytes from the case file.
func (c parityCase) input(t *testing.T) []byte {
	t.Helper()
	if c.CertificateText != nil {
		if string(c.Certificate) != "null" {
			t.Fatalf("%s: certificate_text beside a non-null certificate", c.ID)
		}
		return []byte(*c.CertificateText)
	}
	return c.Certificate
}

// parityCanonical is canonical_json of a JSON text (number lexemes kept,
// keys sorted by code point, ensure_ascii) — the parity form of a result.
func parityCanonical(t *testing.T, raw []byte) string {
	t.Helper()
	v, err := verify.DecodeDocument(raw)
	if err != nil {
		t.Fatalf("not one JSON document: %v", err)
	}
	b, err := verify.CanonicalLexeme(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func parityResultCanonical(t *testing.T, r *CertificateChainResult) string {
	t.Helper()
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return parityCanonical(t, b)
}

func parityKeysFor(keys CertificateChainKeys, p parityPolicy, in *parityInputs) CertificateChainKeys {
	k := keys
	k.MinimumSignableVersion = ""
	if p.MinimumSignableVersion == "v3" {
		k.MinimumSignableVersion = "v3"
	}
	if in != nil {
		k.ExpectedRequestID, k.ExpectedCertificateID = in.ExpectedRequestID, in.ExpectedCertificateID
	}
	return k
}

func parityIn(v string, set []string) bool {
	for _, s := range set {
		if s == v {
			return true
		}
	}
	return false
}

func TestParityCorpus_VendoredCopyMatchesRecordedHashes(t *testing.T) {
	var src struct {
		Format         string `json:"format"`
		SourceCommit   string `json:"source_commit"`
		ManifestSHA256 string `json:"manifest_sha256"`
		KeysSHA256     string `json:"keys_sha256"`
		PolicySHA256   string `json:"key_policy_sha256"`
		TableSHA256    string `json:"recipe_table_sha256"`
	}
	if err := json.Unmarshal(parityRead(t, "SOURCE.json"), &src); err != nil {
		t.Fatal(err)
	}
	m, _ := parityLoad(t)
	if src.Format != parityFormat || m.Format != src.Format || !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(src.SourceCommit) {
		t.Fatalf("SOURCE.json format %q / manifest %q / commit %q", src.Format, m.Format, src.SourceCommit)
	}
	for rel, want := range map[string]string{"v1/manifest.json": src.ManifestSHA256, "v1/keys.json": src.KeysSHA256, "v1/key-policy.json": src.PolicySHA256, "recipe-table.md": src.TableSHA256} {
		if got := paritySHA(parityRead(t, rel)); got != want {
			t.Errorf("%s drifted (%s != %s): re-run testdata/parity-corpus/sync.sh", rel, got, want)
		}
	}
	if k := parityKeys(t); k.Format != parityFormat {
		t.Errorf("keys.json format %q", k.Format)
	}
	entries, err := os.ReadDir(filepath.Join(parityRoot, "v1", "cases"))
	if err != nil {
		t.Fatal(err)
	}
	var onDisk, listed []string
	for _, e := range entries {
		onDisk = append(onDisk, e.Name())
	}
	for _, mc := range m.Cases {
		listed = append(listed, filepath.Base(mc.File))
		if got := paritySHA(parityRead(t, filepath.Join("v1", mc.File))); got != mc.SHA256 {
			t.Errorf("%s drifted from its manifest sha256", mc.ID)
		}
	}
	sort.Strings(onDisk)
	sort.Strings(listed)
	if !reflect.DeepEqual(onDisk, listed) {
		t.Errorf("case files on disk %v != manifest %v", onDisk, listed)
	}
	top, err := os.ReadDir(filepath.Join(parityRoot, "v1"))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range top {
		names = append(names, e.Name())
	}
	if strings.Join(names, ",") != "cases,key-policy.json,keys.json,manifest.json" {
		t.Errorf("unexpected vendored files: %v", names)
	}
}

func TestParityCorpus_StepTableEqualsSpec(t *testing.T) {
	spec := string(parityRead(t, "recipe-table.md"))
	table := strings.Split(strings.Split(spec, "<!-- recipe-table:begin -->")[1], "<!-- recipe-table:end -->")[0]
	lines := strings.Split(strings.TrimSpace(table), "\n")[2:]
	cell := regexp.MustCompile("^(\\S+) `(\\S+)`$")
	var got []verify.ChainStep
	for _, line := range lines {
		cells := strings.Split(strings.Trim(strings.TrimSpace(line), "|"), "|")
		mm := cell.FindStringSubmatch(strings.TrimSpace(cells[2]))
		if mm == nil {
			t.Fatalf("row %q", line)
		}
		got = append(got, verify.ChainStep{ID: strings.TrimSpace(cells[0]), Verdict: mm[1], Reason: mm[2]})
	}
	if !reflect.DeepEqual(got, verify.ChainSteps) {
		t.Fatalf("ChainSteps != recipe-table.md\n got  %v\n want %v", verify.ChainSteps, got)
	}
}

// The manifest's closed vocabularies, policies and bounds are the ones this
// SDK implements.
func TestParityCorpus_ManifestVocabularies(t *testing.T) {
	m, _ := parityLoad(t)
	want := parityManifest{
		Format: parityFormat, Seed: m.Seed, Keys: "keys.json", KeyPolicy: "key-policy.json",
		MaxInputBytes: verify.MaxChainInputBytes, MaxDepth: verify.MaxChainDepth, MaxValuesPointer: verify.MaxChainValuesPointerBytes,
		Policies:         []parityPolicy{{"default", "v2"}, {"minimum_v3", "v3"}},
		Verdicts:         []string{"FAILED", "PARTIAL", "EGRESS_UNATTESTED", "VERIFIED"},
		EgressStates:     []string{"signed_digests", "unattested", "not_evaluated"},
		UserUnredacted:   []string{"true", "false", "unknown"},
		SignedCertTiers:  []string{"absent", "input_shield", "input_shield_two_signer", "audit_only", "inconsistent", "not_evaluated"},
		SignableVersions: []string{"v2", "v3", "none"},
		RequestBindings:  []string{"matched", "not_checked", "not_evaluated"},
		Classes:          []string{"honest", "tamper", "edge"},
	}
	got := m
	got.Reasons, got.Cases = nil, nil
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("manifest header\n got  %+v\n want %+v", got, want)
	}
	// The reason enum is exactly the recipe's reasons.
	fromRecipe := map[string]bool{}
	for _, s := range verify.ChainSteps {
		fromRecipe[s.Reason] = true
	}
	enum := map[string]bool{}
	for _, r := range m.Reasons {
		enum[r] = true
	}
	if !reflect.DeepEqual(fromRecipe, enum) {
		t.Errorf("reason enum %v != recipe reasons %v", m.Reasons, fromRecipe)
	}
}

func TestParityCorpus_EveryCaseEveryPolicy(t *testing.T) {
	m, keys := parityLoad(t)
	if len(m.Cases) != parityExpectedCases {
		t.Fatalf("%d cases, want %d", len(m.Cases), parityExpectedCases)
	}
	passed := map[string]int{}
	reasons := map[string]bool{}
	inputsSeen := 0
	for _, mc := range m.Cases {
		c := parityLoadCase(t, mc.File)
		if c.Format != parityFormat || c.ID != mc.ID || c.Class != mc.Class || c.Surface != mc.Surface ||
			!reflect.DeepEqual(c.Inputs, mc.Inputs) || len(c.Expected) != len(m.Policies) {
			t.Errorf("%s: case file and manifest entry disagree", mc.ID)
		}
		if !parityIn(c.Class, m.Classes) || (c.Surface != "get_certificate" && c.Surface != "witness_export") {
			t.Errorf("%s: class %q / surface %q", c.ID, c.Class, c.Surface)
		}
		if c.Inputs != nil {
			inputsSeen++
		}
		raw := c.input(t)
		// A second, independent input form: the certificate re-serialised
		// as canonical JSON with its lexemes kept (possible for every case
		// that is one document of at most 256 levels).
		var alt []byte
		if c.CertificateText == nil {
			if doc, err := verify.DecodeDocument(raw); err == nil {
				if alt, err = verify.CanonicalLexeme(doc); err != nil {
					t.Fatalf("%s: %v", c.ID, err)
				}
			}
		}
		for _, p := range m.Policies {
			wantRaw, ok := c.Expected[p.Name]
			if !ok {
				t.Errorf("%s: no expected result for policy %s", c.ID, p.Name)
				continue
			}
			var want paritySummary
			if err := json.Unmarshal(wantRaw, &want); err != nil {
				t.Fatal(err)
			}
			if want != mc.Expected[p.Name] {
				t.Errorf("%s [%s]: manifest summary %+v != case file %+v", c.ID, p.Name, mc.Expected[p.Name], want)
			}
			reasons[want.Reason] = true
			got, err := VerifyCertificateChain(raw, parityKeysFor(keys, p, c.Inputs))
			if err != nil {
				t.Fatalf("%s [%s]: %v", c.ID, p.Name, err)
			}
			// Every field, `verified` as canonical JSON, and no extra field.
			gotC, wantC := parityResultCanonical(t, got), parityCanonical(t, wantRaw)
			if gotC == wantC {
				passed[p.Name]++
			} else {
				t.Errorf("%s [%s]\n got  %.2000s\n want %.2000s", c.ID, p.Name, gotC, wantC)
			}
			if alt != nil {
				got2, err := VerifyCertificateChain(alt, parityKeysFor(keys, p, c.Inputs))
				if err != nil || parityResultCanonical(t, got2) != gotC {
					t.Errorf("%s [%s]: the canonical re-serialisation gives a different result", c.ID, p.Name)
				}
			}
			if !parityIn(got.Verdict, m.Verdicts) || !parityIn(got.Reason, m.Reasons) || !parityIn(got.EgressAttestation, m.EgressStates) ||
				!parityIn(got.UserUnredacted, m.UserUnredacted) || !parityIn(got.SignedCertTier, m.SignedCertTiers) ||
				!parityIn(got.SignableVersion, m.SignableVersions) || !parityIn(got.RequestBinding, m.RequestBindings) {
				t.Errorf("%s [%s]: value outside the manifest vocabularies: %+v", c.ID, p.Name, *got)
			}
			// FAILED ⇔ nothing evaluated or verified.
			failed := got.Verdict == "FAILED"
			if failed != (got.UserUnredacted == "unknown") || failed != (got.SignedCertTier == "not_evaluated") ||
				failed != (got.SignableVersion == "none") || failed != (got.RequestBinding == "not_evaluated") ||
				failed != (got.Verified == nil) || failed != (got.EgressAttestation == "not_evaluated") {
				t.Errorf("%s [%s]: FAILED must pair exactly with unknown / not_evaluated / none / verified null: %+v", c.ID, p.Name, *got)
			}
			// request_binding is matched exactly on the cases with inputs.
			if !failed && (got.RequestBinding == "matched") != (c.Inputs != nil) {
				t.Errorf("%s [%s]: request_binding %s with inputs %v", c.ID, p.Name, got.RequestBinding, c.Inputs)
			}
			if !failed {
				parityCheckVerifiedShape(t, c.ID+" ["+p.Name+"]", got)
			}
		}
	}
	for _, r := range m.Reasons {
		if !reasons[r] {
			t.Errorf("reason %s is no case's expected reason", r)
		}
	}
	if inputsSeen < 3 {
		t.Errorf("only %d cases carry request-binding inputs", inputsSeen)
	}
	t.Logf("go parity: default %d/%d, minimum_v3 %d/%d", passed["default"], len(m.Cases), passed["minimum_v3"], len(m.Cases))
	if passed["default"] != parityExpectedCases || passed["minimum_v3"] != parityExpectedCases {
		t.Fatalf("parity incomplete: %v", passed)
	}
}

// parityCheckVerifiedShape — verified.certificate is exactly the 7-key v2 /
// 13-key v3 signable; every claim entry has its canonical bytes and a key
// "<index>:<service_id>:<claim_type>" whose parts match the signed values.
func parityCheckVerifiedShape(t *testing.T, label string, r *CertificateChainResult) {
	t.Helper()
	v2 := []string{"certificate_id", "claim_ids", "issued_at", "overall_verdict", "protocol_version", "request_id", "witness_key_id"}
	v3 := append(append([]string{}, v2...), "api_key_id", "byok_exempt", "client_id", "redaction_manifest_hash", "sanitized_fields_body_hash", "tms_manifest_hash")
	sort.Strings(v3)
	want := map[string][]string{"v2": v2, "v3": v3}[r.SignableVersion]
	var keys []string
	for k := range r.Verified.Certificate {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if !reflect.DeepEqual(keys, want) {
		t.Errorf("%s: verified.certificate keys %v, want the %s signable", label, keys, r.SignableVersion)
	}
	ids, _ := r.Verified.Certificate["claim_ids"].([]any)
	if len(r.Verified.Claims) == 0 || len(r.Verified.Claims) != len(ids) {
		t.Errorf("%s: %d verified claims for %d claim ids", label, len(r.Verified.Claims), len(ids))
	}
	for key, c := range r.Verified.Claims {
		first, last := strings.Index(key, ":"), strings.LastIndex(key, ":")
		if first < 0 || first == last || c.Canonical == "" {
			t.Errorf("%s: claim key %q", label, key)
			continue
		}
		if c.Values["/service_id"] != key[first+1:last] || c.Values["/claim_type"] != key[last+1:] {
			t.Errorf("%s: claim key %q does not match its signed service / type", label, key)
		}
	}
}

// The result's JSON is exactly the corpus result shape.
func TestParityCorpus_ResultJSONShape(t *testing.T) {
	_, keys := parityLoad(t)
	got, err := VerifyCertificateChain([]byte("[]"), keys)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(got)
	want := `{"verdict":"FAILED","reason":"malformed","egress_attestation":"not_evaluated","user_unredacted":"unknown","signed_cert_tier":"not_evaluated","signable_version":"none","request_binding":"not_evaluated","verified":null}`
	if string(b) != want {
		t.Fatalf("got %s", b)
	}
}

// Request binding: an empty string is a supplied value, and it is compared
// with the WITNESS-SIGNED id.
func TestParityCorpus_RequestBindingEmptyStringIsSupplied(t *testing.T) {
	_, keys := parityLoad(t)
	raw := parityLoadCase(t, "cases/honest_full_chain_egress.json").input(t)
	empty := ""
	k := keys
	k.ExpectedRequestID = &empty
	got, err := VerifyCertificateChain(raw, k)
	if err != nil || got.Verdict != "FAILED" || got.Reason != "request_mismatch" {
		t.Fatalf("empty expected request id: %+v %v", got, err)
	}
	reqID := "req_parity_v1_full"
	k.ExpectedRequestID = &reqID
	got, err = VerifyCertificateChain(raw, k)
	if err != nil || got.Verdict != "VERIFIED" || got.RequestBinding != "matched" {
		t.Fatalf("matching request id: %+v %v", got, err)
	}
}

// RED-PROOF: the witness-signature-only VerifyCertificate accepts the
// edited-claim-body case (unchanged by design); VerifyCertificateChain FAILS
// it under both policies.
func TestParityCorpus_RedProof_EditedClaimBodySameID(t *testing.T) {
	_, keys := parityLoad(t)
	raw := parityLoadCase(t, "cases/tamper_claim_body_edited_same_id.json").input(t)
	old, err := VerifyCertificate(raw, VerifyCertificateKeys{WitnessKeyID: keys.WitnessKeyID, WitnessPublicKey: keys.WitnessPublicKey})
	if err != nil {
		t.Fatalf("witness-only verifier refused the case (RED-PROOF stale): %v", err)
	}
	if old.OverallVerdict != "VERDICT_VERIFIED" {
		t.Fatalf("witness-only verdict %q", old.OverallVerdict)
	}
	for _, mv := range []string{"", "v3"} {
		k := keys
		k.MinimumSignableVersion = mv
		got, err := VerifyCertificateChain(raw, k)
		if err != nil {
			t.Fatal(err)
		}
		if got.Verdict != "FAILED" || got.Reason != "claim_signature_invalid" {
			t.Fatalf("policy %q: %+v", mv, *got)
		}
	}
}

// parityNonTestKey is a valid Ed25519 key that is not a corpus test key.
func parityNonTestKey() string {
	seed := sha256.Sum256([]byte("lucairn-sdks go key-policy harness"))
	return base64.StdEncoding.EncodeToString(ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey))
}

// TestParityCorpus_KeyPolicyVectors — every key-policy.json vector, pinned
// both as the witness key and as a service key.
func TestParityCorpus_KeyPolicyVectors(t *testing.T) {
	var f struct {
		Format  string   `json:"format"`
		Codes   []string `json:"codes"`
		Vectors []struct {
			ID            string `json:"id"`
			PublicKey     string `json:"public_key"`
			AllowTestKeys bool   `json:"allow_test_keys"`
			Expected      string `json:"expected"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(parityRead(t, "v1/key-policy.json"), &f); err != nil {
		t.Fatal(err)
	}
	codes := []string{verify.KeyPolicyOK, verify.KeyPolicyMalformed, verify.KeyPolicySmallOrder, verify.KeyPolicyInvalidPoint, verify.KeyPolicyTestKey}
	if f.Format != parityFormat || !reflect.DeepEqual(f.Codes, codes) {
		t.Fatalf("key-policy.json format %q codes %v", f.Format, f.Codes)
	}
	good := parityNonTestKey()
	codeOf := func(k CertificateChainKeys) string {
		_, err := VerifyCertificateChain([]byte("{}"), k)
		if err == nil {
			return verify.KeyPolicyOK
		}
		var kpe *KeyPolicyError
		if !errors.As(err, &kpe) {
			t.Fatalf("not a KeyPolicyError: %v", err)
		}
		return kpe.Code
	}
	seen := map[string]int{}
	for _, v := range f.Vectors {
		asWitness := codeOf(CertificateChainKeys{WitnessKeyID: "w", WitnessPublicKey: v.PublicKey, AllowTestKeys: v.AllowTestKeys})
		asService := codeOf(CertificateChainKeys{WitnessKeyID: "w", WitnessPublicKey: good, AllowTestKeys: v.AllowTestKeys,
			ServicePublicKeys: map[string]any{"dsa-ai": v.PublicKey}})
		if asWitness != v.Expected || asService != v.Expected {
			t.Errorf("key vector %s: witness %s, service %s, want %s", v.ID, asWitness, asService, v.Expected)
		}
		seen[v.Expected]++
	}
	if seen[verify.KeyPolicySmallOrder] != 15 || seen[verify.KeyPolicyTestKey] != len(verify.ChainTestKeys) ||
		seen[verify.KeyPolicyMalformed] < 10 || seen[verify.KeyPolicyInvalidPoint] < 4 {
		t.Errorf("vector coverage: %v", seen)
	}
	// A key given as raw bytes must be exactly 32 bytes.
	raw, _ := base64.StdEncoding.DecodeString(good)
	if c := codeOf(CertificateChainKeys{WitnessKeyID: "w", WitnessPublicKey: raw}); c != verify.KeyPolicyOK {
		t.Errorf("32 raw bytes: %s", c)
	}
	if c := codeOf(CertificateChainKeys{WitnessKeyID: "w", WitnessPublicKey: raw[:31]}); c != verify.KeyPolicyMalformed {
		t.Errorf("31 raw bytes: %s", c)
	}
}

// The embedded test-key denylist is exactly the keys keys.json publishes,
// and the corpus keys load only with AllowTestKeys.
func TestParityCorpus_TestKeysRefusedWithoutAllowTestKeys(t *testing.T) {
	k := parityKeys(t)
	fromFile := []string{k.Witness.Base64}
	for _, v := range k.Services {
		fromFile = append(fromFile, v.Base64)
	}
	for _, v := range k.NotPinned {
		fromFile = append(fromFile, v.Base64)
	}
	embedded := append([]string{}, verify.ChainTestKeys...)
	sort.Strings(fromFile)
	sort.Strings(embedded)
	if !reflect.DeepEqual(fromFile, embedded) {
		t.Fatalf("embedded test keys %v != keys.json %v", embedded, fromFile)
	}
	_, keys := parityLoad(t)
	keys.AllowTestKeys = false
	_, err := VerifyCertificateChain([]byte("{}"), keys)
	var kpe *KeyPolicyError
	if !errors.As(err, &kpe) || kpe.Code != verify.KeyPolicyTestKey || kpe.Key != "witness" {
		t.Fatalf("corpus witness key without AllowTestKeys: %v", err)
	}
	keys.WitnessPublicKey = parityNonTestKey()
	_, err = VerifyCertificateChain([]byte("{}"), keys)
	if !errors.As(err, &kpe) || kpe.Code != verify.KeyPolicyTestKey {
		t.Fatalf("corpus service key without AllowTestKeys: %v", err)
	}
}

func TestVerifyCertificateChain_ConfigErrors(t *testing.T) {
	_, keys := parityLoad(t)
	bad := []CertificateChainKeys{
		{WitnessPublicKey: keys.WitnessPublicKey, AllowTestKeys: true},
		{WitnessKeyID: "w", WitnessPublicKey: keys.WitnessPublicKey, AllowTestKeys: true, ServicePublicKeys: map[string]any{"": keys.WitnessPublicKey}},
		{WitnessKeyID: "w", WitnessPublicKey: keys.WitnessPublicKey, AllowTestKeys: true, MinimumSignableVersion: "v4"},
	}
	for i, k := range bad {
		if _, err := VerifyCertificateChain([]byte("{}"), k); err == nil {
			t.Errorf("case %d: expected a ConfigError", i)
		} else if _, ok := err.(*ConfigError); !ok {
			t.Errorf("case %d: %T", i, err)
		}
	}
	var _ Error = &KeyPolicyError{}
	for _, k := range []CertificateChainKeys{
		{WitnessKeyID: "w", WitnessPublicKey: []byte{1, 2, 3}},
		{WitnessKeyID: "w", WitnessPublicKey: nil},
		{WitnessKeyID: "w", WitnessPublicKey: keys.WitnessPublicKey, AllowTestKeys: true, ServicePublicKeys: map[string]any{"dsa-ai": "!!"}},
	} {
		if _, err := VerifyCertificateChain([]byte("{}"), k); err == nil {
			t.Error("expected a KeyPolicyError")
		} else if e, ok := err.(*KeyPolicyError); !ok || e.Code != "key_malformed" {
			t.Errorf("%T %v", err, err)
		}
	}
	for _, junk := range []string{"", "[]", "\xff", strings.Repeat("{", 20000), "\xef\xbb\xbf{}"} {
		got, err := VerifyCertificateChain([]byte(junk), keys)
		if err != nil || got.Verdict != "FAILED" || got.Reason != "malformed" || got.UserUnredacted != "unknown" || got.Verified != nil {
			t.Errorf("junk %.10q: %+v %v", junk, got, err)
		}
	}
}

// A relabelled spec key (case variant, protojson JSON name) is malformed, so
// a typed re-parse (json.Unmarshal into VeilCertificate matches field names
// case-insensitively) can never read a value the recipe did not check.
func TestParityCorpus_CaseVariantKeyAppendedToHonestCertificate(t *testing.T) {
	_, keys := parityLoad(t)
	raw := parityLoadCase(t, "cases/honest_full_chain_egress.json").input(t)
	for _, extra := range []string{`"BYOK_EXEMPT":true`, `"byokExempt":true`, `"Client_Id":"x"`, `"clientId":"x"`} {
		doc, err := verify.DecodeDocument(raw)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := verify.CanonicalLexeme(doc)
		forged := append([]byte(`{`+extra+`,`), b[1:]...)
		got, err := VerifyCertificateChain(forged, keys)
		if err != nil || got.Verdict != "FAILED" || got.Reason != "malformed" {
			t.Errorf("%s: %+v %v", extra, got, err)
		}
	}
}

// Grammar vectors — the SAME vectors as the corpus references.
func TestParityCorpus_GrammarVectors(t *testing.T) {
	timestamps := [][2]string{
		{"2026-09-25T12:00:02.5Z", "2026-09-25T12:00:02.5Z"},
		{"2026-09-25T12:00:02.500000000Z", "2026-09-25T12:00:02.5Z"},
		{"2026-09-25T12:00:02.5000000000Z", ""},
		{"2026-09-25T12:00:00.123456789-00:30", "2026-09-25T12:30:00.123456789Z"},
		{"2026-09-25T14:00:00+02:00", "2026-09-25T12:00:00Z"},
		{"2024-02-29T00:00:00Z", "2024-02-29T00:00:00Z"},
		{"0001-01-01T00:00:00-01:00", "0001-01-01T01:00:00Z"},
		{"2026-09-25T12:00:00+24:00", ""},
		{"2026-09-25T12:00:00+23:60", ""},
		{"2026-09-25T12:00:00+99:00", ""},
		{"2026-09-25T12:00:60Z", ""},
		{"2026-09-25T24:00:00Z", ""},
		{"2026-02-30T12:00:00Z", ""},
		{"0000-01-01T00:00:00Z", ""},
		{"0001-01-01T00:00:00+01:00", ""},
		{"9999-12-31T23:59:59-01:00", ""},
		{"2026-09-25t12:00:00z", ""},
		{"2026-09-25T12:00:00.Z", ""},
		{"2026-09-25T12:00:00", ""},
		{"２026-09-25T12:00:00Z", ""},
	}
	for _, v := range timestamps {
		got, ok := verify.ChainIssuedAt(v[0])
		if !ok {
			got = ""
		}
		if got != v[1] {
			t.Errorf("timestamp %q: got %q, want %q", v[0], got, v[1])
		}
	}
	nested := func(n int) string { return strings.Repeat("[", n) + strings.Repeat("]", n) }
	depth := verify.MaxChainDepth
	documents := []struct {
		in string
		ok bool
	}{
		{`{"a":1}`, true}, {"{\"a\":1} \n\t\r", true}, {`{"a":1}]`, false}, {`{"a":1}}`, false},
		{`{"a":1} x`, false}, {`{"a":1}{"b":2}`, false}, {`{"a":NaN}`, false}, {`{"a":Infinity}`, false},
		{`{"a":-Infinity}`, false}, {"\xef\xbb\xbf{\"a\":1}", false}, {"{\"a\":\"\xff\"}", false},
		{`{"a":1]`, false}, {`[1,]`, false}, {`{"a":1,}`, false},
		// Duplicate keys, compared after escape decoding.
		{`{"a":1,"a":1}`, false}, {`{"a":1,"a":2}`, false}, {`{"a":1,"a":2}`, false},
		{`{"a":{"b":1},"c":{"b":1}}`, true}, {`[{"a":1},{"a":1}]`, true},
		// Surrogate escapes: a high + low pair only.
		{`{"a":"😀"}`, true}, {`{"a":"😀"}`, true}, {`{"a":"\ud800"}`, false},
		{`{"a":"\udc00"}`, false}, {`{"a":"\ud800A"}`, false}, {`{"a":"\ud800\ud800"}`, false},
		{`{"a":"\ud800\\udc00"}`, false}, {`{"\ud800":1}`, false}, {`{"a":"\\ud800"}`, true},
		// Depth: at most 256 nested arrays / objects; brackets in strings do not count.
		{nested(depth), true}, {nested(depth + 1), false},
		{`{"a":` + nested(depth-1) + `}`, true}, {`{"a":` + nested(depth) + `}`, false},
		{`{"a":"` + strings.Repeat("[", depth+1) + `"}`, true},
	}
	for _, v := range documents {
		if _, err := verify.DecodeDocument([]byte(v.in)); (err == nil) != v.ok {
			t.Errorf("document %.80q: parses=%v, want %v (%v)", v.in, err == nil, v.ok, err)
		}
	}
	certificateKeys := []struct {
		key     string
		refused bool
	}{
		{"byok_exempt", false}, {"BYOK_EXEMPT", true}, {"Client_Id", true},
		{"byoK_exempt", true}, {"ſervice_id", true},
		{"upstream_model", false}, {"UPSTREAM_MODEL", false}, {"PERSON", false},
		{"byok_exempt ", false}, {"İssued_at", false},
		{"byokExempt", true}, {"ByokExempt", true}, {"byokexempt", true}, {"clientId", true},
		{"upstreamRequestBodies", true}, {"upstreamBodySha256", true}, {"kAnonymity", true},
		{"model_uſed", true}, {"upstreamModel", false}, {"certificate_id_", false},
	}
	for _, v := range certificateKeys {
		doc, _ := json.Marshal(map[string]any{v.key: true})
		if _, err := verify.DecodeCertificate(doc); (err != nil) != v.refused {
			t.Errorf("certificate key %q: refused=%v, want %v", v.key, err != nil, v.refused)
		}
	}
	// Every spec key's protojson JSON name is refused.
	for _, k := range verify.SpecKeys() {
		if j := verify.ProtoJSONName(k); j != k {
			doc, _ := json.Marshal(map[string]any{j: true})
			if _, err := verify.DecodeCertificate(doc); err == nil {
				t.Errorf("JSON name %q of spec key %q is not refused", j, k)
			}
		}
	}
	blank := []struct {
		in    string
		blank bool
	}{
		{"", true}, {" \t\n\v\f\r", true}, {"  　\u0085", true},
		{"\u001c", false}, {"\u001f", false}, {"​", false}, {"x", false},
	}
	for _, v := range blank {
		if got := verify.ChainTrimSpace(v.in) == ""; got != v.blank {
			t.Errorf("blank %q: %v, want %v", v.in, got, v.blank)
		}
	}
	integers := []struct {
		in string
		ok bool
	}{
		{"0", true}, {"2", true}, {"18446744073709551615", true}, {"18446744073709551616", false},
		{"00", false}, {"2.0", false}, {"2e0", false}, {"-1", false}, {"1" + strings.Repeat("0", 4999), false},
	}
	for _, v := range integers {
		if _, ok := verify.ChainInteger(json.Number(v.in), math.MaxUint64); ok != v.ok {
			t.Errorf("integer %.30q: %v, want %v", v.in, ok, v.ok)
		}
	}
	floats := []struct {
		in string
		ok bool
	}{
		{"0.25", true}, {"1e-50", true}, {"3.4028235e38", true}, {"3.4028236e38", false},
		{"1e39", false}, {"-1e39", false}, {"1e400", false},
	}
	for _, v := range floats {
		if _, ok := verify.ChainFloat32(json.Number(v.in), false); ok != v.ok {
			t.Errorf("float32 %q: %v, want %v", v.in, ok, v.ok)
		}
	}
	// The input size bound: exactly MaxChainInputBytes passes the bound, one
	// more byte is malformed (whitespace padding keeps the document valid).
	doc := []byte(`{"a":1}`)
	atCap := append(append([]byte{}, doc...), bytes.Repeat([]byte(" "), verify.MaxChainInputBytes-len(doc))...)
	if _, err := verify.DecodeCertificate(atCap); err != nil {
		t.Errorf("a %d-byte document must pass the size bound: %v", len(atCap), err)
	}
	if _, err := verify.DecodeCertificate(append(atCap, ' ')); err == nil {
		t.Errorf("a %d-byte document must be refused", len(atCap)+1)
	}
}

// ---------------------------------------------------------------------------
// The store-cap export: an honest witness-export certificate carrying the
// inference sandbox's full per-turn store of raw upstream bodies (two 8 MiB
// bodies), built at test time (too large to commit). The corpus references
// build the same bytes and pin the same SHA-256 values.
// ---------------------------------------------------------------------------

const (
	storeCapBodyBytes      = 8 << 20
	storeCapInputBytes     = 22377772
	storeCapInputSHA256    = "3b1a18920801e20f239a42ab25fde44ed5bc741e947eb5af8872d24d6cb5469d"
	storeCapVerifiedSHA256 = "8d1c784e2d7d2d5b1df7875a7406350169cdac07924ebfbdf806de0623890ebd"
)

func storeCapExport(t *testing.T, certJSON []byte, seed string) []byte {
	t.Helper()
	root, err := verify.DecodeDocument(certJSON)
	if err != nil {
		t.Fatal(err)
	}
	cert := root.(map[string]any)
	bodies := [][]byte{bytes.Repeat([]byte("a"), storeCapBodyBytes), bytes.Repeat([]byte("b"), storeCapBodyBytes)}
	var digests, encoded []any
	for _, b := range bodies {
		sum := sha256.Sum256(b)
		digests = append(digests, hex.EncodeToString(sum[:]))
		encoded = append(encoded, base64.StdEncoding.EncodeToString(b))
	}
	s := sha256.Sum256([]byte("lucairn-parity-corpus|" + seed + "|dsa-ai"))
	priv := ed25519.NewKeyFromSeed(s[:])
	done := false
	for _, c := range cert["claims"].([]any) {
		m := c.(map[string]any)
		if m["service_id"] != "dsa-ai" {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(m["canonical_payload"].(string))
		if err != nil {
			t.Fatal(err)
		}
		d, err := verify.DecodeDocument(raw)
		if err != nil {
			t.Fatal(err)
		}
		doc := d.(map[string]any)
		doc["payload"].(map[string]any)["upstream_body_sha256"] = digests
		cp, err := verify.CanonicalLexeme(doc)
		if err != nil {
			t.Fatal(err)
		}
		m["canonical_payload"] = base64.StdEncoding.EncodeToString(cp)
		m["signature"] = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, cp))
		m["inference"].(map[string]any)["upstream_request_bodies"] = encoded
		done = true
	}
	if !done {
		t.Fatal("no dsa-ai claim")
	}
	out, err := verify.CanonicalLexeme(cert)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestParityCorpus_StoreCapExportVerified(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a 22 MB certificate")
	}
	m, keys := parityLoad(t)
	in := storeCapExport(t, parityLoadCase(t, "cases/honest_full_chain_egress_export.json").input(t), m.Seed)
	if len(in) <= 16<<20 || len(in) > verify.MaxChainInputBytes {
		t.Fatalf("store-cap export is %d bytes", len(in))
	}
	got, err := VerifyCertificateChain(in, keys)
	if err != nil || got.Verdict != "VERIFIED" || got.Reason != "ok" || got.EgressAttestation != "signed_digests" {
		t.Fatalf("store-cap export: %+v %v", got, err)
	}
	vb, _ := json.Marshal(got.Verified)
	vsum := sha256.Sum256([]byte(parityCanonical(t, vb)))
	if len(in) != storeCapInputBytes || paritySHA(in) != storeCapInputSHA256 || hex.EncodeToString(vsum[:]) != storeCapVerifiedSHA256 {
		t.Errorf("store-cap export pins: %d bytes, sha256 %s, verified sha256 %x", len(in), paritySHA(in), vsum)
	}
}

// The consumer procedure for a displayed upstream body: hash its exact
// bytes and require the digest at the same index in the VERIFIED egress
// claim's values (the claim carrying /payload/upstream_body_sha256/0).
func TestParityCorpus_BodiesHashToVerifiedDigests(t *testing.T) {
	_, keys := parityLoad(t)
	c := parityLoadCase(t, "cases/honest_full_chain_egress_export.json")
	got, err := VerifyCertificateChain(c.input(t), keys)
	if err != nil || got.Verdict != "VERIFIED" {
		t.Fatalf("%+v %v", got, err)
	}
	var egress map[string]any
	for _, vc := range got.Verified.Claims {
		if _, ok := vc.Values["/payload/upstream_body_sha256/0"]; ok {
			if egress != nil {
				t.Fatal("two egress claims")
			}
			egress = vc.Values
		}
	}
	var cert struct {
		Claims []struct {
			Inference *struct {
				Bodies []string `json:"upstream_request_bodies"`
			} `json:"inference"`
		} `json:"claims"`
	}
	if err := json.Unmarshal(c.input(t), &cert); err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, cl := range cert.Claims {
		if cl.Inference == nil {
			continue
		}
		for j, b := range cl.Inference.Bodies {
			raw, err := base64.StdEncoding.DecodeString(b)
			if err != nil {
				t.Fatal(err)
			}
			if egress[fmt.Sprintf("/payload/upstream_body_sha256/%d", j)] != paritySHA(raw) {
				t.Errorf("body %d does not hash to the verified digest", j)
			}
			checked++
		}
	}
	if checked != 2 {
		t.Fatalf("checked %d bodies, want 2", checked)
	}
}

// ---------------------------------------------------------------------------
// Two-signer input-shield chain: corpus v1.2.1 vendors the honest and three
// label-tamper vectors; this in-test matrix is kept ALONGSIDE them because it
// covers the wider label x shape combinations (no duplicate of a vendored case). The witness writes the unsigned tier
// `input_shield_two_signer` for an input-shield chain with only sanitizer +
// gateway claims. Constructed here from honest_input_shield: the dsa-ai claim
// is removed and the certificate re-sealed with the corpus witness TEST key
// (derived from the public corpus seed).
// ---------------------------------------------------------------------------

// reissueClaim rewrites a claim's signed document with mutate (which may
// change its service_id) and re-signs it with that service's corpus TEST key
// (derived from the public corpus seed); the outer service_id follows.
func reissueClaim(t *testing.T, seed string, m map[string]any, mutate func(doc map[string]any)) {
	t.Helper()
	raw, _ := base64.StdEncoding.DecodeString(m["canonical_payload"].(string))
	d, err := verify.DecodeDocument(raw)
	if err != nil {
		t.Fatal(err)
	}
	doc := d.(map[string]any)
	mutate(doc)
	cp, err := verify.CanonicalLexeme(doc)
	if err != nil {
		t.Fatal(err)
	}
	svc := doc["service_id"].(string)
	ks := sha256.Sum256([]byte("lucairn-parity-corpus|" + seed + "|" + svc))
	m["service_id"] = svc
	m["canonical_payload"] = base64.StdEncoding.EncodeToString(cp)
	m["signature"] = base64.StdEncoding.EncodeToString(ed25519.Sign(ed25519.NewKeyFromSeed(ks[:]), cp))
}

// twoSignerCert returns honest_input_shield without the claims of the
// services in drop, each remaining claim whose service_id has an entry in
// edits re-issued through it (reissueClaim), the unsigned tier set to tier,
// and both witness signatures re-made over the resulting signables.
func twoSignerCert(t *testing.T, seed string, drop []string, tier string, edits map[string]func(doc map[string]any)) []byte {
	t.Helper()
	root, err := verify.DecodeDocument(parityLoadCase(t, "cases/honest_input_shield.json").input(t))
	if err != nil {
		t.Fatal(err)
	}
	cert := root.(map[string]any)
	var claims, ids []any
	var sanitizerPayload map[string]any
	for _, c := range cert["claims"].([]any) {
		m := c.(map[string]any)
		if parityIn(m["service_id"].(string), drop) {
			continue
		}
		if edit, ok := edits[m["service_id"].(string)]; ok {
			reissueClaim(t, seed, m, edit)
		}
		claims = append(claims, m)
		ids = append(ids, m["claim_id"])
		if m["service_id"] == "dsa-sanitizer" && sanitizerPayload == nil {
			raw, _ := base64.StdEncoding.DecodeString(m["canonical_payload"].(string))
			d, err := verify.DecodeDocument(raw)
			if err != nil {
				t.Fatal(err)
			}
			sanitizerPayload = d.(map[string]any)["payload"].(map[string]any)
		}
	}
	cert["claims"] = claims
	ver := cert["verification"].(map[string]any)
	ver["cert_tier"] = tier
	issued, ok := verify.ChainIssuedAt(cert["issued_at"].(string))
	if !ok {
		t.Fatal("issued_at")
	}
	v2 := map[string]any{
		"certificate_id": cert["certificate_id"], "request_id": cert["request_id"], "protocol_version": json.Number("2"),
		"claim_ids": ids, "issued_at": issued, "witness_key_id": cert["witness_key_id"],
		"overall_verdict": strings.TrimPrefix(ver["overall_verdict"].(string), "VERDICT_"),
	}
	v3 := map[string]any{}
	for k, v := range v2 {
		v3[k] = v
	}
	byok, _ := ver["byok_exempt"].(bool)
	v3["client_id"], v3["api_key_id"], v3["byok_exempt"] = cert["client_id"], cert["api_key_id"], byok
	for k, src := range map[string]string{"redaction_manifest_hash": "redaction_manifest_hash", "sanitized_fields_body_hash": "sanitized_fields_hash", "tms_manifest_hash": "tms_manifest_hash"} {
		v3[k] = nil
		if s, ok := sanitizerPayload[src].(string); ok && s != "" {
			v3[k] = s
		}
	}
	s := sha256.Sum256([]byte("lucairn-parity-corpus|" + seed + "|witness"))
	priv := ed25519.NewKeyFromSeed(s[:])
	if base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)) != parityKeys(t).Witness.Base64 {
		t.Fatal("derived witness key is not the corpus witness key")
	}
	for field, m := range map[string]map[string]any{"witness_signature": v2, "signable_v3_signature": v3} {
		b, err := verify.CanonicalLexeme(m)
		if err != nil {
			t.Fatal(err)
		}
		cert[field] = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, b))
	}
	out, err := verify.CanonicalLexeme(cert)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestChainExtension_InputShieldTwoSigner(t *testing.T) {
	m, keys := parityLoad(t)
	ai := []string{"dsa-ai"}
	streaming := map[string]func(doc map[string]any){"dsa-sanitizer": func(doc map[string]any) {
		doc["service_id"] = "dsa-sanitizer-streaming"
	}}
	aiNoTier := map[string]func(doc map[string]any){"dsa-ai": func(doc map[string]any) {
		delete(doc["payload"].(map[string]any), "cert_tier")
	}}
	for _, tc := range []struct {
		name         string
		drop         []string
		edits        map[string]func(doc map[string]any)
		tier         string
		verdict, why string
		tier2        string
	}{
		// The two-signer shape pairs with its label: no digests → capped.
		{"two_signer_label", ai, nil, "input_shield_two_signer", "EGRESS_UNATTESTED", "egress_unattested", "input_shield_two_signer"},
		// Any other label on that shape decides exactly as the corpus
		// recipe does (one signed copy = inconsistent; sealed VERIFIED).
		{"two_signer_shape_empty_label", ai, nil, "", "FAILED", "cert_tier_mismatch", "not_evaluated"},
		{"two_signer_shape_input_shield_label", ai, nil, "input_shield", "FAILED", "cert_tier_mismatch", "not_evaluated"},
		{"two_signer_shape_full_chain_label", ai, nil, "full_chain", "FAILED", "cert_tier_mismatch", "not_evaluated"},
		// The label on a chain that still has its dsa-ai claim is a mismatch.
		{"label_with_dsa_ai_claim", nil, nil, "input_shield_two_signer", "FAILED", "cert_tier_mismatch", "not_evaluated"},
		// ... also when that dsa-ai claim signs no cert_tier (the gateway copy
		// is then the only one): any dsa-ai claim rules the label out. The
		// reason is decided at 8d, so the re-issued claim passed step 7.
		{"label_with_untiered_dsa_ai_claim", nil, aiNoTier, "input_shield_two_signer", "FAILED", "cert_tier_mismatch", "not_evaluated"},
		// Control: the re-sealed honest chain still verifies as in the corpus.
		// The label needs a sanitizer claim: gateway alone is a mismatch.
		{"label_without_sanitizer_claim", []string{"dsa-ai", "dsa-sanitizer"}, nil, "input_shield_two_signer", "FAILED", "cert_tier_mismatch", "not_evaluated"},
		{"label_without_sanitizer_claim_ai_kept", []string{"dsa-sanitizer"}, nil, "input_shield_two_signer", "FAILED", "cert_tier_mismatch", "not_evaluated"},
		// A streaming sanitizer claim does not count as the sanitizer claim.
		{"label_with_streaming_sanitizer_only", ai, streaming, "input_shield_two_signer", "FAILED", "cert_tier_mismatch", "not_evaluated"},
		// Control: the re-issued streaming claim itself verifies (the corpus
		// tier rules decide that chain as usual).
		{"control_streaming_sanitizer_resealed", nil, streaming, "input_shield", "EGRESS_UNATTESTED", "egress_unattested", "input_shield"},
		{"control_resealed_honest", nil, nil, "input_shield", "EGRESS_UNATTESTED", "egress_unattested", "input_shield"},
	} {
		for _, p := range m.Policies {
			got, err := VerifyCertificateChain(twoSignerCert(t, m.Seed, tc.drop, tc.tier, tc.edits), parityKeysFor(keys, p, nil))
			if err != nil {
				t.Fatal(err)
			}
			if got.Verdict != tc.verdict || got.Reason != tc.why || got.SignedCertTier != tc.tier2 {
				t.Errorf("%s [%s]: %s / %s / %s, want %s / %s / %s", tc.name, p.Name,
					got.Verdict, got.Reason, got.SignedCertTier, tc.verdict, tc.why, tc.tier2)
			}
		}
	}
}
