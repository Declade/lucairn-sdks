package lucairn

// T-935 S3 parity: VerifyCertificateChain against the vendored corpus
// (testdata/parity-corpus, vendored from Declade/dual-sandbox-architecture
// tools/parity-corpus at the commit in SOURCE.json). The TS
// (ts/src/verify-chain/parityCorpus.test.ts) and Python
// (python/tests/test_parity_corpus.py) SDKs run the same cases against the
// same expectations.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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

const parityExpectedCases = 54

var parityRoot = filepath.Join("..", "testdata", "parity-corpus")

type parityManifest struct {
	Format   string `json:"format"`
	Policies []struct {
		Name                   string `json:"name"`
		MinimumSignableVersion string `json:"minimum_signable_version"`
	} `json:"policies"`
	Verdicts         []string `json:"verdicts"`
	Reasons          []string `json:"reasons"`
	EgressStates     []string `json:"egress_states"`
	UserUnredacted   []string `json:"user_unredacted"`
	SignedCertTiers  []string `json:"signed_cert_tiers"`
	SignableVersions []string `json:"signable_versions"`
	Cases            []struct {
		ID       string                            `json:"id"`
		File     string                            `json:"file"`
		SHA256   string                            `json:"sha256"`
		Expected map[string]CertificateChainResult `json:"expected"`
	} `json:"cases"`
}

func parityRead(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(parityRoot, rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return b
}

func paritySHA(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func parityLoad(t *testing.T) (parityManifest, CertificateChainKeys) {
	t.Helper()
	var m parityManifest
	if err := json.Unmarshal(parityRead(t, "v1/manifest.json"), &m); err != nil {
		t.Fatal(err)
	}
	var k struct {
		Witness struct {
			KeyID  string `json:"key_id"`
			Base64 string `json:"public_key_base64"`
		} `json:"witness"`
		Services map[string]struct {
			Base64 string `json:"public_key_base64"`
		} `json:"services"`
	}
	if err := json.Unmarshal(parityRead(t, "v1/keys.json"), &k); err != nil {
		t.Fatal(err)
	}
	keys := CertificateChainKeys{WitnessKeyID: k.Witness.KeyID, WitnessPublicKey: k.Witness.Base64, ServicePublicKeys: map[string]any{}}
	for s, v := range k.Services {
		keys.ServicePublicKeys[s] = v.Base64
	}
	return m, keys
}

// parityInput is the verifier input: certificate_text verbatim when present,
// else the certificate's JSON text with every number lexeme kept.
func parityInput(t *testing.T, file string) []byte {
	t.Helper()
	doc, err := verify.DecodeDocument(parityRead(t, filepath.Join("v1", file)))
	if err != nil {
		t.Fatalf("%s: %v", file, err)
	}
	m := doc.(map[string]any)
	if txt, ok := m["certificate_text"].(string); ok {
		return []byte(txt)
	}
	b, err := verify.CanonicalLexeme(m["certificate"])
	if err != nil {
		t.Fatalf("%s: %v", file, err)
	}
	return b
}

func TestParityCorpus_VendoredCopyMatchesRecordedHashes(t *testing.T) {
	var src struct {
		Format         string `json:"format"`
		ManifestSHA256 string `json:"manifest_sha256"`
		KeysSHA256     string `json:"keys_sha256"`
		TableSHA256    string `json:"recipe_table_sha256"`
	}
	if err := json.Unmarshal(parityRead(t, "SOURCE.json"), &src); err != nil {
		t.Fatal(err)
	}
	m, _ := parityLoad(t)
	if src.Format != "lucairn-parity-corpus/v1.1" || m.Format != src.Format {
		t.Fatalf("format %q / %q", src.Format, m.Format)
	}
	for rel, want := range map[string]string{"v1/manifest.json": src.ManifestSHA256, "v1/keys.json": src.KeysSHA256, "recipe-table.md": src.TableSHA256} {
		if got := paritySHA(parityRead(t, rel)); got != want {
			t.Errorf("%s drifted (%s != %s): re-run testdata/parity-corpus/sync.sh", rel, got, want)
		}
	}
	entries, err := os.ReadDir(filepath.Join(parityRoot, "v1", "cases"))
	if err != nil {
		t.Fatal(err)
	}
	var onDisk, listed []string
	for _, e := range entries {
		onDisk = append(onDisk, e.Name())
	}
	for _, c := range m.Cases {
		listed = append(listed, filepath.Base(c.File))
		if got := paritySHA(parityRead(t, filepath.Join("v1", c.File))); got != c.SHA256 {
			t.Errorf("%s drifted from its manifest sha256", c.ID)
		}
	}
	sort.Strings(onDisk)
	sort.Strings(listed)
	if !reflect.DeepEqual(onDisk, listed) {
		t.Errorf("case files on disk %v != manifest %v", onDisk, listed)
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

func TestParityCorpus_EveryCaseEveryPolicy(t *testing.T) {
	m, keys := parityLoad(t)
	if len(m.Cases) != parityExpectedCases {
		t.Fatalf("%d cases, want %d", len(m.Cases), parityExpectedCases)
	}
	in := func(v string, set []string) bool {
		for _, s := range set {
			if s == v {
				return true
			}
		}
		return false
	}
	passed := map[string]int{}
	for _, c := range m.Cases {
		raw := parityInput(t, c.File)
		for _, p := range m.Policies {
			k := keys
			if p.MinimumSignableVersion == "v3" {
				k.MinimumSignableVersion = "v3"
			}
			got, err := VerifyCertificateChain(raw, k)
			if err != nil {
				t.Fatalf("%s [%s]: %v", c.ID, p.Name, err)
			}
			want := c.Expected[p.Name]
			if reflect.DeepEqual(*got, want) {
				passed[p.Name]++
			} else {
				t.Errorf("%s [%s]\n got  %+v\n want %+v", c.ID, p.Name, *got, want)
			}
			if !in(got.Verdict, m.Verdicts) || !in(got.Reason, m.Reasons) || !in(got.EgressAttestation, m.EgressStates) ||
				!in(got.UserUnredacted, m.UserUnredacted) || !in(got.SignedCertTier, m.SignedCertTiers) || !in(got.SignableVersion, m.SignableVersions) {
				t.Errorf("%s [%s]: value outside the manifest vocabularies: %+v", c.ID, p.Name, *got)
			}
		}
	}
	t.Logf("go parity: default %d/%d, minimum_v3 %d/%d", passed["default"], parityExpectedCases, passed["minimum_v3"], parityExpectedCases)
	if passed["default"] != parityExpectedCases || passed["minimum_v3"] != parityExpectedCases {
		t.Fatalf("parity incomplete: %v", passed)
	}
}

// The result's JSON is exactly the README § Result shape (field names, `[]`
// never null).
func TestParityCorpus_ResultJSONShape(t *testing.T) {
	_, keys := parityLoad(t)
	got, err := VerifyCertificateChain([]byte("[]"), keys)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(got)
	want := `{"verdict":"FAILED","reason":"malformed","egress_attestation":"not_evaluated","user_unredacted":"unknown","signed_cert_tier":"not_evaluated","signable_version":"none","authenticated_fields":[],"unauthenticated_fields":["api_key_id","byok_exempt","client_id"]}`
	if string(b) != want {
		t.Fatalf("got %s", b)
	}
}

// RED-PROOF (PRD § RED-PROOF): the witness-signature-only VerifyCertificate
// accepts the edited-claim-body case (the T-794 gap, unchanged by design);
// VerifyCertificateChain FAILS it under both policies.
func TestParityCorpus_RedProof_EditedClaimBodySameID(t *testing.T) {
	_, keys := parityLoad(t)
	raw := parityInput(t, "cases/tamper_claim_body_edited_same_id.json")
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

func TestVerifyCertificateChain_ConfigErrors(t *testing.T) {
	_, keys := parityLoad(t)
	bad := []CertificateChainKeys{
		{WitnessPublicKey: keys.WitnessPublicKey},
		{WitnessKeyID: "w", WitnessPublicKey: []byte{1, 2, 3}},
		{WitnessKeyID: "w", WitnessPublicKey: keys.WitnessPublicKey, ServicePublicKeys: map[string]any{"dsa-ai": "!!"}},
		{WitnessKeyID: "w", WitnessPublicKey: keys.WitnessPublicKey, ServicePublicKeys: map[string]any{"": keys.WitnessPublicKey}},
		{WitnessKeyID: "w", WitnessPublicKey: keys.WitnessPublicKey, MinimumSignableVersion: "v4"},
	}
	for i, k := range bad {
		if _, err := VerifyCertificateChain([]byte("{}"), k); err == nil {
			t.Errorf("case %d: expected a ConfigError", i)
		} else if _, ok := err.(*ConfigError); !ok {
			t.Errorf("case %d: %T", i, err)
		}
	}
	for _, junk := range []string{"", "[]", "\xff", strings.Repeat("{", 20000), "\xef\xbb\xbf{}"} {
		got, err := VerifyCertificateChain([]byte(junk), keys)
		if err != nil || got.Verdict != "FAILED" || got.Reason != "malformed" || got.UserUnredacted != "unknown" {
			t.Errorf("junk %.10q: %+v %v", junk, got, err)
		}
	}
}

// Grammar vectors — the SAME vectors as the DSA references
// (reference_test.go TestGrammar_Vectors, test_reference_verify.py).
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
	documents := []struct {
		in string
		ok bool
	}{
		{`{"a":1}`, true}, {"{\"a\":1} \n\t\r", true}, {`{"a":1}]`, false}, {`{"a":1}}`, false},
		{`{"a":1} x`, false}, {`{"a":1}{"b":2}`, false}, {`{"a":NaN}`, false}, {`{"a":Infinity}`, false},
		{`{"a":-Infinity}`, false}, {"\xef\xbb\xbf{\"a\":1}", false}, {"{\"a\":\"\xff\"}", false},
	}
	for _, v := range documents {
		if _, err := verify.DecodeDocument([]byte(v.in)); (err == nil) != v.ok {
			t.Errorf("document %q: parses=%v, want %v", v.in, err == nil, v.ok)
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
}
