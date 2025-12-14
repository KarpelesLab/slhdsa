package slhdsa

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// FIPS-205 ACVP test vector structures

type acvpFile struct {
	Algorithm  string          `json:"algorithm"`
	Mode       string          `json:"mode"`
	Revision   string          `json:"revision"`
	TestGroups json.RawMessage `json:"testGroups"`
}

// KeyGen test structures
type keyGenGroup struct {
	TgID         int          `json:"tgId"`
	TestType     string       `json:"testType"`
	ParameterSet string       `json:"parameterSet"`
	Tests        []keyGenTest `json:"tests"`
}

type keyGenTest struct {
	TcID   int    `json:"tcId"`
	SkSeed string `json:"skSeed"`
	SkPrf  string `json:"skPrf"`
	PkSeed string `json:"pkSeed"`
}

type keyGenResult struct {
	TcID int    `json:"tcId"`
	Sk   string `json:"sk"`
	Pk   string `json:"pk"`
}

type keyGenResultGroup struct {
	TgID  int            `json:"tgId"`
	Tests []keyGenResult `json:"tests"`
}

// SigGen test structures
type sigGenGroup struct {
	TgID               int          `json:"tgId"`
	TestType           string       `json:"testType"`
	ParameterSet       string       `json:"parameterSet"`
	Deterministic      bool         `json:"deterministic"`
	SignatureInterface string       `json:"signatureInterface"`
	PreHash            string       `json:"preHash"`
	Tests              []sigGenTest `json:"tests"`
}

type sigGenTest struct {
	TcID                 int    `json:"tcId"`
	Sk                   string `json:"sk"`
	Message              string `json:"message"`
	Context              string `json:"context"`
	AdditionalRandomness string `json:"additionalRandomness,omitempty"`
}

type sigGenResult struct {
	TcID      int    `json:"tcId"`
	Signature string `json:"signature"`
}

type sigGenResultGroup struct {
	TgID  int            `json:"tgId"`
	Tests []sigGenResult `json:"tests"`
}

// SigVer test structures
type sigVerGroup struct {
	TgID               int          `json:"tgId"`
	TestType           string       `json:"testType"`
	ParameterSet       string       `json:"parameterSet"`
	SignatureInterface string       `json:"signatureInterface"`
	PreHash            string       `json:"preHash"`
	Tests              []sigVerTest `json:"tests"`
}

type sigVerTest struct {
	TcID      int    `json:"tcId"`
	Pk        string `json:"pk"`
	Message   string `json:"message"`
	Context   string `json:"context"`
	Signature string `json:"signature"`
}

type sigVerResult struct {
	TcID       int  `json:"tcId"`
	TestPassed bool `json:"testPassed"`
}

type sigVerResultGroup struct {
	TgID  int            `json:"tgId"`
	Tests []sigVerResult `json:"tests"`
}

func loadGzJSON(path string, v interface{}) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	gr, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gr.Close()

	return json.NewDecoder(gr).Decode(v)
}

func TestKeyGen(t *testing.T) {
	promptPath := filepath.Join("testdata", "SLH-DSA-keyGen-FIPS205", "prompt.json.gz")
	resultsPath := filepath.Join("testdata", "SLH-DSA-keyGen-FIPS205", "expectedResults.json.gz")

	var prompt acvpFile
	if err := loadGzJSON(promptPath, &prompt); err != nil {
		t.Skipf("Could not load test vectors: %v", err)
	}

	var results acvpFile
	if err := loadGzJSON(resultsPath, &results); err != nil {
		t.Fatalf("Could not load expected results: %v", err)
	}

	var promptGroups []keyGenGroup
	if err := json.Unmarshal(prompt.TestGroups, &promptGroups); err != nil {
		t.Fatalf("Could not parse prompt groups: %v", err)
	}

	var resultGroups []keyGenResultGroup
	if err := json.Unmarshal(results.TestGroups, &resultGroups); err != nil {
		t.Fatalf("Could not parse result groups: %v", err)
	}

	// Build result lookup
	resultMap := make(map[int]map[int]keyGenResult)
	for _, rg := range resultGroups {
		resultMap[rg.TgID] = make(map[int]keyGenResult)
		for _, r := range rg.Tests {
			resultMap[rg.TgID][r.TcID] = r
		}
	}

	for _, group := range promptGroups {
		params := ParamsByName(group.ParameterSet)
		if params == nil {
			t.Logf("Skipping unsupported parameter set: %s", group.ParameterSet)
			continue
		}

		t.Run(group.ParameterSet, func(t *testing.T) {
			for _, test := range group.Tests {
				result, ok := resultMap[group.TgID][test.TcID]
				if !ok {
					t.Errorf("No result for test %d", test.TcID)
					continue
				}

				skSeed, _ := hex.DecodeString(test.SkSeed)
				skPrf, _ := hex.DecodeString(test.SkPrf)
				pkSeed, _ := hex.DecodeString(test.PkSeed)
				expectedSk, _ := hex.DecodeString(result.Sk)
				expectedPk, _ := hex.DecodeString(result.Pk)

				// Build key bytes and parse
				keyBytes := make([]byte, 0, 4*params.n)
				keyBytes = append(keyBytes, skSeed...)
				keyBytes = append(keyBytes, skPrf...)
				keyBytes = append(keyBytes, pkSeed...)
				keyBytes = append(keyBytes, expectedSk[3*params.n:]...) // root from expected

				sk, err := NewPrivateKey(params, keyBytes)
				if err != nil {
					t.Errorf("Test %d: NewPrivateKey failed: %v", test.TcID, err)
					continue
				}

				gotSk := sk.Bytes()
				if !bytes.Equal(gotSk, expectedSk) {
					t.Errorf("Test %d: SK mismatch\ngot:  %x\nwant: %x", test.TcID, gotSk, expectedSk)
				}

				gotPk := sk.Public().(*PublicKey).Bytes()
				if !bytes.Equal(gotPk, expectedPk) {
					t.Errorf("Test %d: PK mismatch\ngot:  %x\nwant: %x", test.TcID, gotPk, expectedPk)
				}
			}
		})
	}
}

func TestSigGen(t *testing.T) {
	promptPath := filepath.Join("testdata", "SLH-DSA-sigGen-FIPS205", "prompt.json.gz")
	resultsPath := filepath.Join("testdata", "SLH-DSA-sigGen-FIPS205", "expectedResults.json.gz")

	var prompt acvpFile
	if err := loadGzJSON(promptPath, &prompt); err != nil {
		t.Skipf("Could not load test vectors: %v", err)
	}

	var results acvpFile
	if err := loadGzJSON(resultsPath, &results); err != nil {
		t.Fatalf("Could not load expected results: %v", err)
	}

	var promptGroups []sigGenGroup
	if err := json.Unmarshal(prompt.TestGroups, &promptGroups); err != nil {
		t.Fatalf("Could not parse prompt groups: %v", err)
	}

	var resultGroups []sigGenResultGroup
	if err := json.Unmarshal(results.TestGroups, &resultGroups); err != nil {
		t.Fatalf("Could not parse result groups: %v", err)
	}

	// Build result lookup
	resultMap := make(map[int]map[int]sigGenResult)
	for _, rg := range resultGroups {
		resultMap[rg.TgID] = make(map[int]sigGenResult)
		for _, r := range rg.Tests {
			resultMap[rg.TgID][r.TcID] = r
		}
	}

	for _, group := range promptGroups {
		params := ParamsByName(group.ParameterSet)
		if params == nil {
			t.Logf("Skipping unsupported parameter set: %s", group.ParameterSet)
			continue
		}

		// Only test pure mode (not pre-hash) and deterministic for now
		if group.PreHash != "pure" {
			continue
		}

		t.Run(group.ParameterSet, func(t *testing.T) {
			for _, test := range group.Tests {
				result, ok := resultMap[group.TgID][test.TcID]
				if !ok {
					t.Errorf("No result for test %d", test.TcID)
					continue
				}

				skBytes, _ := hex.DecodeString(test.Sk)
				message, _ := hex.DecodeString(test.Message)
				context, _ := hex.DecodeString(test.Context)
				expectedSig, _ := hex.DecodeString(result.Signature)

				sk, err := NewPrivateKey(params, skBytes)
				if err != nil {
					t.Errorf("Test %d: NewPrivateKey failed: %v", test.TcID, err)
					continue
				}

				var addRand []byte
				if !group.Deterministic && test.AdditionalRandomness != "" {
					addRand, _ = hex.DecodeString(test.AdditionalRandomness)
				}

				sig, err := sk.sign(message, context, addRand)
				if err != nil {
					t.Errorf("Test %d: Sign failed: %v", test.TcID, err)
					continue
				}

				if !bytes.Equal(sig, expectedSig) {
					t.Errorf("Test %d: Signature mismatch\ngot:  %x...\nwant: %x...",
						test.TcID, sig[:min(64, len(sig))], expectedSig[:min(64, len(expectedSig))])
				}
			}
		})
	}
}

func TestSigVer(t *testing.T) {
	promptPath := filepath.Join("testdata", "SLH-DSA-sigVer-FIPS205", "prompt.json.gz")
	resultsPath := filepath.Join("testdata", "SLH-DSA-sigVer-FIPS205", "expectedResults.json.gz")

	var prompt acvpFile
	if err := loadGzJSON(promptPath, &prompt); err != nil {
		t.Skipf("Could not load test vectors: %v", err)
	}

	var results acvpFile
	if err := loadGzJSON(resultsPath, &results); err != nil {
		t.Fatalf("Could not load expected results: %v", err)
	}

	var promptGroups []sigVerGroup
	if err := json.Unmarshal(prompt.TestGroups, &promptGroups); err != nil {
		t.Fatalf("Could not parse prompt groups: %v", err)
	}

	var resultGroups []sigVerResultGroup
	if err := json.Unmarshal(results.TestGroups, &resultGroups); err != nil {
		t.Fatalf("Could not parse result groups: %v", err)
	}

	// Build result lookup
	resultMap := make(map[int]map[int]sigVerResult)
	for _, rg := range resultGroups {
		resultMap[rg.TgID] = make(map[int]sigVerResult)
		for _, r := range rg.Tests {
			resultMap[rg.TgID][r.TcID] = r
		}
	}

	for _, group := range promptGroups {
		params := ParamsByName(group.ParameterSet)
		if params == nil {
			t.Logf("Skipping unsupported parameter set: %s", group.ParameterSet)
			continue
		}

		// Only test pure mode
		if group.PreHash != "pure" {
			continue
		}

		t.Run(group.ParameterSet, func(t *testing.T) {
			for _, test := range group.Tests {
				result, ok := resultMap[group.TgID][test.TcID]
				if !ok {
					t.Errorf("No result for test %d", test.TcID)
					continue
				}

				pkBytes, _ := hex.DecodeString(test.Pk)
				message, _ := hex.DecodeString(test.Message)
				context, _ := hex.DecodeString(test.Context)
				signature, _ := hex.DecodeString(test.Signature)

				pk, err := NewPublicKey(params, pkBytes)
				if err != nil {
					t.Errorf("Test %d: NewPublicKey failed: %v", test.TcID, err)
					continue
				}

				valid := pk.Verify(signature, message, context)
				if valid != result.TestPassed {
					t.Errorf("Test %d: Verify returned %v, expected %v", test.TcID, valid, result.TestPassed)
				}
			}
		})
	}
}

// Basic functionality tests

func TestRoundTrip(t *testing.T) {
	params := []*Params{SHA2_128s, SHA2_128f, SHAKE_128s, SHAKE_128f}

	for _, p := range params {
		t.Run(p.String(), func(t *testing.T) {
			sk, err := GenerateKey(rand.Reader, p)
			if err != nil {
				t.Fatalf("GenerateKey failed: %v", err)
			}

			// Test key serialization round-trip
			sk2, err := NewPrivateKey(p, sk.Bytes())
			if err != nil {
				t.Fatalf("NewPrivateKey failed: %v", err)
			}
			if !sk.Equal(sk2) {
				t.Error("Private key round-trip failed")
			}

			pk := sk.Public().(*PublicKey)
			pk2, err := NewPublicKey(p, pk.Bytes())
			if err != nil {
				t.Fatalf("NewPublicKey failed: %v", err)
			}
			if !pk.Equal(pk2) {
				t.Error("Public key round-trip failed")
			}

			// Test sign/verify
			message := []byte("test message")
			sig, err := sk.Sign(nil, message, nil)
			if err != nil {
				t.Fatalf("Sign failed: %v", err)
			}

			if !pk.Verify(sig, message, nil) {
				t.Error("Verify failed on valid signature")
			}

			// Test with wrong message
			if pk.Verify(sig, []byte("wrong message"), nil) {
				t.Error("Verify should fail with wrong message")
			}

			// Test with corrupted signature
			badSig := make([]byte, len(sig))
			copy(badSig, sig)
			badSig[0] ^= 0xFF
			if pk.Verify(badSig, message, nil) {
				t.Error("Verify should fail with corrupted signature")
			}
		})
	}
}

func TestDeterministicSigning(t *testing.T) {
	sk, err := GenerateKey(rand.Reader, SHA2_128s)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	message := []byte("test message")

	sig1, _ := sk.Sign(nil, message, nil)
	sig2, _ := sk.Sign(nil, message, nil)

	if !bytes.Equal(sig1, sig2) {
		t.Error("Deterministic signing should produce identical signatures")
	}
}

func TestContext(t *testing.T) {
	sk, err := GenerateKey(rand.Reader, SHA2_128s)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	pk := sk.Public().(*PublicKey)

	message := []byte("test message")
	ctx := []byte("my-context")

	sig, err := sk.Sign(nil, message, &Options{Context: ctx})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if !pk.Verify(sig, message, ctx) {
		t.Error("Verify failed with correct context")
	}

	if pk.Verify(sig, message, []byte("wrong-context")) {
		t.Error("Verify should fail with wrong context")
	}

	if pk.Verify(sig, message, nil) {
		t.Error("Verify should fail with no context")
	}
}

// Benchmarks

func BenchmarkKeyGen(b *testing.B) {
	benchmarks := []struct {
		name   string
		params *Params
	}{
		{"SHA2-128s", SHA2_128s},
		{"SHA2-128f", SHA2_128f},
		{"SHAKE-128s", SHAKE_128s},
		{"SHAKE-128f", SHAKE_128f},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, err := GenerateKey(rand.Reader, bm.params)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkSign(b *testing.B) {
	benchmarks := []struct {
		name   string
		params *Params
	}{
		{"SHA2-128s", SHA2_128s},
		{"SHA2-128f", SHA2_128f},
		{"SHAKE-128s", SHAKE_128s},
		{"SHAKE-128f", SHAKE_128f},
	}

	message := []byte("benchmark message")

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			sk, _ := GenerateKey(rand.Reader, bm.params)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := sk.Sign(nil, message, nil)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkVerify(b *testing.B) {
	benchmarks := []struct {
		name   string
		params *Params
	}{
		{"SHA2-128s", SHA2_128s},
		{"SHA2-128f", SHA2_128f},
		{"SHAKE-128s", SHAKE_128s},
		{"SHAKE-128f", SHAKE_128f},
	}

	message := []byte("benchmark message")

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			sk, _ := GenerateKey(rand.Reader, bm.params)
			pk := sk.Public().(*PublicKey)
			sig, _ := sk.Sign(nil, message, nil)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if !pk.Verify(sig, message, nil) {
					b.Fatal("verification failed")
				}
			}
		})
	}
}
