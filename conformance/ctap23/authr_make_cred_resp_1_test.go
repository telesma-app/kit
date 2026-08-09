package ctap23

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"slices"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	secp256k1ecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
	"github.com/telesma-app/ctap/attestation"
	"github.com/telesma-app/ctap/client"
	"github.com/telesma-app/ctap/cose"
	"github.com/telesma-app/ctap/credential"
	ctapcrypto "github.com/telesma-app/ctap/crypto"
	"github.com/telesma-app/ctap/extension"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	registry "github.com/telesma-app/fido-registry"
	"github.com/telesma-app/kit/conformance"
)

var authrMakeCredResp1TestAAGUID = uuid.MustParse("c4b67e31-15d8-4c79-bca7-288193fc9432")

var authrMakeCredResp1ProfileAlgorithms = []string{
	"secp256r1_ecdsa_sha256_raw",
	"rsassa_pss_sha256_raw",
	"secp256k1_ecdsa_sha256_raw",
	"rsassa_pss_sha384_raw",
	"rsassa_pss_sha512_raw",
	"rsassa_pkcsv15_sha256_raw",
	"rsassa_pkcsv15_sha384_raw",
	"rsassa_pkcsv15_sha512_raw",
	"rsassa_pkcsv15_sha1_raw",
	"secp384r1_ecdsa_sha384_raw",
	"secp521r1_ecdsa_sha512_raw",
	"ed25519_eddsa_sha512_raw",
	"ed448_eddsa_sha512_raw",
}

func TestAuthrMakeCredResp1Definitions(t *testing.T) {
	want := []struct {
		id     conformance.TestID
		marker string
	}{
		{TestIDAuthrMakeCredResp1P01, "P-01"},
		{TestIDAuthrMakeCredResp1P02, "P-02"},
		{TestIDAuthrMakeCredResp1P03, "P-03"},
		{TestIDAuthrMakeCredResp1P04, "P-04"},
		{TestIDAuthrMakeCredResp1P06, "P-06"},
		{TestIDAuthrMakeCredResp1F01, "F-01"},
	}
	tests := authrMakeCredResp1Tests(Config{})
	if len(tests) != len(want) {
		t.Fatalf("tests = %d, want %d", len(tests), len(want))
	}
	for index, test := range tests {
		if test.ID != want[index].id || test.Source.Path != authrMakeCredResp1SourcePath ||
			test.Source.Case != want[index].marker || !test.Destructive || len(test.References) < 2 {
			t.Fatalf("test %d = %#v", index, test)
		}
	}
	if got := authrMakeCredResp1MetadataReference().URL; got != metadataStatementURL+"#metadata-statement" {
		t.Fatalf("metadata reference URL = %q", got)
	}
}

func TestAuthrMakeCredResp1SelfAttestationMatrix(t *testing.T) {
	for _, algorithm := range authrMakeCredResp1ProfileAlgorithms {
		t.Run(algorithm, func(t *testing.T) {
			material := newAuthrMakeCredResp1Key(t, algorithm)
			device := newAuthrMakeCredResp1Device(t, []authrMakeCredResp1Key{material}, false)
			config, lifecycle := authrMakeCredResp1Config(t, device, []authrMakeCredResp1Key{material}, "basic_surrogate")
			for _, id := range []conformance.TestID{
				TestIDAuthrMakeCredResp1P01,
				TestIDAuthrMakeCredResp1P02,
				TestIDAuthrMakeCredResp1P03,
				TestIDAuthrMakeCredResp1P06,
				TestIDAuthrMakeCredResp1F01,
			} {
				result := runAuthrMakeCredResp1Test(t, device, config, id)
				assertAuthrMakeCredResp1Status(t, result, conformance.StatusPassed)
			}
			result := runAuthrMakeCredResp1Test(t, device, config, TestIDAuthrMakeCredResp1P04)
			assertAuthrMakeCredResp1Status(t, result, conformance.StatusSkipped)
			lifecycle.assert(t, 6)
		})
	}
}

func TestAuthrMakeCredResp1BasicAttestationMatrix(t *testing.T) {
	for _, algorithm := range []string{
		"secp256r1_ecdsa_sha256_raw",
		"rsassa_pkcsv15_sha256_raw",
		"ed25519_eddsa_sha512_raw",
	} {
		t.Run(algorithm, func(t *testing.T) {
			material := newAuthrMakeCredResp1Key(t, algorithm)
			device := newAuthrMakeCredResp1Device(t, []authrMakeCredResp1Key{material}, true)
			config, lifecycle := authrMakeCredResp1Config(t, device, []authrMakeCredResp1Key{material}, "basic_full")
			for _, id := range []conformance.TestID{
				TestIDAuthrMakeCredResp1P03,
				TestIDAuthrMakeCredResp1P04,
			} {
				result := runAuthrMakeCredResp1Test(t, device, config, id)
				assertAuthrMakeCredResp1Status(t, result, conformance.StatusPassed)
			}
			result := runAuthrMakeCredResp1Test(t, device, config, TestIDAuthrMakeCredResp1P06)
			assertAuthrMakeCredResp1Status(t, result, conformance.StatusSkipped)
			lifecycle.assert(t, 3)
		})
	}
}

func TestAuthrMakeCredResp1ExpandedSelfCryptoRejectsCorruptAndMismatchedStatements(t *testing.T) {
	for _, algorithm := range []string{
		"secp256k1_ecdsa_sha256_raw",
		"ed448_eddsa_sha512_raw",
		"rsassa_pkcsv15_sha1_raw",
	} {
		for _, mutation := range []struct {
			name   string
			mutate func(map[uint64]any)
		}{
			{
				name: "corrupt signature",
				mutate: func(fields map[uint64]any) {
					fields[3].(map[string]any)["sig"] = []byte{0x01}
				},
			},
			{
				name: "algorithm mismatch",
				mutate: func(fields map[uint64]any) {
					fields[3].(map[string]any)["alg"] = int64(cose.AlgorithmES256)
				},
			},
		} {
			t.Run(algorithm+"/"+mutation.name, func(t *testing.T) {
				material := newAuthrMakeCredResp1Key(t, algorithm)
				device := newAuthrMakeCredResp1Device(t, []authrMakeCredResp1Key{material}, false)
				device.mutate = mutation.mutate
				config, _ := authrMakeCredResp1Config(
					t,
					device,
					[]authrMakeCredResp1Key{material},
					"basic_surrogate",
				)

				result := runAuthrMakeCredResp1Test(t, device, config, TestIDAuthrMakeCredResp1P06)

				assertAuthrMakeCredResp1Status(t, result, conformance.StatusFailed)
			})
		}
	}
}

func TestAuthrMakeCredResp1P02ValidatesEveryMetadataProfile(t *testing.T) {
	algorithms := authrMakeCredResp1ProfileAlgorithms
	materials := make([]authrMakeCredResp1Key, 0, len(algorithms))
	for _, algorithm := range algorithms {
		materials = append(materials, newAuthrMakeCredResp1Key(t, algorithm))
	}
	device := newAuthrMakeCredResp1Device(t, materials, false)
	config, lifecycle := authrMakeCredResp1Config(t, device, materials, "basic_surrogate")

	result := runAuthrMakeCredResp1Test(t, device, config, TestIDAuthrMakeCredResp1P02)

	assertAuthrMakeCredResp1Status(t, result, conformance.StatusPassed)
	if len(device.makeCredentialRequests) != len(materials) {
		t.Fatalf("MakeCredential requests = %d, want %d", len(device.makeCredentialRequests), len(materials))
	}
	for index, request := range device.makeCredentialRequests {
		wantAlgorithm := cose.Algorithm(materials[index].profile.Algorithm)
		if !slices.Equal(request.AttestationFormatsPreference, []attestation.AttestationStatementFormatIdentifier{
			attestation.AttestationStatementFormatIdentifierPacked,
		}) || len(request.PubKeyCredParams) != 1 ||
			request.PubKeyCredParams[0].Algorithm != wantAlgorithm {
			t.Fatalf("request %d = %#v, want packed/%d", index, request, wantAlgorithm)
		}
		token := bytes.Repeat([]byte{byte(index + 1)}, 32)
		wantAuthParam := ctapcrypto.Authenticate(
			protocol.PinUvAuthProtocolTwo,
			token,
			request.ClientDataHash,
		)
		if request.PinUvAuthProtocol != protocol.PinUvAuthProtocolTwo ||
			!bytes.Equal(request.PinUvAuthParam, wantAuthParam) {
			t.Fatalf("request %d authorization = %d/%x", index, request.PinUvAuthProtocol, request.PinUvAuthParam)
		}
	}
	if len(lifecycle.tokens) != len(materials) {
		t.Fatalf("tokens = %d, want %d", len(lifecycle.tokens), len(materials))
	}
	if countGetAssertionFixtureSteps(result.Tests[0].Steps, "make-credential-fixture.cleanup") != 1 {
		t.Fatalf("cleanup steps = %#v", result.Tests[0].Steps)
	}
	lifecycle.assert(t, 1)
}

func TestAuthrMakeCredResp1FormatAdjudication(t *testing.T) {
	material := newAuthrMakeCredResp1Key(t, "secp256r1_ecdsa_sha256_raw")
	for _, testCase := range []struct {
		name       string
		advertised bool
		want       conformance.Status
	}{
		{name: "advertised packed is binding", advertised: true, want: conformance.StatusFailed},
		{name: "packed-only evidence is unavailable", advertised: false, want: conformance.StatusSkipped},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			device := newAuthrMakeCredResp1Device(t, []authrMakeCredResp1Key{material}, false)
			device.format = attestation.AttestationStatementFormatIdentifierNone
			if !testCase.advertised {
				device.info.AttestationFormats = nil
			}
			config, _ := authrMakeCredResp1Config(t, device, []authrMakeCredResp1Key{material}, "basic_surrogate")

			result := runAuthrMakeCredResp1Test(t, device, config, TestIDAuthrMakeCredResp1P01)

			assertAuthrMakeCredResp1Status(t, result, testCase.want)
		})
	}
}

func TestAuthrMakeCredResp1WireAndAttestationFailures(t *testing.T) {
	material := newAuthrMakeCredResp1Key(t, "secp256r1_ecdsa_sha256_raw")
	for _, testCase := range []struct {
		name   string
		id     conformance.TestID
		mutate func(map[uint64]any)
	}{
		{
			name: "P02 wrong RP ID hash",
			id:   TestIDAuthrMakeCredResp1P02,
			mutate: func(fields map[uint64]any) {
				authData := slices.Clone(fields[2].([]byte))
				authData[0] ^= 0xff
				fields[2] = authData
			},
		},
		{
			name: "P02 wrong AAGUID",
			id:   TestIDAuthrMakeCredResp1P02,
			mutate: func(fields map[uint64]any) {
				authData := slices.Clone(fields[2].([]byte))
				authData[37] ^= 0xff
				fields[2] = authData
			},
		},
		{
			name: "P02 ED flag",
			id:   TestIDAuthrMakeCredResp1P02,
			mutate: func(fields map[uint64]any) {
				authData := slices.Clone(fields[2].([]byte))
				authData[32] |= byte(protocol.AuthDataFlagExtensionDataIncluded)
				authData = append(authData, 0xa0)
				fields[2] = authData
			},
		},
		{
			name: "P02 missing UP flag",
			id:   TestIDAuthrMakeCredResp1P02,
			mutate: func(fields map[uint64]any) {
				authData := slices.Clone(fields[2].([]byte))
				authData[32] &^= byte(protocol.AuthDataFlagUserPresent)
				fields[2] = authData
			},
		},
		{
			name: "P02 oversized credential ID",
			id:   TestIDAuthrMakeCredResp1P02,
			mutate: func(fields map[uint64]any) {
				fields[2] = authrMakeCredResp1ReplaceCredentialID(
					fields[2].([]byte),
					bytes.Repeat([]byte{0x11}, 1024),
				)
			},
		},
		{
			name: "P02 noncanonical credential key",
			id:   TestIDAuthrMakeCredResp1P02,
			mutate: func(fields map[uint64]any) {
				authData := slices.Clone(fields[2].([]byte))
				keyOffset := 55 + (int(authData[53])<<8 | int(authData[54]))
				if !bytes.Equal(authData[keyOffset:keyOffset+5], []byte{0xa5, 0x01, 0x02, 0x03, 0x26}) {
					t.Fatalf("unexpected canonical key prefix %x", authData[keyOffset:keyOffset+5])
				}
				copy(authData[keyOffset:keyOffset+5], []byte{0xa5, 0x03, 0x26, 0x01, 0x02})
				fields[2] = authData
			},
		},
		{
			name: "P03 missing alg",
			id:   TestIDAuthrMakeCredResp1P03,
			mutate: func(fields map[uint64]any) {
				statement := fields[3].(map[string]any)
				delete(statement, "alg")
			},
		},
		{
			name: "P03 empty signature",
			id:   TestIDAuthrMakeCredResp1P03,
			mutate: func(fields map[uint64]any) {
				fields[3].(map[string]any)["sig"] = []byte{}
			},
		},
		{
			name: "P03 extra field",
			id:   TestIDAuthrMakeCredResp1P03,
			mutate: func(fields map[uint64]any) {
				fields[3].(map[string]any)["ecdaaKeyId"] = []byte{1}
			},
		},
		{
			name: "P03 missing attStmt",
			id:   TestIDAuthrMakeCredResp1P03,
			mutate: func(fields map[uint64]any) {
				delete(fields, 3)
			},
		},
		{
			name: "P06 invalid signature",
			id:   TestIDAuthrMakeCredResp1P06,
			mutate: func(fields map[uint64]any) {
				fields[3].(map[string]any)["sig"] = []byte{1}
			},
		},
		{
			name: "F01 present empty extensions",
			id:   TestIDAuthrMakeCredResp1F01,
			mutate: func(fields map[uint64]any) {
				fields[6] = map[string]any{}
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			device := newAuthrMakeCredResp1Device(t, []authrMakeCredResp1Key{material}, false)
			device.mutate = testCase.mutate
			config, _ := authrMakeCredResp1Config(t, device, []authrMakeCredResp1Key{material}, "basic_surrogate")

			result := runAuthrMakeCredResp1Test(t, device, config, testCase.id)

			assertAuthrMakeCredResp1Status(t, result, conformance.StatusFailed)
		})
	}
}

func TestAuthrMakeCredResp1CredentialIDMaximumIsAccepted(t *testing.T) {
	material := newAuthrMakeCredResp1Key(t, "secp256r1_ecdsa_sha256_raw")
	device := newAuthrMakeCredResp1Device(t, []authrMakeCredResp1Key{material}, false)
	device.mutate = func(fields map[uint64]any) {
		fields[2] = authrMakeCredResp1ReplaceCredentialID(
			fields[2].([]byte),
			bytes.Repeat([]byte{0x11}, 1023),
		)
	}
	config, _ := authrMakeCredResp1Config(t, device, []authrMakeCredResp1Key{material}, "basic_surrogate")

	result := runAuthrMakeCredResp1Test(t, device, config, TestIDAuthrMakeCredResp1P02)

	assertAuthrMakeCredResp1Status(t, result, conformance.StatusPassed)
}

func TestAuthrMakeCredResp1P03AllowsDifferentBasicAttestationAlgorithm(t *testing.T) {
	material := newAuthrMakeCredResp1Key(t, "secp256r1_ecdsa_sha256_raw")
	device := newAuthrMakeCredResp1Device(t, []authrMakeCredResp1Key{material}, true)
	device.mutate = func(fields map[uint64]any) {
		fields[3].(map[string]any)["alg"] = int64(cose.AlgorithmES384)
	}
	config, _ := authrMakeCredResp1Config(t, device, []authrMakeCredResp1Key{material}, "basic_full")

	result := runAuthrMakeCredResp1Test(t, device, config, TestIDAuthrMakeCredResp1P03)

	assertAuthrMakeCredResp1Status(t, result, conformance.StatusPassed)
}

func TestAuthrMakeCredResp1P02RejectsCredentialKeyWireViolations(t *testing.T) {
	material := newAuthrMakeCredResp1Key(t, "secp256r1_ecdsa_sha256_raw")
	for _, testCase := range []struct {
		name   string
		mutate func(cose.Key)
	}{
		{name: "missing label", mutate: func(key cose.Key) { delete(key, cose.EC2KeyParameterY) }},
		{name: "extra label", mutate: func(key cose.Key) { key[99] = int64(1) }},
		{name: "wrong key type", mutate: func(key cose.Key) { key[cose.KeyParameterKty] = cose.KeyTypeRSA }},
		{name: "wrong coordinate type", mutate: func(key cose.Key) { key[cose.EC2KeyParameterX] = "x" }},
		{name: "wrong coordinate size", mutate: func(key cose.Key) { key[cose.EC2KeyParameterX] = []byte{1} }},
		{name: "wrong algorithm", mutate: func(key cose.Key) { key[cose.KeyParameterAlg] = cose.AlgorithmES384 }},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			device := newAuthrMakeCredResp1Device(t, []authrMakeCredResp1Key{material}, false)
			device.keyMutate = testCase.mutate
			config, _ := authrMakeCredResp1Config(t, device, []authrMakeCredResp1Key{material}, "basic_surrogate")

			result := runAuthrMakeCredResp1Test(t, device, config, TestIDAuthrMakeCredResp1P02)

			assertAuthrMakeCredResp1Status(t, result, conformance.StatusFailed)
		})
	}
}

func TestAuthrMakeCredResp1ConditionalX5CAdjudication(t *testing.T) {
	material := newAuthrMakeCredResp1Key(t, "secp256r1_ecdsa_sha256_raw")
	for _, testCase := range []struct {
		name string
		id   conformance.TestID
		x5c  any
		want conformance.Status
	}{
		{name: "P04 absent", id: TestIDAuthrMakeCredResp1P04, want: conformance.StatusSkipped},
		{name: "P04 empty", id: TestIDAuthrMakeCredResp1P04, x5c: []any{}, want: conformance.StatusFailed},
		{name: "P04 non-byte certificate", id: TestIDAuthrMakeCredResp1P04, x5c: []any{"certificate"}, want: conformance.StatusFailed},
		{name: "P06 absent", id: TestIDAuthrMakeCredResp1P06, want: conformance.StatusPassed},
		{name: "P06 empty", id: TestIDAuthrMakeCredResp1P06, x5c: []any{}, want: conformance.StatusFailed},
		{name: "P06 nonempty", id: TestIDAuthrMakeCredResp1P06, x5c: []any{[]byte{1}}, want: conformance.StatusSkipped},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			device := newAuthrMakeCredResp1Device(t, []authrMakeCredResp1Key{material}, false)
			if testCase.x5c != nil {
				device.mutate = func(fields map[uint64]any) {
					fields[3].(map[string]any)["x5c"] = testCase.x5c
				}
			}
			config, _ := authrMakeCredResp1Config(t, device, []authrMakeCredResp1Key{material}, "basic_surrogate")

			result := runAuthrMakeCredResp1Test(t, device, config, testCase.id)

			assertAuthrMakeCredResp1Status(t, result, testCase.want)
		})
	}
}

func TestAuthrMakeCredResp1P04Failures(t *testing.T) {
	material := newAuthrMakeCredResp1Key(t, "secp256r1_ecdsa_sha256_raw")
	for _, testCase := range []struct {
		name            string
		mutate          func(map[uint64]any)
		attestationType string
		wrongRoot       bool
	}{
		{
			name: "invalid signature",
			mutate: func(fields map[uint64]any) {
				fields[3].(map[string]any)["sig"] = []byte{0x01}
			},
			attestationType: "basic_full",
		},
		{
			name: "invalid certificate encoding",
			mutate: func(fields map[uint64]any) {
				fields[3].(map[string]any)["x5c"] = []any{[]byte{0x01}}
			},
			attestationType: "basic_full",
		},
		{name: "wrong metadata attestation type", attestationType: "basic_surrogate"},
		{name: "attCA metadata is not basic full", attestationType: "attca"},
		{name: "chain does not reach metadata root", attestationType: "basic_full", wrongRoot: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			device := newAuthrMakeCredResp1Device(t, []authrMakeCredResp1Key{material}, true)
			device.mutate = testCase.mutate
			config, _ := authrMakeCredResp1Config(
				t,
				device,
				[]authrMakeCredResp1Key{material},
				testCase.attestationType,
			)
			if testCase.wrongRoot {
				wrongRoot, _ := newAuthrMakeCredResp1Root(t)
				var statement map[string]any
				if err := json.Unmarshal([]byte(config.Metadata.StatementJSON), &statement); err != nil {
					t.Fatal(err)
				}
				statement["attestationRootCertificates"] = []string{
					base64.StdEncoding.EncodeToString(wrongRoot.Raw),
				}
				encoded, err := json.Marshal(statement)
				if err != nil {
					t.Fatal(err)
				}
				config.Metadata.StatementJSON = string(encoded)
			}

			result := runAuthrMakeCredResp1Test(t, device, config, TestIDAuthrMakeCredResp1P04)

			assertAuthrMakeCredResp1Status(t, result, conformance.StatusFailed)
		})
	}
}

func TestAuthrMakeCredResp1P06RequiresSurrogateMetadata(t *testing.T) {
	material := newAuthrMakeCredResp1Key(t, "secp256r1_ecdsa_sha256_raw")
	device := newAuthrMakeCredResp1Device(t, []authrMakeCredResp1Key{material}, false)
	config, _ := authrMakeCredResp1Config(t, device, []authrMakeCredResp1Key{material}, "basic_full")

	result := runAuthrMakeCredResp1Test(t, device, config, TestIDAuthrMakeCredResp1P06)

	assertAuthrMakeCredResp1Status(t, result, conformance.StatusFailed)
}

func TestAuthrMakeCredResp1P06RequiresExplicitEmptyAttestationRoots(t *testing.T) {
	material := newAuthrMakeCredResp1Key(t, "secp256r1_ecdsa_sha256_raw")
	for _, testCase := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{
			name: "missing",
			mutate: func(statement map[string]any) {
				delete(statement, "attestationRootCertificates")
			},
		},
		{
			name: "wrong type",
			mutate: func(statement map[string]any) {
				statement["attestationRootCertificates"] = "not-an-array"
			},
		},
		{
			name: "nonempty",
			mutate: func(statement map[string]any) {
				statement["attestationRootCertificates"] = []string{"unexpected-root"}
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			device := newAuthrMakeCredResp1Device(t, []authrMakeCredResp1Key{material}, false)
			config, _ := authrMakeCredResp1Config(
				t,
				device,
				[]authrMakeCredResp1Key{material},
				"basic_surrogate",
			)
			var statement map[string]any
			if err := json.Unmarshal([]byte(config.Metadata.StatementJSON), &statement); err != nil {
				t.Fatal(err)
			}
			testCase.mutate(statement)
			encoded, err := json.Marshal(statement)
			if err != nil {
				t.Fatal(err)
			}
			config.Metadata.StatementJSON = string(encoded)

			result := runAuthrMakeCredResp1Test(t, device, config, TestIDAuthrMakeCredResp1P06)

			assertAuthrMakeCredResp1Status(t, result, conformance.StatusFailed)
		})
	}
}

func TestAuthrMakeCredResp1P06AllowsMixedBasicFullAndSurrogateWithRoots(t *testing.T) {
	material := newAuthrMakeCredResp1Key(t, "secp256r1_ecdsa_sha256_raw")
	device := newAuthrMakeCredResp1Device(t, []authrMakeCredResp1Key{material}, false)
	config, _ := authrMakeCredResp1Config(
		t,
		device,
		[]authrMakeCredResp1Key{material},
		"basic_surrogate",
	)
	root, _ := newAuthrMakeCredResp1Root(t)
	var statement map[string]any
	if err := json.Unmarshal([]byte(config.Metadata.StatementJSON), &statement); err != nil {
		t.Fatal(err)
	}
	statement["attestationTypes"] = []string{"basic_full", "basic_surrogate"}
	statement["attestationRootCertificates"] = []string{
		base64.StdEncoding.EncodeToString(root.Raw),
	}
	encoded, err := json.Marshal(statement)
	if err != nil {
		t.Fatal(err)
	}
	config.Metadata.StatementJSON = string(encoded)

	result := runAuthrMakeCredResp1Test(t, device, config, TestIDAuthrMakeCredResp1P06)

	assertAuthrMakeCredResp1Status(t, result, conformance.StatusPassed)
}

func TestValidateMakeCredResp1LeafCertificate(t *testing.T) {
	material := newAuthrMakeCredResp1Key(t, "secp256r1_ecdsa_sha256_raw")
	root, rootKey := newAuthrMakeCredResp1Root(t)
	valid := func() *x509.Certificate {
		return newAuthrMakeCredResp1Leaf(
			t,
			root,
			rootKey,
			material.privateKey.Public(),
			authrMakeCredResp1TestAAGUID,
		)
	}
	now := time.Now()
	if err := validateMakeCredResp1LeafCertificate(valid(), authrMakeCredResp1TestAAGUID, now); err != nil {
		t.Fatal(err)
	}

	withoutAAGUID := valid()
	withoutAAGUID.Extensions = slices.DeleteFunc(withoutAAGUID.Extensions, func(extension pkix.Extension) bool {
		return extension.Id.Equal(oidFIDOAAGUID)
	})
	if err := validateMakeCredResp1LeafCertificate(withoutAAGUID, authrMakeCredResp1TestAAGUID, now); err != nil {
		t.Fatalf("optional AAGUID extension: %v", err)
	}

	for _, testCase := range []struct {
		name   string
		mutate func(*x509.Certificate)
	}{
		{name: "version", mutate: func(certificate *x509.Certificate) { certificate.Version = 2 }},
		{name: "basicConstraints absent", mutate: func(certificate *x509.Certificate) { certificate.BasicConstraintsValid = false }},
		{name: "CA true", mutate: func(certificate *x509.Certificate) { certificate.IsCA = true }},
		{name: "not yet valid", mutate: func(certificate *x509.Certificate) { certificate.NotBefore = now.Add(time.Hour) }},
		{name: "expired", mutate: func(certificate *x509.Certificate) { certificate.NotAfter = now.Add(-time.Hour) }},
		{
			name: "wrong subject string type",
			mutate: func(certificate *x509.Certificate) {
				certificate.RawSubject = authrMakeCredResp1Subject(t, asn1.TagPrintableString, "US", "Authenticator Attestation")
			},
		},
		{
			name: "country",
			mutate: func(certificate *x509.Certificate) {
				certificate.RawSubject = authrMakeCredResp1Subject(t, asn1.TagUTF8String, "USA", "Authenticator Attestation")
			},
		},
		{
			name: "unknown country ZZ",
			mutate: func(certificate *x509.Certificate) {
				certificate.RawSubject = authrMakeCredResp1Subject(t, asn1.TagUTF8String, "ZZ", "Authenticator Attestation")
			},
		},
		{
			name: "private country XK",
			mutate: func(certificate *x509.Certificate) {
				certificate.RawSubject = authrMakeCredResp1Subject(t, asn1.TagUTF8String, "XK", "Authenticator Attestation")
			},
		},
		{
			name: "organizational unit",
			mutate: func(certificate *x509.Certificate) {
				certificate.RawSubject = authrMakeCredResp1Subject(t, asn1.TagUTF8String, "US", "Wrong")
			},
		},
		{
			name: "critical AAGUID",
			mutate: func(certificate *x509.Certificate) {
				for index := range certificate.Extensions {
					if certificate.Extensions[index].Id.Equal(oidFIDOAAGUID) {
						certificate.Extensions[index].Critical = true
					}
				}
			},
		},
		{
			name: "mismatched AAGUID",
			mutate: func(certificate *x509.Certificate) {
				encoded, err := asn1.Marshal(uuid.Nil[:])
				if err != nil {
					t.Fatal(err)
				}
				for index := range certificate.Extensions {
					if certificate.Extensions[index].Id.Equal(oidFIDOAAGUID) {
						certificate.Extensions[index].Value = encoded
					}
				}
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			certificate := valid()
			testCase.mutate(certificate)
			if err := validateMakeCredResp1LeafCertificate(certificate, authrMakeCredResp1TestAAGUID, now); err == nil {
				t.Fatal("validation passed")
			}
		})
	}
}

func TestAuthrMakeCredResp1StatusTransportAndCleanupFailures(t *testing.T) {
	material := newAuthrMakeCredResp1Key(t, "secp256r1_ecdsa_sha256_raw")
	for _, testCase := range []struct {
		name      string
		status    ctaptransport.StatusCode
		err       error
		cleanup   error
		want      conformance.Status
		wantToken bool
	}{
		{name: "CTAP status", status: ctaptransport.CTAP2_ERR_INVALID_CBOR, want: conformance.StatusFailed, wantToken: true},
		{name: "transport", err: errors.New("device disconnected"), want: conformance.StatusError, wantToken: true},
		{name: "cleanup", cleanup: errors.New("cleanup failed"), want: conformance.StatusError, wantToken: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			device := newAuthrMakeCredResp1Device(t, []authrMakeCredResp1Key{material}, false)
			device.makeCredentialStatus = testCase.status
			device.makeCredentialError = testCase.err
			config, lifecycle := authrMakeCredResp1Config(t, device, []authrMakeCredResp1Key{material}, "basic_surrogate")
			lifecycle.cleanupFailure = testCase.cleanup

			result := runAuthrMakeCredResp1Test(t, device, config, TestIDAuthrMakeCredResp1P02)

			assertAuthrMakeCredResp1Status(t, result, testCase.want)
			for _, token := range lifecycle.tokens {
				assertMakeCredentialFixtureZeroed(t, token)
			}
		})
	}
}

func TestAuthrMakeCredResp1MalformedAndNoncanonicalResponsesFail(t *testing.T) {
	material := newAuthrMakeCredResp1Key(t, "secp256r1_ecdsa_sha256_raw")
	for _, testCase := range []struct {
		name   string
		encode func(testing.TB, map[uint64]any) []byte
	}{
		{
			name: "malformed",
			encode: func(testing.TB, map[uint64]any) []byte {
				return []byte{0xff}
			},
		},
		{
			name: "noncanonical outer map",
			encode: func(t testing.TB, fields map[uint64]any) []byte {
				encoded := []byte{0xa3, 0x03}
				encoded = append(encoded, marshalMakeCredentialFixture(t, fields[3])...)
				encoded = append(encoded, 0x01)
				encoded = append(encoded, marshalMakeCredentialFixture(t, fields[1])...)
				encoded = append(encoded, 0x02)
				encoded = append(encoded, marshalMakeCredentialFixture(t, fields[2])...)

				return encoded
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			device := newAuthrMakeCredResp1Device(t, []authrMakeCredResp1Key{material}, false)
			device.encodeResponse = func(fields map[uint64]any) []byte {
				return testCase.encode(t, fields)
			}
			config, _ := authrMakeCredResp1Config(t, device, []authrMakeCredResp1Key{material}, "basic_surrogate")

			result := runAuthrMakeCredResp1Test(t, device, config, TestIDAuthrMakeCredResp1P02)

			assertAuthrMakeCredResp1Status(t, result, conformance.StatusFailed)
		})
	}
}

func TestAuthrMakeCredResp1ProviderErrorWipesReturnedToken(t *testing.T) {
	providerFailure := errors.New("PIN entry canceled")
	secret := bytes.Repeat([]byte{0x71}, 32)
	material := newAuthrMakeCredResp1Key(t, "secp256r1_ecdsa_sha256_raw")
	device := newAuthrMakeCredResp1Device(t, []authrMakeCredResp1Key{material}, false)
	config, _ := authrMakeCredResp1Config(t, device, []authrMakeCredResp1Key{material}, "basic_surrogate")
	config.TokenProvider = func(
		context.Context,
		*client.Client,
		PinUvAuthTokenRequest,
	) (PinUvAuthToken, error) {
		return PinUvAuthToken{Protocol: protocol.PinUvAuthProtocolTwo, Value: secret}, providerFailure
	}

	result := runAuthrMakeCredResp1Test(t, device, config, TestIDAuthrMakeCredResp1P02)

	assertAuthrMakeCredResp1Status(t, result, conformance.StatusError)
	assertMakeCredentialFixtureZeroed(t, secret)
	if len(device.makeCredentialRequests) != 0 {
		t.Fatal("MakeCredential ran after token provider failure")
	}
}

type authrMakeCredResp1Key struct {
	name        string
	profile     registry.COSEAuthenticationProfile
	key         cose.Key
	privateKey  crypto.Signer
	signMessage func([]byte) ([]byte, error)
}

func newAuthrMakeCredResp1Key(t testing.TB, name string) authrMakeCredResp1Key {
	t.Helper()
	algorithm, ok := registry.ParseAuthenticationAlgorithm(name)
	if !ok {
		t.Fatalf("unknown algorithm %q", name)
	}
	profile, ok := algorithm.COSEProfile()
	if !ok {
		t.Fatalf("algorithm %q has no profile", name)
	}
	material := authrMakeCredResp1Key{name: name, profile: profile}
	switch {
	case profile.KeyType == cose.KeyTypeEC2 && profile.Curve != cose.EllipticCurveSecp256k1:
		var curve elliptic.Curve
		switch profile.Curve {
		case cose.EllipticCurveP256:
			curve = elliptic.P256()
		case cose.EllipticCurveP384:
			curve = elliptic.P384()
		case cose.EllipticCurveP521:
			curve = elliptic.P521()
		default:
			t.Fatalf("unsupported EC2 curve %d", profile.Curve)
		}
		privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		material.privateKey = privateKey
		material.signMessage = func(message []byte) ([]byte, error) {
			digest := authrMakeCredResp1Digest(cose.Algorithm(profile.Algorithm), message)

			return ecdsa.SignASN1(rand.Reader, privateKey, digest)
		}
		material.key = cose.Key{
			cose.KeyParameterKty:    cose.KeyTypeEC2,
			cose.KeyParameterAlg:    cose.Algorithm(profile.Algorithm),
			cose.EC2KeyParameterCrv: profile.Curve,
			cose.EC2KeyParameterX:   privateKey.X.FillBytes(make([]byte, profile.KeySizeBytes)),
			cose.EC2KeyParameterY:   privateKey.Y.FillBytes(make([]byte, profile.KeySizeBytes)),
		}
	case profile.KeyType == cose.KeyTypeEC2 && profile.Curve == cose.EllipticCurveSecp256k1:
		privateKey, err := secp256k1.GeneratePrivateKey()
		if err != nil {
			t.Fatal(err)
		}
		material.signMessage = func(message []byte) ([]byte, error) {
			digest := authrMakeCredResp1Digest(cose.Algorithm(profile.Algorithm), message)

			return secp256k1ecdsa.Sign(privateKey, digest).Serialize(), nil
		}
		publicKey := privateKey.PubKey().SerializeUncompressed()
		material.key = cose.Key{
			cose.KeyParameterKty:    cose.KeyTypeEC2,
			cose.KeyParameterAlg:    cose.Algorithm(profile.Algorithm),
			cose.EC2KeyParameterCrv: cose.EllipticCurveSecp256k1,
			cose.EC2KeyParameterX:   slices.Clone(publicKey[1:33]),
			cose.EC2KeyParameterY:   slices.Clone(publicKey[33:65]),
		}
	case profile.KeyType == cose.KeyTypeRSA:
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		material.privateKey = privateKey
		material.signMessage = func(message []byte) ([]byte, error) {
			algorithm := cose.Algorithm(profile.Algorithm)
			hash := authrMakeCredResp1Hash(algorithm)
			digest := authrMakeCredResp1Digest(algorithm, message)
			switch algorithm {
			case cose.AlgorithmPS256, cose.AlgorithmPS384, cose.AlgorithmPS512:
				return rsa.SignPSS(rand.Reader, privateKey, hash, digest, &rsa.PSSOptions{
					SaltLength: rsa.PSSSaltLengthEqualsHash,
					Hash:       hash,
				})
			default:
				return rsa.SignPKCS1v15(rand.Reader, privateKey, hash, digest)
			}
		}
		material.key = cose.Key{
			cose.KeyParameterKty: cose.KeyTypeRSA,
			cose.KeyParameterAlg: cose.Algorithm(profile.Algorithm),
			cose.RSAKeyParameterN: privateKey.N.FillBytes(
				make([]byte, profile.KeySizeBytes),
			),
			cose.RSAKeyParameterE: big.NewInt(int64(privateKey.E)).Bytes(),
		}
	case profile.KeyType == cose.KeyTypeOKP && profile.Curve == cose.EllipticCurveEd25519:
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		material.privateKey = privateKey
		material.signMessage = func(message []byte) ([]byte, error) {
			return ed25519.Sign(privateKey, message), nil
		}
		material.key = cose.Key{
			cose.KeyParameterKty:    cose.KeyTypeOKP,
			cose.KeyParameterAlg:    cose.Algorithm(profile.Algorithm),
			cose.OKPKeyParameterCrv: cose.EllipticCurveEd25519,
			cose.OKPKeyParameterX:   []byte(publicKey),
		}
	case profile.KeyType == cose.KeyTypeOKP && profile.Curve == cose.EllipticCurveEd448:
		publicKey, privateKey, err := ed448.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		material.signMessage = func(message []byte) ([]byte, error) {
			return ed448.Sign(privateKey, message, ""), nil
		}
		material.key = cose.Key{
			cose.KeyParameterKty:    cose.KeyTypeOKP,
			cose.KeyParameterAlg:    cose.Algorithm(profile.Algorithm),
			cose.OKPKeyParameterCrv: cose.EllipticCurveEd448,
			cose.OKPKeyParameterX:   []byte(publicKey),
		}
	default:
		t.Fatalf("test key profile is unsupported: %#v", profile)
	}

	return material
}

func (material authrMakeCredResp1Key) sign(t testing.TB, message []byte) []byte {
	t.Helper()
	signature, err := material.signMessage(message)
	if err != nil {
		t.Fatal(err)
	}

	return signature
}

func authrMakeCredResp1Digest(algorithm cose.Algorithm, message []byte) []byte {
	hash := authrMakeCredResp1Hash(algorithm)
	switch hash {
	case crypto.SHA1:
		digest := sha1.Sum(message)

		return digest[:]
	case crypto.SHA256:
		digest := sha256.Sum256(message)

		return digest[:]
	case crypto.SHA384:
		digest := sha512.Sum384(message)

		return digest[:]
	case crypto.SHA512:
		digest := sha512.Sum512(message)

		return digest[:]
	default:
		panic("test requested an unsupported digest")
	}
}

func authrMakeCredResp1Hash(algorithm cose.Algorithm) crypto.Hash {
	switch algorithm {
	case cose.AlgorithmES256, cose.AlgorithmES256K, cose.AlgorithmPS256, cose.AlgorithmRS256:
		return crypto.SHA256
	case cose.AlgorithmES384, cose.AlgorithmPS384, cose.AlgorithmRS384:
		return crypto.SHA384
	case cose.AlgorithmES512, cose.AlgorithmPS512, cose.AlgorithmRS512:
		return crypto.SHA512
	case cose.AlgorithmRS1:
		return crypto.SHA1
	default:
		panic("test requested a digest for an EdDSA algorithm")
	}
}

type authrMakeCredResp1Device struct {
	t                      testing.TB
	info                   protocol.AuthenticatorGetInfoResponse
	materials              []authrMakeCredResp1Key
	basic                  bool
	format                 attestation.AttestationStatementFormatIdentifier
	root                   *x509.Certificate
	rootKey                crypto.Signer
	makeCredentialRequests []protocol.AuthenticatorMakeCredentialRequest
	makeCredentialStatus   ctaptransport.StatusCode
	makeCredentialError    error
	mutate                 func(map[uint64]any)
	keyMutate              func(cose.Key)
	encodeResponse         func(map[uint64]any) []byte
	resets                 int
}

func newAuthrMakeCredResp1Device(
	t testing.TB,
	materials []authrMakeCredResp1Key,
	basic bool,
) *authrMakeCredResp1Device {
	t.Helper()
	algorithms := make([]credential.PublicKeyCredentialParameters, 0, len(materials))
	for _, material := range materials {
		algorithm := cose.Algorithm(material.profile.Algorithm)
		algorithms = append(algorithms, credential.PublicKeyCredentialParameters{
			Type:      credential.PublicKeyCredentialTypePublicKey,
			Algorithm: algorithm,
		})
	}
	device := &authrMakeCredResp1Device{
		t:         t,
		materials: materials,
		basic:     basic,
		format:    attestation.AttestationStatementFormatIdentifierPacked,
		info: protocol.AuthenticatorGetInfoResponse{
			Versions:           []protocol.Version{protocol.FIDO_2_3},
			Extensions:         []extension.ExtensionIdentifier{},
			AAGUID:             authrMakeCredResp1TestAAGUID,
			Options:            map[protocol.Option]bool{protocol.OptionClientPIN: false},
			PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo},
			Algorithms:         algorithms,
			AttestationFormats: []attestation.AttestationStatementFormatIdentifier{
				attestation.AttestationStatementFormatIdentifierPacked,
			},
		},
	}
	if basic {
		device.root, device.rootKey = newAuthrMakeCredResp1Root(t)
	}

	return device
}

func (device *authrMakeCredResp1Device) CBOR(
	ctx context.Context,
	request []byte,
) (ctaptransport.CBORResponse, error) {
	device.t.Helper()
	if err := ctx.Err(); err != nil {
		return ctaptransport.CBORResponse{}, err
	}
	command := protocol.Command(request[0])
	switch command {
	case protocol.AuthenticatorReset:
		device.resets++

		return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_OK}, nil
	case protocol.AuthenticatorGetInfo:
		return ctaptransport.CBORResponse{
			StatusCode: ctaptransport.CTAP2_OK,
			Data:       marshalMakeCredentialFixture(device.t, device.info),
		}, nil
	case protocol.AuthenticatorMakeCredential:
		if device.makeCredentialError != nil {
			return ctaptransport.CBORResponse{}, device.makeCredentialError
		}
		if device.makeCredentialStatus != 0 && device.makeCredentialStatus != ctaptransport.CTAP2_OK {
			return ctaptransport.CBORResponse{StatusCode: device.makeCredentialStatus}, nil
		}
		var makeCredentialRequest protocol.AuthenticatorMakeCredentialRequest
		if err := cbor.Unmarshal(request[1:], &makeCredentialRequest); err != nil {
			device.t.Fatal(err)
		}
		if len(makeCredentialRequest.PubKeyCredParams) != 1 {
			device.t.Fatalf("pubKeyCredParams = %#v", makeCredentialRequest.PubKeyCredParams)
		}
		material := device.materials[len(device.makeCredentialRequests)%len(device.materials)]
		if makeCredentialRequest.PubKeyCredParams[0].Algorithm != cose.Algorithm(material.profile.Algorithm) {
			device.t.Fatalf(
				"requested algorithm %d, want %d",
				makeCredentialRequest.PubKeyCredParams[0].Algorithm,
				material.profile.Algorithm,
			)
		}
		device.makeCredentialRequests = append(device.makeCredentialRequests, makeCredentialRequest)
		fields := device.responseFields(makeCredentialRequest, material)
		if device.mutate != nil {
			device.mutate(fields)
		}
		data := marshalMakeCredentialFixture(device.t, fields)
		if device.encodeResponse != nil {
			data = device.encodeResponse(fields)
		}

		return ctaptransport.CBORResponse{
			StatusCode: ctaptransport.CTAP2_OK,
			Data:       data,
		}, nil
	default:
		device.t.Fatalf("unexpected command %s", command)

		return ctaptransport.CBORResponse{}, nil
	}
}

func (device *authrMakeCredResp1Device) responseFields(
	request protocol.AuthenticatorMakeCredentialRequest,
	material authrMakeCredResp1Key,
) map[uint64]any {
	key := make(cose.Key, len(material.key))
	for label, value := range material.key {
		key[label] = value
	}
	if device.keyMutate != nil {
		device.keyMutate(key)
	}
	authData := authrMakeCredResp1AuthData(device.t, request.RP.ID, key)
	statement := map[string]any{
		"alg": material.profile.Algorithm,
		"sig": material.sign(device.t, slices.Concat(authData, request.ClientDataHash)),
	}
	if device.basic {
		leaf := newAuthrMakeCredResp1Leaf(
			device.t,
			device.root,
			device.rootKey,
			material.privateKey.Public(),
			authrMakeCredResp1TestAAGUID,
		)
		statement["x5c"] = []any{leaf.Raw}
	}

	return map[uint64]any{
		1: string(device.format),
		2: authData,
		3: statement,
	}
}

func authrMakeCredResp1AuthData(t testing.TB, rpID string, key cose.Key) []byte {
	t.Helper()
	authData := make([]byte, 37)
	copy(authData, sha256Bytes(rpID))
	authData[32] = byte(protocol.AuthDataFlagUserPresent | protocol.AuthDataFlagAttestedCredentialDataIncluded)
	authData = append(authData, authrMakeCredResp1TestAAGUID[:]...)
	credentialID := bytes.Repeat([]byte{0x5c}, 32)
	authData = append(authData, 0, byte(len(credentialID)))
	authData = append(authData, credentialID...)
	authData = append(authData, marshalMakeCredentialFixture(t, key)...)

	return authData
}

func authrMakeCredResp1ReplaceCredentialID(authData, credentialID []byte) []byte {
	oldLength := int(authData[53])<<8 | int(authData[54])
	key := authData[55+oldLength:]
	replaced := slices.Clone(authData[:53])
	replaced = append(replaced, byte(len(credentialID)>>8), byte(len(credentialID)))
	replaced = append(replaced, credentialID...)
	replaced = append(replaced, key...)

	return replaced
}

func newAuthrMakeCredResp1Root(t testing.TB) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "CTAP test root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	encoded, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(encoded)
	if err != nil {
		t.Fatal(err)
	}

	return certificate, privateKey
}

func newAuthrMakeCredResp1Leaf(
	t testing.TB,
	root *x509.Certificate,
	rootKey crypto.Signer,
	publicKey crypto.PublicKey,
	aaguid uuid.UUID,
) *x509.Certificate {
	t.Helper()
	rawSubject := authrMakeCredResp1Subject(t, asn1.TagUTF8String, "US", "Authenticator Attestation")
	extensionValue, err := asn1.Marshal(aaguid[:])
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		RawSubject:            rawSubject,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		ExtraExtensions: []pkix.Extension{{
			Id:       oidFIDOAAGUID,
			Critical: false,
			Value:    extensionValue,
		}},
	}
	encoded, err := x509.CreateCertificate(rand.Reader, template, root, publicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(encoded)
	if err != nil {
		t.Fatal(err)
	}

	return certificate
}

func authrMakeCredResp1Subject(t testing.TB, organizationTag int, country, unit string) []byte {
	t.Helper()
	raw, err := asn1.Marshal(pkix.RDNSequence{
		{{Type: oidCountryName, Value: asn1.RawValue{Tag: asn1.TagPrintableString, Bytes: []byte(country)}}},
		{{Type: oidOrganizationName, Value: asn1.RawValue{Tag: organizationTag, Bytes: []byte("Telesma")}}},
		{{Type: oidOrganizationalUnitName, Value: asn1.RawValue{Tag: asn1.TagUTF8String, Bytes: []byte(unit)}}},
		{{Type: oidCommonName, Value: asn1.RawValue{Tag: asn1.TagUTF8String, Bytes: []byte("CTAP test authenticator")}}},
	})
	if err != nil {
		t.Fatal(err)
	}

	return raw
}

type authrMakeCredResp1Lifecycle struct {
	powerCycles    int
	providerCalls  []PinUvAuthTokenRequest
	tokens         [][]byte
	cleanupFailure error
}

func authrMakeCredResp1Config(
	t testing.TB,
	device *authrMakeCredResp1Device,
	materials []authrMakeCredResp1Key,
	attestationType string,
) (Config, *authrMakeCredResp1Lifecycle) {
	t.Helper()
	algorithmNames := make([]string, 0, len(materials))
	for _, material := range materials {
		algorithmNames = append(algorithmNames, material.name)
	}
	statement := map[string]any{
		"aaguid":                      authrMakeCredResp1TestAAGUID.String(),
		"authenticationAlgorithms":    algorithmNames,
		"attestationTypes":            []string{attestationType},
		"attestationRootCertificates": []string{},
	}
	if device.root != nil {
		statement["attestationRootCertificates"] = []string{
			base64.StdEncoding.EncodeToString(device.root.Raw),
		}
	}
	statementJSON, err := json.Marshal(statement)
	if err != nil {
		t.Fatal(err)
	}
	lifecycle := &authrMakeCredResp1Lifecycle{}
	config := Config{
		Metadata: Metadata{StatementJSON: string(statementJSON)},
		PowerCycler: func(context.Context) error {
			lifecycle.powerCycles++
			if lifecycle.cleanupFailure != nil && lifecycle.powerCycles%3 == 0 {
				return lifecycle.cleanupFailure
			}

			return nil
		},
		TokenProvider: func(
			_ context.Context,
			_ *client.Client,
			request PinUvAuthTokenRequest,
		) (PinUvAuthToken, error) {
			if request.Permission != protocol.PermissionMakeCredential || request.RPID != authrMakeCredResp1RPID {
				t.Fatalf("token request = %#v", request)
			}
			lifecycle.providerCalls = append(lifecycle.providerCalls, request)
			token := bytes.Repeat([]byte{byte(len(lifecycle.tokens) + 1)}, 32)
			lifecycle.tokens = append(lifecycle.tokens, token)

			return PinUvAuthToken{Protocol: protocol.PinUvAuthProtocolTwo, Value: token}, nil
		},
	}

	return config, lifecycle
}

func (lifecycle *authrMakeCredResp1Lifecycle) assert(t testing.TB, runs int) {
	t.Helper()
	if lifecycle.powerCycles != runs*3 {
		t.Fatalf("power cycles = %d, want %d", lifecycle.powerCycles, runs*3)
	}
	if len(lifecycle.providerCalls) == 0 {
		t.Fatal("token provider was not called")
	}
	for _, token := range lifecycle.tokens {
		if slices.ContainsFunc(token, func(value byte) bool { return value != 0 }) {
			t.Fatal("PIN/UV token was not zeroed")
		}
	}
}

func runAuthrMakeCredResp1Test(
	t *testing.T,
	device ctaptransport.CBOR,
	config Config,
	id conformance.TestID,
) conformance.SuiteResult {
	t.Helper()
	var selected conformance.Test
	for _, test := range authrMakeCredResp1Tests(config) {
		if test.ID == id {
			selected = test
			break
		}
	}
	if selected.Run == nil {
		t.Fatalf("test %q not found", id)
	}
	runner, err := conformance.NewRunner(device)
	if err != nil {
		t.Fatal(err)
	}
	result, err := runner.Run(t.Context(), conformance.Suite{
		ID:    "authr-make-cred-resp-1-test",
		Name:  "Authr MakeCred Resp 1 test",
		Tests: []conformance.Test{selected},
	})
	if err != nil {
		t.Fatal(err)
	}

	return result
}

func assertAuthrMakeCredResp1Status(
	t testing.TB,
	result conformance.SuiteResult,
	want conformance.Status,
) {
	t.Helper()
	if result.Status != want || len(result.Tests) != 1 || result.Tests[0].Status != want {
		t.Fatalf("result = %#v, want %s", result, want)
	}
}
