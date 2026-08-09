package ctap23

import (
	"errors"
	"slices"
	"testing"

	"github.com/telesma-app/ctap/cose"
	registry "github.com/telesma-app/fido-registry"
	"github.com/telesma-app/kit/conformance"
)

var metadataCOSEProfileTestAlgorithmNames = []string{
	"secp256r1_ecdsa_sha256_raw",
	"secp256r1_ecdsa_sha256_der",
	"rsassa_pss_sha256_raw",
	"rsassa_pss_sha256_der",
	"secp256k1_ecdsa_sha256_raw",
	"secp256k1_ecdsa_sha256_der",
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

func TestResolveMetadataCOSEAlgorithmsPreservesRegistryProfiles(t *testing.T) {
	algorithms, err := resolveMetadataCOSEAlgorithms(metadataCOSEProfileTestAlgorithmNames)
	if err != nil {
		t.Fatal(err)
	}
	if len(algorithms) != 16 {
		t.Fatalf("algorithms = %d, want 16", len(algorithms))
	}

	profiles := map[registry.COSEAuthenticationProfile][]registry.AuthenticationAlgorithm{}
	for index, algorithm := range algorithms {
		if algorithm.name != metadataCOSEProfileTestAlgorithmNames[index] {
			t.Fatalf("algorithm %d name = %q", index, algorithm.name)
		}
		profiles[algorithm.profile] = append(profiles[algorithm.profile], algorithm.value)
	}
	if len(profiles) != 13 {
		t.Fatalf("profiles = %d, want 13", len(profiles))
	}

	wantPairs := [][]registry.AuthenticationAlgorithm{
		{
			registry.AuthenticationAlgorithmSECP256R1ECDSASHA256Raw,
			registry.AuthenticationAlgorithmSECP256R1ECDSASHA256DER,
		},
		{
			registry.AuthenticationAlgorithmRSASSAPSSSHA256Raw,
			registry.AuthenticationAlgorithmRSASSAPSSSHA256DER,
		},
		{
			registry.AuthenticationAlgorithmSECP256K1ECDSASHA256Raw,
			registry.AuthenticationAlgorithmSECP256K1ECDSASHA256DER,
		},
	}
	for _, pair := range wantPairs {
		profile, ok := pair[0].COSEProfile()
		if !ok || !slices.Equal(profiles[profile], pair) {
			t.Fatalf("profile %#v algorithms = %v, want %v", profile, profiles[profile], pair)
		}
	}
}

func TestCredentialPublicKeyProfileValidatesAllProfilesAndRejectsMismatches(t *testing.T) {
	algorithms, err := resolveMetadataCOSEAlgorithms(authrMakeCredResp1ProfileAlgorithms)
	if err != nil {
		t.Fatal(err)
	}
	for index, algorithm := range algorithms {
		material := newAuthrMakeCredResp1Key(t, algorithm.name)
		raw := marshalMakeCredentialFixture(t, material.key)
		if err := validateCredentialPublicKeyProfile(material.key, raw, algorithm); err != nil {
			t.Fatalf("profile %q: %v", algorithm.name, err)
		}

		mismatch := algorithms[(index+1)%len(algorithms)]
		err := validateCredentialPublicKeyProfile(material.key, raw, mismatch)
		var assertion *conformance.AssertionError
		if !errors.As(err, &assertion) {
			t.Fatalf("profile %q accepted mismatch %q: %v", algorithm.name, mismatch.name, err)
		}
	}
}

func TestResolveCredentialPublicKeyMetadataAlgorithmsPreservesEncodingPairsAndCurves(t *testing.T) {
	algorithms, err := resolveMetadataCOSEAlgorithms(metadataCOSEProfileTestAlgorithmNames)
	if err != nil {
		t.Fatal(err)
	}
	for _, testCase := range []struct {
		name      string
		wantNames []string
	}{
		{
			name: "secp256r1_ecdsa_sha256_raw",
			wantNames: []string{
				"secp256r1_ecdsa_sha256_raw",
				"secp256r1_ecdsa_sha256_der",
			},
		},
		{
			name:      "ed25519_eddsa_sha512_raw",
			wantNames: []string{"ed25519_eddsa_sha512_raw"},
		},
		{
			name:      "ed448_eddsa_sha512_raw",
			wantNames: []string{"ed448_eddsa_sha512_raw"},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			material := newAuthrMakeCredResp1Key(t, testCase.name)
			matches, err := resolveCredentialPublicKeyMetadataAlgorithms(material.key, algorithms)
			if err != nil {
				t.Fatal(err)
			}
			names := make([]string, 0, len(matches))
			for _, match := range matches {
				names = append(names, match.name)
			}
			if !slices.Equal(names, testCase.wantNames) {
				t.Fatalf("names = %v, want %v", names, testCase.wantNames)
			}
		})
	}

	ed25519Key := newAuthrMakeCredResp1Key(t, "ed25519_eddsa_sha512_raw").key
	ed448Only, err := resolveMetadataCOSEAlgorithms([]string{"ed448_eddsa_sha512_raw"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = resolveCredentialPublicKeyMetadataAlgorithms(ed25519Key, ed448Only)
	var assertion *conformance.AssertionError
	if !errors.As(err, &assertion) {
		t.Fatalf("Ed25519 key matched Ed448 metadata: %v", err)
	}

	wrongCurve := newAuthrMakeCredResp1Key(t, "ed25519_eddsa_sha512_raw").key
	wrongCurve[cose.OKPKeyParameterCrv] = cose.EllipticCurveEd448
	if _, err := credentialPublicKeyProfile(wrongCurve); !errors.As(err, &assertion) {
		t.Fatalf("mismatched OKP curve error = %v", err)
	}
}
