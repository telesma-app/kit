package ctap23

import (
	"errors"
	"fmt"
	"math"
	"slices"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/cose"
	registry "github.com/telesma-app/fido-registry"
	"github.com/telesma-app/kit/conformance"
)

type metadataCOSEAlgorithm struct {
	name    string
	value   registry.AuthenticationAlgorithm
	profile registry.COSEAuthenticationProfile
}

func resolveMetadataCOSEAlgorithms(names []string) ([]metadataCOSEAlgorithm, error) {
	algorithms := make([]metadataCOSEAlgorithm, 0, len(names))
	for _, name := range names {
		algorithm, ok := registry.ParseAuthenticationAlgorithm(name)
		if !ok {
			return nil, conformance.Failf(
				"metadata authenticationAlgorithms contains unregistered value %q",
				name,
			)
		}
		profile, ok := algorithm.COSEProfile()
		if !ok {
			return nil, fmt.Errorf(
				"ctap23: Registry 2.3 authentication algorithm %q has no supported COSE profile",
				name,
			)
		}
		algorithms = append(algorithms, metadataCOSEAlgorithm{
			name:    name,
			value:   algorithm,
			profile: profile,
		})
	}

	return algorithms, nil
}

func resolveCredentialPublicKeyMetadataAlgorithms(
	key cose.Key,
	algorithms []metadataCOSEAlgorithm,
) ([]metadataCOSEAlgorithm, error) {
	profile, err := credentialPublicKeyProfile(key)
	if err != nil {
		return nil, err
	}

	matches := make([]metadataCOSEAlgorithm, 0, 2)
	for _, algorithm := range algorithms {
		if algorithm.profile == profile {
			matches = append(matches, algorithm)
		}
	}
	if len(matches) == 0 {
		return nil, conformance.Failf(
			"credential COSE key profile alg=%d kty=%d crv=%d is not allowed by metadata",
			profile.Algorithm,
			profile.KeyType,
			profile.Curve,
		)
	}

	return matches, nil
}

func credentialPublicKeyProfile(key cose.Key) (registry.COSEAuthenticationProfile, error) {
	algorithm, err := credentialPublicKeyInteger(key, cose.KeyParameterAlg, "alg")
	if err != nil {
		return registry.COSEAuthenticationProfile{}, err
	}
	keyType, err := credentialPublicKeyInteger(key, cose.KeyParameterKty, "kty")
	if err != nil {
		return registry.COSEAuthenticationProfile{}, err
	}

	var curve int64
	if keyType != cose.KeyTypeRSA {
		curve, err = credentialPublicKeyInteger(key, cose.EC2KeyParameterCrv, "crv")
		if err != nil {
			return registry.COSEAuthenticationProfile{}, err
		}
	}
	profile, ok := registry.LookupCOSEAuthenticationProfile(algorithm, keyType, curve)
	if !ok {
		return registry.COSEAuthenticationProfile{}, conformance.Failf(
			"credential COSE key has unregistered profile alg=%d kty=%d crv=%d",
			algorithm,
			keyType,
			curve,
		)
	}
	if _, err := key.PublicKey(); err != nil {
		if errors.Is(err, cose.ErrUnsupportedAlgorithm) || errors.Is(err, cose.ErrUnsupportedKey) {
			return registry.COSEAuthenticationProfile{}, fmt.Errorf(
				"ctap23: Registry COSE profile is not implemented by ctap/cose: %w",
				err,
			)
		}

		return registry.COSEAuthenticationProfile{}, conformance.Failf(
			"invalid credential COSE key: %v",
			err,
		)
	}

	return profile, nil
}

func validateCredentialPublicKeyProfile(
	key cose.Key,
	raw []byte,
	algorithm metadataCOSEAlgorithm,
) error {
	var fields map[int64]cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(raw, &fields); err != nil {
		return conformance.Failf("invalid credential COSE key: %v", err)
	}
	profile := algorithm.profile
	if err := requireCredentialPublicKeyInteger(fields, cose.KeyParameterKty, profile.KeyType, "kty"); err != nil {
		return err
	}
	if err := requireCredentialPublicKeyInteger(fields, cose.KeyParameterAlg, profile.Algorithm, "alg"); err != nil {
		return err
	}

	allowed := []int64{cose.KeyParameterKty, cose.KeyParameterAlg}
	switch profile.KeyType {
	case cose.KeyTypeRSA:
		allowed = append(allowed, cose.RSAKeyParameterN, cose.RSAKeyParameterE)
		if err := requireCredentialPublicKeyBytes(fields, cose.RSAKeyParameterN, profile.KeySizeBytes, "n"); err != nil {
			return err
		}
		if err := requireCredentialPublicKeyBytes(fields, cose.RSAKeyParameterE, -1, "e"); err != nil {
			return err
		}
	case cose.KeyTypeEC2:
		allowed = append(allowed, cose.EC2KeyParameterCrv, cose.EC2KeyParameterX, cose.EC2KeyParameterY)
		if err := requireCredentialPublicKeyInteger(fields, cose.EC2KeyParameterCrv, profile.Curve, "crv"); err != nil {
			return err
		}
		if err := requireCredentialPublicKeyBytes(fields, cose.EC2KeyParameterX, profile.KeySizeBytes, "x"); err != nil {
			return err
		}
		if err := requireCredentialPublicKeyBytes(fields, cose.EC2KeyParameterY, profile.KeySizeBytes, "y"); err != nil {
			return err
		}
	case cose.KeyTypeOKP:
		allowed = append(allowed, cose.OKPKeyParameterCrv, cose.OKPKeyParameterX)
		if err := requireCredentialPublicKeyInteger(fields, cose.OKPKeyParameterCrv, profile.Curve, "crv"); err != nil {
			return err
		}
		if err := requireCredentialPublicKeyBytes(fields, cose.OKPKeyParameterX, profile.KeySizeBytes, "x"); err != nil {
			return err
		}
	default:
		return fmt.Errorf("ctap23: unsupported Registry COSE key type %d", profile.KeyType)
	}
	if len(fields) != len(allowed) || slices.ContainsFunc(
		allowed,
		func(label int64) bool { _, present := fields[label]; return !present },
	) {
		return conformance.Failf("credential COSE key labels are %v, want exactly %v", mapKeys(fields), allowed)
	}
	keyProfile, err := credentialPublicKeyProfile(key)
	if err != nil {
		return err
	}
	if keyProfile != profile {
		return conformance.Failf(
			"credential COSE key profile is alg=%d kty=%d crv=%d, want alg=%d kty=%d crv=%d",
			keyProfile.Algorithm,
			keyProfile.KeyType,
			keyProfile.Curve,
			profile.Algorithm,
			profile.KeyType,
			profile.Curve,
		)
	}
	registered, ok := profile.AuthenticationAlgorithms()
	if !ok || !slices.Contains(registered, algorithm.value) {
		return fmt.Errorf("ctap23: Registry COSE profile cannot map metadata algorithm %q", algorithm.name)
	}

	return nil
}

func credentialPublicKeyInteger(key cose.Key, label int, name string) (int64, error) {
	value, present := key[label]
	if !present {
		return 0, conformance.Failf("credential COSE key %s is missing or is not an integer", name)
	}
	switch value := value.(type) {
	case int:
		return int64(value), nil
	case int64:
		return value, nil
	case uint64:
		if value <= math.MaxInt64 {
			return int64(value), nil
		}
	case cose.Algorithm:
		return int64(value), nil
	}

	return 0, conformance.Failf("credential COSE key %s is missing or is not an integer", name)
}

func requireCredentialPublicKeyInteger(
	fields map[int64]cbor.RawMessage,
	label int,
	want int64,
	name string,
) error {
	raw, present := fields[int64(label)]
	if !present || len(raw) == 0 || raw[0]>>5 > 1 {
		return conformance.Failf("credential COSE key %s is missing or is not an integer", name)
	}
	var value int64
	if err := getInfoDecMode.Unmarshal(raw, &value); err != nil {
		return conformance.Failf("credential COSE key %s is invalid: %v", name, err)
	}
	if value != want {
		return conformance.Failf("credential COSE key %s is %d, want %d", name, value, want)
	}

	return nil
}

func requireCredentialPublicKeyBytes(
	fields map[int64]cbor.RawMessage,
	label int,
	wantLength int,
	name string,
) error {
	raw, present := fields[int64(label)]
	if !present || !hasCBORMajorType(raw, 2) {
		return conformance.Failf("credential COSE key %s is missing or is not a byte string", name)
	}
	var value []byte
	if err := getInfoDecMode.Unmarshal(raw, &value); err != nil {
		return conformance.Failf("credential COSE key %s is invalid: %v", name, err)
	}
	if len(value) == 0 || wantLength >= 0 && len(value) != wantLength {
		if wantLength < 0 {
			return conformance.Failf("credential COSE key %s must not be empty", name)
		}

		return conformance.Failf(
			"credential COSE key %s is %d bytes, want %d",
			name,
			len(value),
			wantLength,
		)
	}

	return nil
}
