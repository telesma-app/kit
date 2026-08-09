package ctap23

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	ctapcrypto "github.com/telesma-app/ctap/crypto"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
)

type encryptedMember struct {
	testID  conformance.TestID
	caseID  string
	name    string
	field   uint64
	value   func(protocol.AuthenticatorGetInfoResponse) []byte
	decrypt func([]byte, []byte) ([16]byte, error)
	state   string
}

func encryptedIdentifierTest(
	provider PinUvAuthTokenProvider,
	resetter AuthenticatorResetter,
) conformance.Test {
	return encryptedStateTest(encryptedMember{
		testID: TestIDAuthrGeneric1P4,
		caseID: "P-4",
		name:   "encIdentifier",
		field:  25,
		value: func(info protocol.AuthenticatorGetInfoResponse) []byte {
			return info.EncIdentifier
		},
		decrypt: ctapcrypto.DecryptDeviceIdentifier,
		state:   "device identifier",
	}, provider, resetter)
}

func encryptedCredentialStoreStateTest(
	provider PinUvAuthTokenProvider,
	resetter AuthenticatorResetter,
) conformance.Test {
	return encryptedStateTest(encryptedMember{
		testID: TestIDAuthrGeneric1P5,
		caseID: "P-5",
		name:   "encCredStoreState",
		field:  30,
		value: func(info protocol.AuthenticatorGetInfoResponse) []byte {
			return info.EncCredStoreState
		},
		decrypt: ctapcrypto.DecryptCredentialStoreState,
		state:   "credential store state",
	}, provider, resetter)
}

func encryptedStateTest(
	member encryptedMember,
	provider PinUvAuthTokenProvider,
	resetter AuthenticatorResetter,
) conformance.Test {
	getInfoRequirement := getInfoReference()
	resetRequirement := resetReference()

	return conformance.Test{
		ID:          member.testID,
		Name:        member.name + " stability and reset behavior",
		Description: "Checks fresh encryption IVs, stable plaintext between GetInfo calls, and regenerated ciphertext after reset",
		Destructive: true,
		Source: conformance.SourceLocation{
			Path: getInfoSourcePath,
			Case: member.caseID,
		},
		References: []conformance.RequirementRef{getInfoRequirement, resetRequirement},
		Run: func(test *conformance.TestContext) {
			var authorization PinUvAuthToken
			defer func() {
				clear(authorization.Value)
			}()

			if !test.Step(conformance.Step{
				ID:         "encrypted-state.support",
				Name:       "Check encrypted state support",
				References: []conformance.RequirementRef{getInfoRequirement},
				Run: func(ctx context.Context) error {
					fields, info, err := readGetInfo(ctx, test.CBOR())
					if err != nil {
						return err
					}
					if _, present := fields[member.field]; !present {
						return conformance.Skip(member.name + " is not advertised")
					}
					if size := len(member.value(info)); size != 32 {
						return conformance.Failf("%s length is %d, want 32", member.name, size)
					}

					return nil
				},
			}) {
				return
			}

			if !test.Step(conformance.Step{
				ID:         "encrypted-state.acquire-token",
				Name:       "Acquire persistent PIN/UV auth token",
				References: []conformance.RequirementRef{getInfoRequirement},
				Run: func(ctx context.Context) error {
					if provider == nil {
						return fmt.Errorf("ctap23: token provider is required for %s", member.name)
					}

					var err error
					authorization, err = provider(
						ctx,
						test.Client(),
						PinUvAuthTokenRequest{
							Permission: protocol.PermissionPersistentCredentialManagementReadOnly,
						},
					)
					if err != nil {
						return err
					}
					if len(authorization.Value) == 0 {
						return fmt.Errorf("ctap23: token provider returned an empty token")
					}

					return nil
				},
			}) {
				return
			}

			var second []byte
			if !test.Step(conformance.Step{
				ID:         "encrypted-state.stability",
				Name:       "Validate fresh IV and stable plaintext",
				References: []conformance.RequirementRef{getInfoRequirement},
				Run: func(ctx context.Context) error {
					first, err := readEncryptedMember(ctx, test.CBOR(), member)
					if err != nil {
						return err
					}
					firstPlaintext, err := member.decrypt(authorization.Value, first)
					if err != nil {
						return conformance.Failf("decrypt %s: %v", member.name, err)
					}

					second, err = readEncryptedMember(ctx, test.CBOR(), member)
					if err != nil {
						return err
					}
					secondPlaintext, err := member.decrypt(authorization.Value, second)
					if err != nil {
						return conformance.Failf("decrypt %s: %v", member.name, err)
					}

					if bytes.Equal(first[:16], second[:16]) {
						return conformance.Failf("%s reused its encryption IV", member.name)
					}
					if firstPlaintext != secondPlaintext {
						return conformance.Failf("%s plaintext changed between GetInfo calls", member.state)
					}

					return nil
				},
			}) {
				return
			}

			if !test.Step(conformance.Step{
				ID:         "authenticator.reset",
				Name:       "Reset the authenticator",
				References: []conformance.RequirementRef{resetRequirement},
				Run: func(ctx context.Context) error {
					if resetter == nil {
						return resetCommandError(test.Client().Reset(ctx))
					}

					return resetCommandError(resetter(ctx, test.Client()))
				},
			}) {
				return
			}

			test.Step(conformance.Step{
				ID:         "encrypted-state.after-reset",
				Name:       "Validate regenerated encrypted state",
				References: []conformance.RequirementRef{getInfoRequirement, resetRequirement},
				Run: func(ctx context.Context) error {
					afterReset, err := readEncryptedMember(ctx, test.CBOR(), member)
					if err != nil {
						return err
					}
					if bytes.Equal(second[:16], afterReset[:16]) {
						return conformance.Failf("%s reused its encryption IV after reset", member.name)
					}
					if bytes.Equal(second[16:], afterReset[16:]) {
						return conformance.Failf("%s ciphertext did not change after reset", member.state)
					}

					return nil
				},
			})
		},
	}
}

func readEncryptedMember(
	ctx context.Context,
	device ctaptransport.CBOR,
	member encryptedMember,
) ([]byte, error) {
	fields, info, err := readGetInfo(ctx, device)
	if err != nil {
		return nil, err
	}
	if _, present := fields[member.field]; !present {
		return nil, conformance.Fail(member.name + " disappeared from GetInfo")
	}

	value := member.value(info)
	if len(value) != 32 {
		return nil, conformance.Failf("%s length is %d, want 32", member.name, len(value))
	}

	return value, nil
}

func resetCommandError(err error) error {
	if err == nil {
		return nil
	}

	var ctapErr *ctaptransport.CTAPError
	if errors.As(err, &ctapErr) {
		return conformance.Failf("authenticatorReset returned %s", ctapErr.StatusCode)
	}

	return err
}

func resetReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "ctap-2.3-ps-20260226:6.6:authenticator-reset",
		Specification: conformance.SpecificationCTAP23,
		Section:       "6.6",
		Clause:        "authenticator-reset",
		URL:           "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorReset",
		Level:         conformance.RequirementConstraint,
	}
}
