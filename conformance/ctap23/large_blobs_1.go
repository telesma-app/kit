package ctap23

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"fmt"
	"slices"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/client"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
)

const largeBlobs1SourcePath = "tests/CTAP2/Protocol/LargeBlobs/LargeBlobs-1.js"

const (
	TestIDLargeBlobs1P1 conformance.TestID = "fido.ctap2.3.large-blobs-1.p-1"
	TestIDLargeBlobs1P2 conformance.TestID = "fido.ctap2.3.large-blobs-1.p-2"
	TestIDLargeBlobs1P3 conformance.TestID = "fido.ctap2.3.large-blobs-1.p-3"
	TestIDLargeBlobs1P4 conformance.TestID = "fido.ctap2.3.large-blobs-1.p-4"
)

type largeBlobs1WriteState struct {
	payload    []byte
	serialized []byte
	readback   []byte
	fragment   []byte
}

func (state *largeBlobs1WriteState) clear() {
	clear(state.payload)
	clear(state.serialized)
	clear(state.readback)
	clear(state.fragment)
}

func largeBlobs1Tests(config Config) []conformance.Test {
	featureReference := largeBlobs1FeatureReference()
	storageReference := largeBlobs1StorageReference()
	authorizationReference := largeBlobs1AuthorizationReference()
	maximumReference := largeBlobs1MaximumReference()
	resetRequirement := resetReference()

	return []conformance.Test{
		{
			ID:          TestIDLargeBlobs1P1,
			Name:        "Large-blob storage capacity",
			Description: "Checks the advertised maximum serialized large-blob array size when the field is present",
			Source: conformance.SourceLocation{
				Path: largeBlobs1SourcePath,
				Case: "P-1",
			},
			References: []conformance.RequirementRef{featureReference, maximumReference},
			Run: func(test *conformance.TestContext) {
				test.Step(conformance.Step{
					ID:         "large-blobs-1.p-1.get-info",
					Name:       "Check large-blob support and capacity",
					References: []conformance.RequirementRef{featureReference, maximumReference},
					Run: func(ctx context.Context) error {
						fields, _, err := largeBlobs1GetInfo(ctx, test.CBOR(), config)
						if err != nil {
							return err
						}

						rawMaximum, present := fields[11]
						if !present {
							return nil
						}

						var decoded any
						if err := getInfoDecMode.Unmarshal(rawMaximum, &decoded); err != nil {
							return conformance.Failf("maxSerializedLargeBlobArray is not an unsigned integer: %v", err)
						}
						maximum, ok := decoded.(uint64)
						if !ok {
							return conformance.Fail("maxSerializedLargeBlobArray is not an unsigned integer")
						}
						if maximum < 1024 {
							return conformance.Failf("maxSerializedLargeBlobArray is %d, want at least 1024", maximum)
						}

						return nil
					},
				})
			},
		},
		{
			ID:          TestIDLargeBlobs1P2,
			Name:        "Zero-length large-blob read",
			Description: "Requires a present empty byte string when zero bytes are requested at offset zero",
			Source: conformance.SourceLocation{
				Path: largeBlobs1SourcePath,
				Case: "P-2",
			},
			References: []conformance.RequirementRef{featureReference, storageReference},
			Run: func(test *conformance.TestContext) {
				if !test.Step(conformance.Step{
					ID:         "large-blobs-1.p-2.applicability",
					Name:       "Check large-blob applicability",
					References: []conformance.RequirementRef{featureReference},
					Run: func(ctx context.Context) error {
						_, _, err := largeBlobs1GetInfo(ctx, test.CBOR(), config)

						return err
					},
				}) {
					return
				}

				test.Step(conformance.Step{
					ID:         "large-blobs-1.p-2.read",
					Name:       "Read zero bytes at offset zero",
					References: []conformance.RequirementRef{storageReference},
					Run: func(ctx context.Context) error {
						get := uint(0)
						response, err := exchangeCTAP2(
							ctx,
							test.CBOR(),
							protocol.AuthenticatorLargeBlobs,
							protocol.AuthenticatorLargeBlobsRequest{Get: &get, Offset: 0},
						)
						if err != nil {
							return unexpectedCTAPStatus("authenticatorLargeBlobs", err)
						}

						var fields map[uint64]cbor.RawMessage
						if err := getInfoDecMode.Unmarshal(response.Data, &fields); err != nil {
							return conformance.Failf("invalid authenticatorLargeBlobs response CBOR: %v", err)
						}
						rawConfig, present := fields[1]
						if !present {
							return conformance.Fail("authenticatorLargeBlobs response is missing config")
						}
						if !bytes.Equal(rawConfig, []byte{0x40}) {
							return conformance.Fail("authenticatorLargeBlobs config is not an empty byte string")
						}

						return nil
					},
				})
			},
		},
		{
			ID:          TestIDLargeBlobs1P3,
			Name:        "Initial serialized large-blob array",
			Description: "Reads more than the minimum and requires the exact post-reset serialized empty array",
			Source: conformance.SourceLocation{
				Path: largeBlobs1SourcePath,
				Case: "P-3",
			},
			References:  []conformance.RequirementRef{featureReference, storageReference, resetRequirement},
			Destructive: true,
			Run: func(test *conformance.TestContext) {
				if !test.Step(conformance.Step{
					ID:         "large-blobs-1.p-3.applicability",
					Name:       "Check large-blob applicability",
					References: []conformance.RequirementRef{featureReference},
					Run: func(ctx context.Context) error {
						_, _, err := largeBlobs1GetInfo(ctx, test.CBOR(), config)

						return err
					},
				}) {
					return
				}
				if !test.Step(conformance.Step{
					ID:   "large-blobs-1.p-3.reset",
					Name: "Reset and rebind the authenticator",
					References: []conformance.RequirementRef{
						resetRequirement,
						clientPINPowerCycleReference(),
					},
					Run: func(ctx context.Context) error {
						return largeBlobs1ResetAndRebind(ctx, test, config)
					},
				}) {
					return
				}

				test.Step(conformance.Step{
					ID:         "large-blobs-1.p-3.read",
					Name:       "Read the initial serialized large-blob array",
					References: []conformance.RequirementRef{storageReference},
					Run: func(ctx context.Context) error {
						requested, err := largeBlobs1RandomRange(18, 100)
						if err != nil {
							return fmt.Errorf("ctap23: generate large-blob read length: %w", err)
						}
						response, err := test.Client().LargeBlobs(ctx, 0, nil, requested, nil, 0, 0)
						if err != nil {
							return unexpectedCTAPStatus("authenticatorLargeBlobs", err)
						}
						defer clear(response.Config)

						expected := largeBlobs1InitialSerializedArray()
						if !bytes.Equal(response.Config, expected[:]) {
							return conformance.Fail("authenticatorLargeBlobs did not return the initial serialized large-blob array")
						}

						return nil
					},
				})
			},
		},
		{
			ID:          TestIDLargeBlobs1P4,
			Name:        "Write and read a serialized large-blob array",
			Description: "Writes an authenticated serialized array, reads it back in full, and verifies an exact slice",
			Source: conformance.SourceLocation{
				Path: largeBlobs1SourcePath,
				Case: "P-4",
			},
			References: []conformance.RequirementRef{
				featureReference,
				storageReference,
				authorizationReference,
				clientPIN2PermissionsTokenLengthReference(),
				resetRequirement,
			},
			Destructive: true,
			Run: func(test *conformance.TestContext) {
				if !test.Step(conformance.Step{
					ID:         "large-blobs-1.p-4.applicability",
					Name:       "Check large-blob applicability",
					References: []conformance.RequirementRef{featureReference},
					Run: func(ctx context.Context) error {
						_, info, err := largeBlobs1GetInfo(ctx, test.CBOR(), config)
						if err != nil {
							return err
						}
						if !slices.Contains(info.PinUvAuthProtocols, protocol.PinUvAuthProtocolTwo) {
							return conformance.Skip("LargeBlobs P-4 requires PIN/UV protocol 2")
						}

						return nil
					},
				}) {
					return
				}

				test.Cleanup(largeBlobs1CleanupStep(test, config))
				if !test.Step(conformance.Step{
					ID:   "large-blobs-1.p-4.reset",
					Name: "Reset and rebind the authenticator",
					References: []conformance.RequirementRef{
						resetRequirement,
						clientPINPowerCycleReference(),
					},
					Run: func(ctx context.Context) error {
						return largeBlobs1ResetAndRebind(ctx, test, config)
					},
				}) {
					return
				}

				test.Step(conformance.Step{
					ID:   "large-blobs-1.p-4.write-read",
					Name: "Write and read the serialized large-blob array",
					References: []conformance.RequirementRef{
						storageReference,
						authorizationReference,
						clientPIN2PermissionsTokenLengthReference(),
					},
					Run: func(ctx context.Context) error {
						return largeBlobs1WriteAndRead(ctx, test, config)
					},
				})
			},
		},
	}
}

func largeBlobs1GetInfo(
	ctx context.Context,
	device ctaptransport.CBOR,
	config Config,
) (map[uint64]cbor.RawMessage, protocol.AuthenticatorGetInfoResponse, error) {
	fields, info, err := readGetInfo(ctx, device)
	if err != nil {
		return nil, protocol.AuthenticatorGetInfoResponse{}, err
	}

	largeBlobs, _, err := rawGetInfoOption(fields, protocol.OptionLargeBlobs)
	if err != nil {
		return nil, protocol.AuthenticatorGetInfoResponse{}, err
	}
	if config.Featureful && !largeBlobs {
		return nil, protocol.AuthenticatorGetInfoResponse{}, conformance.Fail(
			"featureful profile requires largeBlobs=true",
		)
	}

	residentKeys, _, err := rawGetInfoOption(fields, protocol.OptionResidentKeys)
	if err != nil {
		return nil, protocol.AuthenticatorGetInfoResponse{}, err
	}
	if !largeBlobs || !residentKeys {
		return nil, protocol.AuthenticatorGetInfoResponse{}, conformance.Skip(
			"authenticatorLargeBlobs requires largeBlobs=true and discoverable credentials",
		)
	}

	return fields, info, nil
}

func largeBlobs1ResetAndRebind(ctx context.Context, test *conformance.TestContext, config Config) error {
	if config.PowerCycler == nil {
		return fmt.Errorf("ctap23: authenticator power cycler is required for LargeBlobs state tests")
	}
	if err := config.PowerCycler(ctx); err != nil {
		return err
	}
	if err := resetAuthenticatorForTest(ctx, test.Client(), config.Resetter); err != nil {
		return err
	}

	return config.PowerCycler(ctx)
}

func largeBlobs1CleanupStep(test *conformance.TestContext, config Config) conformance.Step {
	return conformance.Step{
		ID:   "large-blobs-1.cleanup",
		Name: "Reset the authenticator after the large-blob write",
		References: []conformance.RequirementRef{
			resetReference(),
			clientPINPowerCycleReference(),
		},
		Run: func(ctx context.Context) error {
			if config.PowerCycler == nil {
				return fmt.Errorf("ctap23: authenticator power cycler is required for LargeBlobs cleanup")
			}
			if err := config.PowerCycler(ctx); err != nil {
				return err
			}

			return resetAuthenticatorForTest(ctx, test.Client(), config.Resetter)
		},
	}
}

func largeBlobs1WriteAndRead(ctx context.Context, test *conformance.TestContext, config Config) error {
	authorization, err := largeBlobs1IssueWriteAuthorization(ctx, test, config)
	if err != nil {
		return err
	}
	defer largeBlobs1ClearAuthorization(authorization)
	if authorization.Protocol != protocol.PinUvAuthProtocolTwo {
		return fmt.Errorf(
			"ctap23: LargeBlobs test requires PIN/UV protocol 2, provider returned protocol %d",
			authorization.Protocol,
		)
	}
	if err := clientPIN2ValidatePermissionToken(authorization.Value); err != nil {
		return err
	}

	state, err := largeBlobs1NewWriteState()
	if err != nil {
		return err
	}
	defer state.clear()

	if _, err := test.Client().LargeBlobs(
		ctx,
		authorization.Protocol,
		authorization.Value,
		0,
		state.serialized,
		0,
		uint(len(state.serialized)),
	); err != nil {
		return unexpectedCTAPStatus("authenticatorLargeBlobs set", err)
	}

	response, err := test.Client().LargeBlobs(ctx, 0, nil, uint(len(state.serialized)), nil, 0, 0)
	if err != nil {
		return unexpectedCTAPStatus("authenticatorLargeBlobs get", err)
	}
	state.readback = response.Config
	if !bytes.Equal(state.readback, state.serialized) {
		return conformance.Fail("authenticatorLargeBlobs full readback differs from the serialized value")
	}

	offset := len(state.serialized) / 4
	length := len(state.serialized) / 2
	response, err = test.Client().LargeBlobs(ctx, 0, nil, uint(length), nil, uint(offset), 0)
	if err != nil {
		return unexpectedCTAPStatus("authenticatorLargeBlobs sliced get", err)
	}
	state.fragment = response.Config
	if !bytes.Equal(state.fragment, state.serialized[offset:offset+length]) {
		return conformance.Fail("authenticatorLargeBlobs sliced readback differs from the requested substring")
	}

	return nil
}

func largeBlobs1IssueWriteAuthorization(
	ctx context.Context,
	test *conformance.TestContext,
	config Config,
) (PinUvAuthToken, error) {
	fields, info, err := readGetInfo(ctx, test.CBOR())
	if err != nil {
		return PinUvAuthToken{}, err
	}
	if !slices.Contains(info.PinUvAuthProtocols, protocol.PinUvAuthProtocolTwo) {
		return PinUvAuthToken{}, conformance.Fail("PIN/UV protocol 2 support disappeared after reset")
	}
	pinUvAuthToken, present, err := rawGetInfoOption(fields, protocol.OptionPinUvAuthToken)
	if err != nil {
		return PinUvAuthToken{}, err
	}
	if !present || !pinUvAuthToken {
		return PinUvAuthToken{}, conformance.Skip("LargeBlobs P-4 requires pinUvAuthToken=true")
	}

	_, clientPINPresent, err := rawGetInfoOption(fields, protocol.OptionClientPIN)
	if err != nil {
		return PinUvAuthToken{}, err
	}
	if clientPINPresent {
		return largeBlobs1IssuePINWriteAuthorization(ctx, test.Client(), test.CBOR(), config, info)
	}

	_, uvPresent, err := rawGetInfoOption(fields, protocol.OptionUserVerification)
	if err != nil {
		return PinUvAuthToken{}, err
	}
	if !uvPresent {
		return PinUvAuthToken{}, fmt.Errorf(
			"ctap23: LargeBlobs P-4 requires an advertised ClientPIN or built-in UV capability",
		)
	}

	return largeBlobs1IssueUVWriteAuthorization(ctx, test.Client(), test.CBOR(), config, info)
}

func largeBlobs1IssuePINWriteAuthorization(
	ctx context.Context,
	ctapClient *client.Client,
	device ctaptransport.CBOR,
	config Config,
	info protocol.AuthenticatorGetInfoResponse,
) (PinUvAuthToken, error) {
	if config.TemporaryPINProvider == nil {
		return PinUvAuthToken{}, fmt.Errorf("ctap23: temporary PIN provider is required for LargeBlobs P-4")
	}

	request := temporaryPINRequest(info)
	pin, err := config.TemporaryPINProvider(ctx, request)
	defer clear(pin)
	if err != nil {
		return PinUvAuthToken{}, err
	}
	if err := validateTemporaryPIN(pin, request); err != nil {
		return PinUvAuthToken{}, err
	}

	keyAgreement, err := ctapClient.GetKeyAgreement(ctx, protocol.PinUvAuthProtocolTwo)
	if err != nil {
		return PinUvAuthToken{}, unexpectedCTAPStatus("authenticatorClientPIN getKeyAgreement", err)
	}
	if err := ctapClient.SetPIN(ctx, protocol.PinUvAuthProtocolTwo, keyAgreement, string(pin)); err != nil {
		return PinUvAuthToken{}, unexpectedCTAPStatus("authenticatorClientPIN setPIN", err)
	}

	fields, _, err := readGetInfo(ctx, device)
	if err != nil {
		return PinUvAuthToken{}, err
	}
	clientPIN, present, err := rawGetInfoOption(fields, protocol.OptionClientPIN)
	if err != nil {
		return PinUvAuthToken{}, err
	}
	if !present || !clientPIN {
		return PinUvAuthToken{}, conformance.Fail("clientPin is not true after setting the temporary PIN")
	}

	token, err := clientPIN2IssuePermissionToken(
		ctx,
		ctapClient,
		pin,
		protocol.PermissionLargeBlobWrite,
		"",
	)
	if err != nil {
		return PinUvAuthToken{}, unexpectedCTAPStatus(
			"authenticatorClientPIN getPinUvAuthTokenUsingPinWithPermissions",
			err,
		)
	}

	return largeBlobs1ValidatedWriteAuthorization(token)
}

func largeBlobs1IssueUVWriteAuthorization(
	ctx context.Context,
	ctapClient *client.Client,
	device ctaptransport.CBOR,
	config Config,
	info protocol.AuthenticatorGetInfoResponse,
) (PinUvAuthToken, error) {
	if config.TemporaryPINProvider == nil {
		return PinUvAuthToken{}, fmt.Errorf(
			"ctap23: temporary PIN provider is required to configure built-in UV for LargeBlobs P-4",
		)
	}
	if config.UVConfigurator == nil {
		return PinUvAuthToken{}, fmt.Errorf("ctap23: UV configurator is required for LargeBlobs P-4")
	}

	request := temporaryPINRequest(info)
	pin, err := config.TemporaryPINProvider(ctx, request)
	defer clear(pin)
	if err != nil {
		return PinUvAuthToken{}, err
	}
	if err := validateTemporaryPIN(pin, request); err != nil {
		return PinUvAuthToken{}, err
	}
	if err := config.UVConfigurator(ctx, pin); err != nil {
		return PinUvAuthToken{}, err
	}

	fields, _, err := readGetInfo(ctx, device)
	if err != nil {
		return PinUvAuthToken{}, err
	}
	uv, present, err := rawGetInfoOption(fields, protocol.OptionUserVerification)
	if err != nil {
		return PinUvAuthToken{}, err
	}
	if !present || !uv {
		return PinUvAuthToken{}, fmt.Errorf(
			"ctap23: UV configurator completed but GetInfo uv is not true",
		)
	}

	token, err := clientPIN2IssueUVPermissionToken(
		ctx,
		ctapClient,
		protocol.PermissionLargeBlobWrite,
		"",
	)
	if err != nil {
		return PinUvAuthToken{}, unexpectedCTAPStatus(
			"authenticatorClientPIN getPinUvAuthTokenUsingUvWithPermissions",
			err,
		)
	}

	return largeBlobs1ValidatedWriteAuthorization(token)
}

func largeBlobs1ValidatedWriteAuthorization(token []byte) (PinUvAuthToken, error) {
	if err := clientPIN2ValidatePermissionToken(token); err != nil {
		clear(token)

		return PinUvAuthToken{}, err
	}

	return PinUvAuthToken{
		Protocol: protocol.PinUvAuthProtocolTwo,
		Value:    token,
	}, nil
}

func largeBlobs1ClearAuthorization(authorization PinUvAuthToken) {
	clear(authorization.Value)
}

func largeBlobs1NewWriteState() (largeBlobs1WriteState, error) {
	length, err := largeBlobs1RandomRange(20, 100)
	if err != nil {
		return largeBlobs1WriteState{}, fmt.Errorf("ctap23: generate large-blob payload length: %w", err)
	}

	payload := make([]byte, length)
	if _, err := cryptorand.Read(payload); err != nil {
		clear(payload)

		return largeBlobs1WriteState{}, fmt.Errorf("ctap23: generate large-blob payload: %w", err)
	}
	digest := sha256.Sum256(payload)
	serialized := slices.Concat(payload, digest[:16])
	clear(digest[:])

	return largeBlobs1WriteState{payload: payload, serialized: serialized}, nil
}

func largeBlobs1RandomRange(minimum, maximum uint) (uint, error) {
	var sample [1]byte
	if _, err := cryptorand.Read(sample[:]); err != nil {
		return 0, err
	}

	return minimum + uint(sample[0])%(maximum-minimum+1), nil
}

func largeBlobs1InitialSerializedArray() [17]byte {
	digest := sha256.Sum256([]byte{0x80})
	var serialized [17]byte
	serialized[0] = 0x80
	copy(serialized[1:], digest[:16])
	clear(digest[:])

	return serialized
}

func largeBlobs1FeatureReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "ctap-2.3-ps-20260226:6.10.1:large-blobs-feature-detection",
		Specification: conformance.SpecificationCTAP23,
		Section:       "6.10.1",
		Clause:        "large-blobs-feature-detection",
		URL:           "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorLargeBlobs",
		Level:         conformance.RequirementConstraint,
	}
}

func largeBlobs1MaximumReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "ctap-2.3-ps-20260226:6.4:max-serialized-large-blob-array",
		Specification: conformance.SpecificationCTAP23,
		Section:       "6.4",
		Clause:        "max-serialized-large-blob-array",
		URL:           "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorGetInfo",
		Level:         conformance.RequirementMust,
	}
}

func largeBlobs1StorageReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "ctap-2.3-ps-20260226:6.10.2:serialized-large-blob-reads-and-writes",
		Specification: conformance.SpecificationCTAP23,
		Section:       "6.10.2",
		Clause:        "serialized-large-blob-reads-and-writes",
		URL:           "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorLargeBlobs",
		Level:         conformance.RequirementMust,
	}
}

func largeBlobs1AuthorizationReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "ctap-2.3-ps-20260226:6.10.2:large-blob-write-authorization",
		Specification: conformance.SpecificationCTAP23,
		Section:       "6.10.2",
		Clause:        "large-blob-write-authorization",
		URL:           "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorLargeBlobs",
		Level:         conformance.RequirementMust,
	}
}
