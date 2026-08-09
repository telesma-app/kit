package ctap23

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/credential"
	ctapcrypto "github.com/telesma-app/ctap/crypto"
	"github.com/telesma-app/ctap/extension"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
)

const hmacSecretMCSourcePath = "tests/CTAP2/Protocol/Extensions/hmacSecretMC.js"

const (
	TestIDHMACSecretMCP1 conformance.TestID = "fido.ctap2.3.hmac-secret-mc.p-1"
	TestIDHMACSecretMCP2 conformance.TestID = "fido.ctap2.3.hmac-secret-mc.p-2"
	TestIDHMACSecretMCP3 conformance.TestID = "fido.ctap2.3.hmac-secret-mc.p-3"
	TestIDHMACSecretMCF1 conformance.TestID = "fido.ctap2.3.hmac-secret-mc.f-1"
	TestIDHMACSecretMCF2 conformance.TestID = "fido.ctap2.3.hmac-secret-mc.f-2"
	TestIDHMACSecretMCF3 conformance.TestID = "fido.ctap2.3.hmac-secret-mc.f-3"
	TestIDHMACSecretMCF4 conformance.TestID = "fido.ctap2.3.hmac-secret-mc.f-4"
)

type hmacSecretMCSession struct {
	hmacSecretSession
	protocols        []protocol.PinUvAuthProtocol
	makeCredUvNotRqd bool
}

func (session *hmacSecretMCSession) clear() {
	session.hmacSecretSession.clear()
	session.protocols = nil
}

func hmacSecretMCTests(config Config) []conformance.Test {
	mcReference := hmacSecretMCReference("make-credential-secret-output", conformance.RequirementMust)
	dependencyReference := hmacSecretMCReference("requires-hmac-secret", conformance.RequirementMust)
	missingReference := hmacSecretMCReference("missing-hmac-secret-error", conformance.RequirementMust)
	inputReference := hmacSecretReference("hmac-secret-input-validation", conformance.RequirementMust)
	makeCredentialReference := authrMakeCredReq1CommandReference()
	getAssertionReference := authrGetAssertionReq1CommandReference()
	encodingReference := ctapMessageEncodingReference()

	return []conformance.Test{
		hmacSecretMCTest(
			config,
			TestIDHMACSecretMCP1,
			"P-1",
			"Non-UV MakeCredential and UV GetAssertion use distinct credential secrets",
			[]conformance.RequirementRef{
				mcReference,
				dependencyReference,
				makeCredentialReference,
				getAssertionReference,
				encodingReference,
			},
			func(ctx context.Context, test *conformance.TestContext, session *hmacSecretMCSession) error {
				if session.alwaysUV || !session.makeCredUvNotRqd {
					return conformance.Skip(
						"P-1 requires alwaysUv=false and makeCredUvNotRqd=true",
					)
				}

				return runHMACSecretMCProtocols(session, func(selectedProtocol protocol.PinUvAuthProtocol) error {
					label := hmacSecretMCLabel("p-1", selectedProtocol, false, "primary")
					rpID := hmacSecretMCRPID("p-1", selectedProtocol, false)
					firstSalt := hmacSecretSalt(label + "-first")
					defer clear(firstSalt)
					secondSalt := hmacSecretSalt(label + "-second")
					defer clear(secondSalt)

					credential, unverified, err := hmacSecretMCCreateCredential(
						ctx,
						test,
						session,
						selectedProtocol,
						label,
						rpID,
						false,
						false,
						false,
						firstSalt,
						secondSalt,
					)
					if err != nil {
						return err
					}
					defer clear(credential.ID)
					defer unverified.clear()

					protocolSession := session.hmacSecretSession
					protocolSession.protocol = selectedProtocol
					verified, err := hmacSecretGetAssertion(
						ctx,
						test,
						&protocolSession,
						credential,
						firstSalt,
						secondSalt,
						selectedProtocol,
						true,
					)
					if err != nil {
						return err
					}
					defer verified.clear()

					if bytes.Equal(unverified.First, verified.First) {
						return conformance.Fail("first MC no-UV output equals GA UV output")
					}
					if bytes.Equal(unverified.Second, verified.Second) {
						return conformance.Fail("second MC no-UV output equals GA UV output")
					}

					return nil
				})
			},
		),
		hmacSecretMCTest(
			config,
			TestIDHMACSecretMCP2,
			"P-2",
			"One-salt MakeCredential output equals GetAssertion output",
			[]conformance.RequirementRef{
				mcReference,
				dependencyReference,
				makeCredentialReference,
				getAssertionReference,
				encodingReference,
			},
			func(ctx context.Context, test *conformance.TestContext, session *hmacSecretMCSession) error {
				return runHMACSecretMCMatrix(session, func(selectedProtocol protocol.PinUvAuthProtocol, discoverable bool) error {
					label := hmacSecretMCLabel("p-2", selectedProtocol, discoverable, "primary")
					rpID := hmacSecretMCRPID("p-2", selectedProtocol, discoverable)
					firstSalt := hmacSecretSalt(label + "-first")
					defer clear(firstSalt)

					credential, created, err := hmacSecretMCCreateCredential(
						ctx, test, session, selectedProtocol, label, rpID,
						discoverable, true, true, firstSalt, nil,
					)
					if err != nil {
						return err
					}
					defer clear(credential.ID)
					defer created.clear()

					protocolSession := session.hmacSecretSession
					protocolSession.protocol = selectedProtocol
					asserted, err := hmacSecretGetAssertion(
						ctx, test, &protocolSession, credential,
						firstSalt, nil, selectedProtocol, true,
					)
					if err != nil {
						return err
					}
					defer asserted.clear()

					if !bytes.Equal(created.First, asserted.First) {
						return conformance.Fail("one-salt MC output differs from GA output")
					}

					return nil
				})
			},
		),
		hmacSecretMCTest(
			config,
			TestIDHMACSecretMCP3,
			"P-3",
			"Two-salt outputs preserve order and differ by credential",
			[]conformance.RequirementRef{
				mcReference,
				dependencyReference,
				makeCredentialReference,
				getAssertionReference,
				encodingReference,
			},
			func(ctx context.Context, test *conformance.TestContext, session *hmacSecretMCSession) error {
				return runHMACSecretMCMatrix(session, func(selectedProtocol protocol.PinUvAuthProtocol, discoverable bool) error {
					rpID := hmacSecretMCRPID("p-3", selectedProtocol, discoverable)
					firstSalt := hmacSecretSalt(hmacSecretMCLabel("p-3", selectedProtocol, discoverable, "first-salt"))
					defer clear(firstSalt)
					secondSalt := hmacSecretSalt(hmacSecretMCLabel("p-3", selectedProtocol, discoverable, "second-salt"))
					defer clear(secondSalt)

					firstCredential, created, err := hmacSecretMCCreateCredential(
						ctx, test, session, selectedProtocol,
						hmacSecretMCLabel("p-3", selectedProtocol, discoverable, "first-credential"),
						rpID, discoverable, true, true, firstSalt, secondSalt,
					)
					if err != nil {
						return err
					}
					defer clear(firstCredential.ID)
					defer created.clear()

					protocolSession := session.hmacSecretSession
					protocolSession.protocol = selectedProtocol
					asserted, err := hmacSecretGetAssertion(
						ctx, test, &protocolSession, firstCredential,
						firstSalt, secondSalt, selectedProtocol, true,
					)
					if err != nil {
						return err
					}
					defer asserted.clear()
					if !bytes.Equal(created.First, asserted.First) ||
						!bytes.Equal(created.Second, asserted.Second) {
						return conformance.Fail("two-salt MC and GA outputs differ or changed order")
					}

					secondCredential, secondCreated, err := hmacSecretMCCreateCredential(
						ctx, test, session, selectedProtocol,
						hmacSecretMCLabel("p-3", selectedProtocol, discoverable, "second-credential"),
						rpID, discoverable, true, true, firstSalt, secondSalt,
					)
					if err != nil {
						return err
					}
					defer clear(secondCredential.ID)
					defer secondCreated.clear()
					if bytes.Equal(firstCredential.ID, secondCredential.ID) {
						return conformance.Fail("two local credentials have equal credential IDs")
					}
					if bytes.Equal(created.First, secondCreated.First) {
						return conformance.Fail("first HMAC output is not credential-scoped")
					}
					if bytes.Equal(created.Second, secondCreated.Second) {
						return conformance.Fail("second HMAC output is not credential-scoped")
					}

					return nil
				})
			},
		),
		hmacSecretMCTest(
			config,
			TestIDHMACSecretMCF1,
			"F-1",
			"MakeCredential requires hmac-secret with hmac-secret-mc",
			[]conformance.RequirementRef{
				missingReference,
				makeCredentialReference,
				encodingReference,
			},
			func(ctx context.Context, test *conformance.TestContext, session *hmacSecretMCSession) error {
				return runHMACSecretMCMatrix(session, func(selectedProtocol protocol.PinUvAuthProtocol, discoverable bool) error {
					return hmacSecretMCMalformedRequest(
						ctx, test, session, selectedProtocol,
						"f-1", discoverable, hmacSecretMCMissingDependency,
					)
				})
			},
		),
		hmacSecretMCTest(
			config,
			TestIDHMACSecretMCF2,
			"F-2",
			"MakeCredential rejects malformed hmac-secret-mc members",
			[]conformance.RequirementRef{
				mcReference,
				inputReference,
				makeCredentialReference,
				encodingReference,
			},
			func(ctx context.Context, test *conformance.TestContext, session *hmacSecretMCSession) error {
				return runHMACSecretMCMatrix(session, func(selectedProtocol protocol.PinUvAuthProtocol, discoverable bool) error {
					return hmacSecretMCMalformedRequest(
						ctx, test, session, selectedProtocol,
						"f-2", discoverable, hmacSecretMCWrongMembers,
					)
				})
			},
		),
		hmacSecretMCTest(
			config,
			TestIDHMACSecretMCF3,
			"F-3",
			"MakeCredential rejects a short first salt",
			[]conformance.RequirementRef{
				mcReference,
				inputReference,
				makeCredentialReference,
				encodingReference,
			},
			func(ctx context.Context, test *conformance.TestContext, session *hmacSecretMCSession) error {
				return runHMACSecretMCMatrix(session, func(selectedProtocol protocol.PinUvAuthProtocol, discoverable bool) error {
					salt := hmacSecretSalt(hmacSecretMCLabel("f-3", selectedProtocol, discoverable, "short"))
					defer clear(salt)

					return hmacSecretMCInvalidSalt(
						ctx, test, session, selectedProtocol,
						"f-3", discoverable, salt[:16],
					)
				})
			},
		),
		hmacSecretMCTest(
			config,
			TestIDHMACSecretMCF4,
			"F-4",
			"MakeCredential rejects a short second salt",
			[]conformance.RequirementRef{
				mcReference,
				inputReference,
				makeCredentialReference,
				encodingReference,
			},
			func(ctx context.Context, test *conformance.TestContext, session *hmacSecretMCSession) error {
				return runHMACSecretMCMatrix(session, func(selectedProtocol protocol.PinUvAuthProtocol, discoverable bool) error {
					first := hmacSecretSalt(hmacSecretMCLabel("f-4", selectedProtocol, discoverable, "first"))
					defer clear(first)
					second := hmacSecretSalt(hmacSecretMCLabel("f-4", selectedProtocol, discoverable, "short-second"))
					defer clear(second)
					plaintext := make([]byte, 0, 48)
					plaintext = append(plaintext, first...)
					plaintext = append(plaintext, second[:16]...)
					defer clear(plaintext)

					return hmacSecretMCInvalidSalt(
						ctx, test, session, selectedProtocol,
						"f-4", discoverable, plaintext,
					)
				})
			},
		),
	}
}

func hmacSecretMCTest(
	config Config,
	id conformance.TestID,
	marker string,
	name string,
	references []conformance.RequirementRef,
	run func(context.Context, *conformance.TestContext, *hmacSecretMCSession) error,
) conformance.Test {
	featureReference := hmacSecretMCReference("feature-detection", conformance.RequirementMust)
	protocolReference := hmacSecretProtocolTwoReference()
	resetRequirement := resetReference()
	powerCycleRequirement := clientPINPowerCycleReference()
	testReferences := make([]conformance.RequirementRef, 0, len(references)+4)
	testReferences = append(testReferences, hmacSecretMandatoryReference(), featureReference)
	testReferences = append(testReferences, references...)
	testReferences = append(testReferences, protocolReference, resetRequirement, powerCycleRequirement)

	return conformance.Test{
		ID:          id,
		Name:        name,
		Description: name,
		Source: conformance.SourceLocation{
			Path: hmacSecretMCSourcePath,
			Case: marker,
		},
		References:  testReferences,
		Destructive: true,
		Run: func(test *conformance.TestContext) {
			if !test.Step(conformance.Step{
				ID:   "hmac-secret-mc.applicability",
				Name: "Check hmac-secret-mc and protocol applicability",
				References: []conformance.RequirementRef{
					featureReference,
					protocolReference,
				},
				Run: func(ctx context.Context) error {
					fields, info, err := readGetInfo(ctx, test.CBOR())
					if err != nil {
						return err
					}

					return hmacSecretMCApplicability(fields, info, config)
				},
			}) {
				return
			}
			if config.PowerCycler == nil {
				test.Step(conformance.Step{
					ID:   "hmac-secret-mc.environment",
					Name: "Require authenticator lifecycle control",
					Run: func(context.Context) error {
						return errors.New("ctap23: authenticator power cycler is required for hmac-secret-mc tests")
					},
				})

				return
			}

			test.Cleanup(hmacSecretCleanupStep(test, config, resetRequirement, powerCycleRequirement))
			if !test.Step(hmacSecretResetStep(test, config, resetRequirement, powerCycleRequirement)) {
				return
			}

			var session hmacSecretMCSession
			if !test.Step(conformance.Step{
				ID:         "hmac-secret-mc.authorization",
				Name:       "Prepare protocol authorization and advertised protocol matrix",
				References: []conformance.RequirementRef{protocolReference},
				Run: func(ctx context.Context) error {
					return prepareHMACSecretMCSession(ctx, test, config, &session)
				},
			}) {
				return
			}
			defer session.clear()

			test.Step(conformance.Step{
				ID:         conformance.StepID("hmac-secret-mc." + strings.ToLower(marker) + ".command"),
				Name:       name,
				References: references,
				Run: func(ctx context.Context) error {
					return run(ctx, test, &session)
				},
			})
		},
	}
}

func hmacSecretMCApplicability(
	fields map[uint64]cbor.RawMessage,
	info protocol.AuthenticatorGetInfoResponse,
	config Config,
) error {
	hasHMACSecret := slices.Contains(info.Extensions, extension.ExtensionIdentifierHMACSecret)
	hasMC := slices.Contains(info.Extensions, extension.ExtensionIdentifierHMACSecretMC)
	if config.Featureful && (!hasHMACSecret || !hasMC) {
		return conformance.Fail("featureful profile requires hmac-secret and hmac-secret-mc")
	}
	if !hasHMACSecret || !hasMC {
		return conformance.Skip("authenticator does not advertise both hmac-secret extensions")
	}

	return validateClientPINProtocolSupport(fields, info, config, protocol.PinUvAuthProtocolTwo)
}

func prepareHMACSecretMCSession(
	ctx context.Context,
	test *conformance.TestContext,
	config Config,
	session *hmacSecretMCSession,
) error {
	if err := prepareHMACSecretSessionForProtocol(
		ctx,
		test,
		config,
		&session.hmacSecretSession,
		protocol.PinUvAuthProtocolTwo,
	); err != nil {
		return err
	}

	fields, info, err := readGetInfo(ctx, test.CBOR())
	if err != nil {
		return err
	}
	if !slices.Contains(info.Extensions, extension.ExtensionIdentifierHMACSecret) ||
		!slices.Contains(info.Extensions, extension.ExtensionIdentifierHMACSecretMC) {
		return conformance.Fail("hmac-secret extension support disappeared after reset")
	}
	if !slices.Contains(info.PinUvAuthProtocols, protocol.PinUvAuthProtocolTwo) {
		return conformance.Fail("PIN/UV protocol 2 support disappeared after reset")
	}

	for _, selectedProtocol := range info.PinUvAuthProtocols {
		if selectedProtocol == protocol.PinUvAuthProtocolOne ||
			selectedProtocol == protocol.PinUvAuthProtocolTwo {
			session.protocols = append(session.protocols, selectedProtocol)
		}
	}
	if len(session.protocols) == 0 {
		return conformance.Fail("authenticator advertises no supported PIN/UV protocol")
	}
	session.info = info
	session.makeCredUvNotRqd, _, err = rawGetInfoOption(fields, protocol.OptionMakeCredentialUvNotRequired)

	return err
}

func runHMACSecretMCProtocols(
	session *hmacSecretMCSession,
	run func(protocol.PinUvAuthProtocol) error,
) error {
	for _, selectedProtocol := range session.protocols {
		if err := run(selectedProtocol); err != nil {
			return err
		}
	}

	return nil
}

func runHMACSecretMCMatrix(
	session *hmacSecretMCSession,
	run func(protocol.PinUvAuthProtocol, bool) error,
) error {
	return runHMACSecretMCProtocols(session, func(selectedProtocol protocol.PinUvAuthProtocol) error {
		return runHMACSecretCredentialKinds(func(discoverable bool) error {
			return run(selectedProtocol, discoverable)
		})
	})
}

func hmacSecretMCCreateCredential(
	ctx context.Context,
	test *conformance.TestContext,
	session *hmacSecretMCSession,
	selectedProtocol protocol.PinUvAuthProtocol,
	label string,
	rpID string,
	discoverable bool,
	includeOptions bool,
	verified bool,
	first []byte,
	second []byte,
) (hmacSecretCredential, hmacSecretOutputs, error) {
	envelope, err := newHMACSecretSaltEnvelopeForProtocol(
		ctx, test, first, second, selectedProtocol, selectedProtocol,
	)
	if err != nil {
		return hmacSecretCredential{}, hmacSecretOutputs{}, err
	}
	defer envelope.clear()

	request := hmacSecretMCMakeCredentialRequest(
		label,
		rpID,
		session.algorithms,
		discoverable,
		includeOptions,
		envelope.input,
		true,
	)
	if verified {
		protocolSession := session.hmacSecretSession
		protocolSession.protocol = selectedProtocol
		authorization, err := hmacSecretAuthorization(
			ctx, test, &protocolSession, protocol.PermissionMakeCredential, rpID,
		)
		if err != nil {
			return hmacSecretCredential{}, hmacSecretOutputs{}, err
		}
		defer clear(authorization.Value)

		request.PinUvAuthParam = ctapcrypto.Authenticate(
			selectedProtocol,
			authorization.Value,
			request.ClientDataHash,
		)
		defer clear(request.PinUvAuthParam)
		request.PinUvAuthProtocol = selectedProtocol
	}

	wireResponse, err := exchangeMakeCredential(ctx, test.CBOR(), request)
	if err != nil {
		return hmacSecretCredential{}, hmacSecretOutputs{}, unexpectedCTAPStatus(
			"authenticatorMakeCredential",
			err,
		)
	}
	defer clear(wireResponse.Data)

	response, err := decodeMakeCredentialResponse(wireResponse.Data)
	if err != nil {
		return hmacSecretCredential{}, hmacSecretOutputs{}, err
	}
	defer clearMakeCredentialResponse(&response)
	if response.AuthData == nil || !response.AuthData.Flags.UserPresent() {
		return hmacSecretCredential{}, hmacSecretOutputs{}, conformance.Fail(
			"authenticatorMakeCredential response has UP=false",
		)
	}
	if response.AuthData.Flags.UserVerified() != verified {
		return hmacSecretCredential{}, hmacSecretOutputs{}, conformance.Failf(
			"authenticatorMakeCredential response UV=%t, want %t",
			response.AuthData.Flags.UserVerified(),
			verified,
		)
	}
	if response.AuthData.AttestedCredentialData == nil ||
		len(response.AuthData.AttestedCredentialData.CredentialID) == 0 {
		return hmacSecretCredential{}, hmacSecretOutputs{}, conformance.Fail(
			"authenticatorMakeCredential response is missing an attested credential ID",
		)
	}
	rpIDHash := sha256.Sum256([]byte(rpID))
	if !bytes.Equal(response.AuthData.RPIDHash, rpIDHash[:]) {
		return hmacSecretCredential{}, hmacSecretOutputs{}, conformance.Fail(
			"authenticatorMakeCredential response rpIdHash does not match the request",
		)
	}
	if err := requireHMACSecretCreateOutput(response); err != nil {
		return hmacSecretCredential{}, hmacSecretOutputs{}, err
	}
	ciphertext, err := requireHMACSecretMCOutput(response)
	if err != nil {
		return hmacSecretCredential{}, hmacSecretOutputs{}, err
	}
	defer clear(ciphertext)

	pinProtocol, err := ctapcrypto.NewPinUvAuthProtocol(selectedProtocol)
	if err != nil {
		return hmacSecretCredential{}, hmacSecretOutputs{}, err
	}
	decrypted, err := pinProtocol.Decrypt(envelope.sharedSecret, ciphertext)
	if err != nil {
		clear(decrypted)

		return hmacSecretCredential{}, hmacSecretOutputs{}, err
	}
	expectedLength := len(first) + len(second)
	if len(decrypted) != expectedLength {
		clear(decrypted)

		return hmacSecretCredential{}, hmacSecretOutputs{}, conformance.Failf(
			"decrypted hmac-secret-mc output is %d bytes, want %d",
			len(decrypted),
			expectedLength,
		)
	}

	return hmacSecretCredential{
			ID:   slices.Clone(response.AuthData.AttestedCredentialData.CredentialID),
			RPID: rpID,
		}, hmacSecretOutputs{
			First:  decrypted[:len(first)],
			Second: decrypted[len(first):],
		}, nil
}

func hmacSecretMCMakeCredentialRequest(
	label string,
	rpID string,
	algorithms []credential.PublicKeyCredentialParameters,
	discoverable bool,
	includeOptions bool,
	input protocol.HMACSecret,
	includeHMACSecret bool,
) protocol.AuthenticatorMakeCredentialRequest {
	clientDataHash := sha256.Sum256([]byte("hmac-secret-mc make credential client data " + label))
	userID := sha256.Sum256([]byte("hmac-secret-mc make credential user " + label))
	request := protocol.AuthenticatorMakeCredentialRequest{
		ClientDataHash: clientDataHash[:],
		RP: credential.PublicKeyCredentialRpEntity{
			ID:   rpID,
			Name: "CTAP 2.3 hmac-secret-mc conformance",
		},
		User: credential.PublicKeyCredentialUserEntity{
			ID:          userID[:16],
			Name:        "hmac-secret-mc-" + label,
			DisplayName: "HMAC secret MC " + label,
		},
		PubKeyCredParams: algorithms,
		Extensions: protocol.CreateExtensionInputs{
			CreateHMACSecretMCInput: protocol.CreateHMACSecretMCInput{HMACSecret: input},
		},
	}
	if includeHMACSecret {
		request.Extensions.CreateHMACSecretInput.HMACSecret = true
	}
	if includeOptions {
		request.Options = map[protocol.Option]bool{protocol.OptionResidentKeys: discoverable}
	}

	return request
}

func requireHMACSecretMCOutput(response protocol.AuthenticatorMakeCredentialResponse) ([]byte, error) {
	view, err := observeMakeCredentialAuthDataExtensions(response.AuthDataRaw)
	if err != nil {
		return nil, err
	}
	defer view.clearValues()
	if !view.Included {
		return nil, conformance.Fail("authenticatorMakeCredential authData omits extension data")
	}
	raw, present := view.Values[string(extension.ExtensionIdentifierHMACSecretMC)]
	if !present {
		return nil, conformance.Fail("authenticatorMakeCredential authData extensions omit hmac-secret-mc")
	}
	if !hasCBORMajorType(raw, 2) {
		return nil, conformance.Fail("authenticatorMakeCredential hmac-secret-mc output is not a byte string")
	}
	var value []byte
	if err := getInfoDecMode.Unmarshal(raw, &value); err != nil {
		return nil, conformance.Failf("invalid hmac-secret-mc output: %v", err)
	}
	if response.AuthData.Extensions == nil ||
		!bytes.Equal(response.AuthData.Extensions.CreateHMACSecretMCOutput.HMACSecret, value) {
		clear(value)

		return nil, conformance.Fail("typed hmac-secret-mc output differs from wire value")
	}

	return value, nil
}

type hmacSecretMCMalformedMode uint8

const (
	hmacSecretMCMissingDependency hmacSecretMCMalformedMode = iota + 1
	hmacSecretMCWrongMembers
)

func hmacSecretMCMalformedRequest(
	ctx context.Context,
	test *conformance.TestContext,
	session *hmacSecretMCSession,
	selectedProtocol protocol.PinUvAuthProtocol,
	marker string,
	discoverable bool,
	mode hmacSecretMCMalformedMode,
) error {
	label := hmacSecretMCLabel(marker, selectedProtocol, discoverable, "malformed")
	rpID := hmacSecretMCRPID(marker, selectedProtocol, discoverable)
	salt := hmacSecretSalt(label + "-salt")
	defer clear(salt)
	envelope, err := newHMACSecretSaltEnvelopeForProtocol(
		ctx, test, salt, nil, selectedProtocol, selectedProtocol,
	)
	if err != nil {
		return err
	}
	defer envelope.clear()

	request := hmacSecretMCMakeCredentialRequest(
		label, rpID, session.algorithms, discoverable, true, envelope.input, true,
	)
	protocolSession := session.hmacSecretSession
	protocolSession.protocol = selectedProtocol
	authorization, err := hmacSecretAuthorization(
		ctx, test, &protocolSession, protocol.PermissionMakeCredential, rpID,
	)
	if err != nil {
		return err
	}
	defer clear(authorization.Value)
	request.PinUvAuthParam = ctapcrypto.Authenticate(
		selectedProtocol, authorization.Value, request.ClientDataHash,
	)
	defer clear(request.PinUvAuthParam)
	request.PinUvAuthProtocol = selectedProtocol

	fields := ctap2WireFields("hmac-secret-mc malformed MakeCredential", request)
	defer clearCTAP2WireValue(fields)
	clearCTAP2WireValue(fields[6])
	switch mode {
	case hmacSecretMCMissingDependency:
		fields[6] = map[string]any{
			string(extension.ExtensionIdentifierHMACSecretMC): envelope.input,
		}
	case hmacSecretMCWrongMembers:
		fields[6] = map[string]any{
			string(extension.ExtensionIdentifierHMACSecret): true,
			string(extension.ExtensionIdentifierHMACSecretMC): map[uint64]any{
				1: "not-a-key",
				2: uint64(7),
				3: false,
			},
		}
	default:
		panic("unsupported hmac-secret-mc malformed mode")
	}

	response, err := exchangeRawMakeCredential(ctx, test.CBOR(), fields)
	defer clearCTAP2ResponseData(response)
	if mode == hmacSecretMCMissingDependency {
		return expectCTAPStatus(err, ctaptransport.CTAP2_ERR_MISSING_PARAMETER)
	}

	return expectAnyCTAPError(err)
}

func hmacSecretMCInvalidSalt(
	ctx context.Context,
	test *conformance.TestContext,
	session *hmacSecretMCSession,
	selectedProtocol protocol.PinUvAuthProtocol,
	marker string,
	discoverable bool,
	plaintext []byte,
) error {
	label := hmacSecretMCLabel(marker, selectedProtocol, discoverable, "invalid-salt")
	rpID := hmacSecretMCRPID(marker, selectedProtocol, discoverable)
	envelope, err := newHMACSecretEnvelopeForProtocol(
		ctx, test, plaintext, selectedProtocol, selectedProtocol,
	)
	if err != nil {
		return err
	}
	defer envelope.clear()
	request := hmacSecretMCMakeCredentialRequest(
		label, rpID, session.algorithms, discoverable, true, envelope.input, true,
	)
	protocolSession := session.hmacSecretSession
	protocolSession.protocol = selectedProtocol
	authorization, err := hmacSecretAuthorization(
		ctx, test, &protocolSession, protocol.PermissionMakeCredential, rpID,
	)
	if err != nil {
		return err
	}
	defer clear(authorization.Value)
	request.PinUvAuthParam = ctapcrypto.Authenticate(
		selectedProtocol, authorization.Value, request.ClientDataHash,
	)
	defer clear(request.PinUvAuthParam)
	request.PinUvAuthProtocol = selectedProtocol

	response, err := exchangeMakeCredential(ctx, test.CBOR(), request)
	defer clearCTAP2ResponseData(response)

	return expectCTAPStatus(err, ctaptransport.CTAP1_ERR_INVALID_PARAMETER)
}

func hmacSecretMCLabel(
	marker string,
	selectedProtocol protocol.PinUvAuthProtocol,
	discoverable bool,
	suffix string,
) string {
	return fmt.Sprintf(
		"hmac-secret-mc-%s-p%d-%s-%s",
		marker,
		selectedProtocol,
		hmacSecretLabel("credential", discoverable),
		suffix,
	)
}

func hmacSecretMCRPID(
	marker string,
	selectedProtocol protocol.PinUvAuthProtocol,
	discoverable bool,
) string {
	return fmt.Sprintf(
		"hmac-secret-mc-%s-p%d-%s.ctap23-conformance.example",
		marker,
		selectedProtocol,
		hmacSecretLabel("credential", discoverable),
	)
}

func hmacSecretMCReference(
	clause string,
	level conformance.RequirementLevel,
) conformance.RequirementRef {
	return conformance.RequirementRef{
		ID: conformance.RequirementID(
			"ctap-2.3-ps-20260226:12.8:" + clause,
		),
		Specification: conformance.SpecificationCTAP23,
		Section:       "12.8",
		Clause:        clause,
		URL: "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/" +
			"fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-hmac-secret-mc-extension",
		Level: level,
	}
}
