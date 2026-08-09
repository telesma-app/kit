package ctap23

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/credential"
	ctapcrypto "github.com/telesma-app/ctap/crypto"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
)

const (
	residentKeySourcePath = "tests/CTAP2/Protocol/Options/ResidentKey.js"
	residentKeyRPID       = "resident-key.ctap23-conformance.example"

	TestIDResidentKeyP1 conformance.TestID = "fido.ctap2.3.resident-key.p-1"
	TestIDResidentKeyP2 conformance.TestID = "fido.ctap2.3.resident-key.p-2"
	TestIDResidentKeyP3 conformance.TestID = "fido.ctap2.3.resident-key.p-3"
	TestIDResidentKeyP4 conformance.TestID = "fido.ctap2.3.resident-key.p-4"
	TestIDResidentKeyP5 conformance.TestID = "fido.ctap2.3.resident-key.p-5"
	TestIDResidentKeyP6 conformance.TestID = "fido.ctap2.3.resident-key.p-6"
)

type residentKeyCase struct {
	id          conformance.TestID
	marker      string
	name        string
	description string
	references  []conformance.RequirementRef
	applicable  func(Config, map[uint64]cbor.RawMessage, protocol.AuthenticatorGetInfoResponse) error
	prepare     func(context.Context, *conformance.TestContext, *residentKeySession) error
	run         func(context.Context, *conformance.TestContext, *residentKeySession) error
}

func residentKeyTests(config Config) []conformance.Test {
	makeReference := residentKeyReference(
		"6.1.2",
		"resident-key-make-credential",
		"authenticatorMakeCredential",
		conformance.RequirementMust,
	)
	discoverableReference := residentKeyReference(
		"6.1.3",
		"discoverable-credential-storage-and-overwrite",
		"sctn-discoverable-credentials",
		conformance.RequirementMust,
	)
	assertionReference := residentKeyReference(
		"6.2.2",
		"discoverable-credential-selection-and-response",
		"authenticatorGetAssertion",
		conformance.RequirementMust,
	)
	nextReference := residentKeyReference(
		"6.3",
		"get-next-assertion-sequence",
		"authenticatorGetNextAssertion",
		conformance.RequirementMust,
	)
	stateReference := residentKeyReference(
		"6.4",
		"encrypted-credential-store-state",
		"authenticatorGetInfo",
		conformance.RequirementMust,
	)

	definitions := []residentKeyCase{
		{
			id:          TestIDResidentKeyP1,
			marker:      "P-1",
			name:        "Create a discoverable credential",
			description: "Independently resets the authenticator and creates one credential with the canonical rk=true option",
			references:  []conformance.RequirementRef{makeReference, discoverableReference},
			prepare:     residentKeyPrepareConditionalAuthorization,
			run:         residentKeyP1,
		},
		{
			id:          TestIDResidentKeyP2,
			marker:      "P-2",
			name:        "Enumerate three accounts without user verification",
			description: "On an authenticator without an account-selection display, discovers three unverified accounts and validates exact first and continuation response fields",
			references:  []conformance.RequirementRef{discoverableReference, assertionReference, nextReference},
			applicable:  residentKeyAbsentDisplayApplicable,
			prepare:     residentKeyPrepareUnauthenticatedDiscovery,
			run:         residentKeyP2,
		},
		{
			id:          TestIDResidentKeyP3,
			marker:      "P-3",
			name:        "Enumerate two accounts with user verification",
			description: "Configures verification, obtains fresh protocol 2 mc and ga tokens, and validates authenticated account discovery",
			references:  []conformance.RequirementRef{discoverableReference, assertionReference, nextReference},
			applicable:  residentKeyAuthenticatedAbsentDisplayApplicable,
			prepare:     residentKeyPrepareAuthenticatedDiscovery,
			run:         residentKeyP3,
		},
		{
			id:          TestIDResidentKeyP4,
			marker:      "P-4",
			name:        "Select accounts on the authenticator display",
			description: "Prepares three requested on-device selections and requires userSelected=true with no enumeration count",
			references:  []conformance.RequirementRef{discoverableReference, assertionReference},
			applicable:  residentKeyPresentDisplayApplicable,
			prepare:     residentKeyPrepareAuthenticatedDiscovery,
			run:         residentKeyP4,
		},
		{
			id:          TestIDResidentKeyP5,
			marker:      "P-5",
			name:        "Change encrypted credential-store state",
			description: "Requires raw 32-byte encCredStoreState values and verifies both the IV and ciphertext change after a new discoverable credential",
			references:  []conformance.RequirementRef{makeReference, stateReference},
			applicable:  residentKeyEncryptedStateApplicable,
			prepare:     residentKeyPrepareConditionalAuthorization,
			run:         residentKeyP5,
		},
		{
			id:          TestIDResidentKeyP6,
			marker:      "P-6",
			name:        "Overwrite a discoverable credential for the same account",
			description: "Creates the same RP and user ID twice, requires a fresh credential ID and key, rejects the old ID, and accepts the replacement",
			references:  []conformance.RequirementRef{makeReference, discoverableReference, assertionReference},
			prepare:     residentKeyPrepareConditionalAuthorization,
			run:         residentKeyP6,
		},
	}

	tests := make([]conformance.Test, 0, len(definitions))
	for _, definition := range definitions {
		tests = append(tests, residentKeyTest(config, definition))
	}
	return tests
}

func residentKeyTest(config Config, definition residentKeyCase) conformance.Test {
	return conformance.Test{
		ID:          definition.id,
		Name:        definition.name,
		Description: definition.description,
		Source: conformance.SourceLocation{
			Path: residentKeySourcePath,
			Case: definition.marker,
		},
		References:  definition.references,
		Destructive: true,
		Run: func(test *conformance.TestContext) {
			if !test.Step(residentKeyApplicabilityStep(test, config, definition)) {
				return
			}

			test.Cleanup(residentKeyCleanupStep(test, config))
			var session residentKeySession
			prepared := test.Step(conformance.Step{
				ID:         conformance.StepID("resident-key." + definition.marker + ".prepare"),
				Name:       "Reset, rebind, and prepare the independent resident-key session",
				References: []conformance.RequirementRef{resetReference(), clientPINPowerCycleReference()},
				Run: func(ctx context.Context) error {
					var err error
					session, err = prepareResidentKeySession(ctx, test, config)
					if err != nil {
						return err
					}
					if definition.prepare != nil {
						return definition.prepare(ctx, test, &session)
					}
					return nil
				},
			})
			defer session.clear()
			if !prepared {
				return
			}

			test.Step(conformance.Step{
				ID:         conformance.StepID("resident-key." + definition.marker + ".execute"),
				Name:       definition.name,
				References: definition.references,
				Run: func(ctx context.Context) error {
					return definition.run(ctx, test, &session)
				},
			})
		},
	}
}

func residentKeyApplicabilityStep(
	test *conformance.TestContext,
	config Config,
	definition residentKeyCase,
) conformance.Step {
	return conformance.Step{
		ID:         conformance.StepID("resident-key." + definition.marker + ".applicability"),
		Name:       "Confirm resident-key and case-specific applicability",
		References: []conformance.RequirementRef{getInfoReference()},
		Run: func(ctx context.Context) error {
			fields, info, err := residentKeyReadInfo(ctx, test.CBOR())
			if err != nil {
				return err
			}
			defer clearCTAP2RawFields(fields)
			defer clearResidentKeyGetInfo(&info)

			residentKeys, present, err := rawGetInfoOption(fields, protocol.OptionResidentKeys)
			if err != nil {
				return err
			}
			if !present || !residentKeys {
				return conformance.Skip("authenticator does not advertise options.rk=true")
			}
			if definition.applicable != nil {
				return definition.applicable(config, fields, info)
			}
			return nil
		},
	}
}

func residentKeyAbsentDisplayApplicable(
	config Config,
	_ map[uint64]cbor.RawMessage,
	_ protocol.AuthenticatorGetInfoResponse,
) error {
	if config.AccountSelectionDisplay != AccountSelectionDisplayAbsent {
		return conformance.Skip("case requires accountSelectionDisplay=absent")
	}
	return nil
}

func residentKeyPresentDisplayApplicable(
	config Config,
	fields map[uint64]cbor.RawMessage,
	info protocol.AuthenticatorGetInfoResponse,
) error {
	if config.AccountSelectionDisplay != AccountSelectionDisplayPresent {
		return conformance.Skip("case requires accountSelectionDisplay=present")
	}
	if config.PrepareAccountSelection == nil {
		return fmt.Errorf("ctap23: account-selection preparer is required when an account-selection display is declared")
	}
	return validateClientPINProtocolSupport(fields, info, config, protocol.PinUvAuthProtocolTwo)
}

func residentKeyAuthenticatedAbsentDisplayApplicable(
	config Config,
	fields map[uint64]cbor.RawMessage,
	info protocol.AuthenticatorGetInfoResponse,
) error {
	if err := residentKeyAbsentDisplayApplicable(config, fields, info); err != nil {
		return err
	}
	return validateClientPINProtocolSupport(fields, info, config, protocol.PinUvAuthProtocolTwo)
}

func residentKeyEncryptedStateApplicable(
	_ Config,
	fields map[uint64]cbor.RawMessage,
	_ protocol.AuthenticatorGetInfoResponse,
) error {
	raw, present := fields[30]
	if !present {
		return conformance.Skip("GetInfo does not contain encCredStoreState")
	}
	if !hasCBORMajorType(raw, 2) {
		return conformance.Fail("GetInfo encCredStoreState is not a byte string")
	}
	return nil
}

func residentKeyPrepareConditionalAuthorization(
	ctx context.Context,
	test *conformance.TestContext,
	session *residentKeySession,
) error {
	fields, info, err := residentKeyReadInfo(ctx, test.CBOR())
	if err != nil {
		return err
	}
	defer clearCTAP2RawFields(fields)
	defer clearResidentKeyGetInfo(&info)
	return session.useAuthorizationIfRequired(fields)
}

func residentKeyPrepareUnauthenticatedDiscovery(
	ctx context.Context,
	test *conformance.TestContext,
	session *residentKeySession,
) error {
	fields, info, err := residentKeyReadInfo(ctx, test.CBOR())
	if err != nil {
		return err
	}
	defer clearCTAP2RawFields(fields)
	defer clearResidentKeyGetInfo(&info)
	return session.requireUnauthenticatedDiscovery(fields)
}

func residentKeyPrepareAuthenticatedDiscovery(
	ctx context.Context,
	test *conformance.TestContext,
	session *residentKeySession,
) error {
	return session.prepareRequiredVerification(ctx, test)
}

func residentKeyP1(
	ctx context.Context,
	test *conformance.TestContext,
	session *residentKeySession,
) error {
	user := residentKeyUser("p1", nil)
	defer clear(user.ID)
	created, err := residentKeyMakeCredential(
		ctx,
		test,
		session,
		residentKeyMakeCredentialRequest("p1", residentKeyRPID, user, session.algorithms),
	)
	defer created.clear()
	if err != nil {
		return err
	}
	if len(created.ID) == 0 || len(created.PublicKey) == 0 {
		return conformance.Fail("created discoverable credential has an empty ID or public key")
	}
	return nil
}

func residentKeyP2(
	ctx context.Context,
	test *conformance.TestContext,
	session *residentKeySession,
) error {
	credentials, err := residentKeyCreateCredentials(ctx, test, session, "p2", 3, nil)
	defer clearResidentKeyCredentials(credentials)
	if err != nil {
		return err
	}

	assertions, err := residentKeyDiscover(ctx, test, session, "p2", residentKeyRPID, 3)
	defer clearResidentKeyAssertions(assertions)
	if err != nil {
		return err
	}
	if err := residentKeyValidateCountFields(assertions, 3); err != nil {
		return err
	}
	return residentKeyValidateCoverage(credentials, assertions, false)
}

func residentKeyP3(
	ctx context.Context,
	test *conformance.TestContext,
	session *residentKeySession,
) error {
	credentials, err := residentKeyCreateCredentials(ctx, test, session, "p3", 2, nil)
	defer clearResidentKeyCredentials(credentials)
	if err != nil {
		return err
	}

	assertions, err := residentKeyDiscover(ctx, test, session, "p3", residentKeyRPID, 2)
	defer clearResidentKeyAssertions(assertions)
	if err != nil {
		return err
	}
	if err := residentKeyValidateCountFields(assertions, 2); err != nil {
		return err
	}
	return residentKeyValidateCoverage(credentials, assertions, true)
}

func residentKeyP4(
	ctx context.Context,
	test *conformance.TestContext,
	session *residentKeySession,
) error {
	credentials, err := residentKeyCreateCredentials(ctx, test, session, "p4", 3, nil)
	defer clearResidentKeyCredentials(credentials)
	if err != nil {
		return err
	}

	for sequence, index := range []int{2, 0, 1} {
		expected := credentials[index]
		request := residentKeyGetAssertionRequest(fmt.Sprintf("p4-%d", sequence), residentKeyRPID)
		authorization, err := session.authorization(
			ctx,
			test,
			protocol.PermissionGetAssertion,
			request.RPID,
		)
		if err != nil {
			clear(authorization.Value)
			return err
		}
		if len(authorization.Value) != 0 {
			request.PinUvAuthParam = ctapcrypto.Authenticate(
				protocol.PinUvAuthProtocolTwo,
				authorization.Value,
				request.ClientDataHash,
			)
			request.PinUvAuthProtocol = protocol.PinUvAuthProtocolTwo
		}
		selection := AccountSelectionRequest{
			RPID:        residentKeyRPID,
			UserID:      expected.UserID,
			Name:        expected.Name,
			DisplayName: expected.DisplayName,
		}
		if err := session.config.PrepareAccountSelection(ctx, selection); err != nil {
			clear(request.PinUvAuthParam)
			clear(authorization.Value)
			return err
		}

		assertion, err := residentKeyGetAssertionAuthorized(ctx, test, request)
		clear(request.PinUvAuthParam)
		clear(authorization.Value)
		if err != nil {
			assertion.clear()
			return err
		}
		if err := residentKeyValidateSelected(expected, assertion); err != nil {
			assertion.clear()
			return err
		}
		assertion.clear()
	}

	return nil
}

func residentKeyP5(
	ctx context.Context,
	test *conformance.TestContext,
	session *residentKeySession,
) error {
	before, err := residentKeyEncryptedStoreState(ctx, test)
	defer clear(before)
	if err != nil {
		return err
	}

	user := residentKeyUser("p5", nil)
	defer clear(user.ID)
	created, err := residentKeyMakeCredential(
		ctx,
		test,
		session,
		residentKeyMakeCredentialRequest("p5", residentKeyRPID, user, session.algorithms),
	)
	defer created.clear()
	if err != nil {
		return err
	}

	after, err := residentKeyEncryptedStoreState(ctx, test)
	defer clear(after)
	if err != nil {
		return err
	}
	if bytes.Equal(before[:16], after[:16]) {
		return conformance.Fail("encCredStoreState IV did not change after creating a discoverable credential")
	}
	if bytes.Equal(before[16:], after[16:]) {
		return conformance.Fail("encCredStoreState ciphertext did not change after creating a discoverable credential")
	}
	return nil
}

func residentKeyP6(
	ctx context.Context,
	test *conformance.TestContext,
	session *residentKeySession,
) error {
	userID := sha256.Sum256([]byte("resident-key p6 same user"))
	firstUser := residentKeyUser("p6-first", userID[:16])
	defer clear(firstUser.ID)
	first, err := residentKeyMakeCredential(
		ctx,
		test,
		session,
		residentKeyMakeCredentialRequest("p6-first", residentKeyRPID, firstUser, session.algorithms),
	)
	defer first.clear()
	if err != nil {
		return err
	}

	secondUser := residentKeyUser("p6-second", userID[:16])
	defer clear(secondUser.ID)
	second, err := residentKeyMakeCredential(
		ctx,
		test,
		session,
		residentKeyMakeCredentialRequest("p6-second", residentKeyRPID, secondUser, session.algorithms),
	)
	defer second.clear()
	if err != nil {
		return err
	}
	if !bytes.Equal(first.UserID, second.UserID) {
		return conformance.Fail("overwrite fixture did not use the same user ID")
	}
	if bytes.Equal(first.ID, second.ID) {
		return conformance.Fail("replacement credential reused the old credential ID")
	}
	if bytes.Equal(first.PublicKey, second.PublicKey) {
		return conformance.Fail("replacement credential reused the old credential public key")
	}

	oldRequest := residentKeyGetAssertionRequest("p6-old", residentKeyRPID)
	oldRequest.AllowList = []credential.PublicKeyCredentialDescriptor{{
		Type: credential.PublicKeyCredentialTypePublicKey,
		ID:   first.ID,
	}}
	if err := residentKeyExpectNoCredentials(ctx, test, session, oldRequest); err != nil {
		return err
	}

	newRequest := residentKeyGetAssertionRequest("p6-new", residentKeyRPID)
	newRequest.AllowList = []credential.PublicKeyCredentialDescriptor{{
		Type: credential.PublicKeyCredentialTypePublicKey,
		ID:   second.ID,
	}}
	assertion, err := residentKeyGetAssertion(ctx, test, session, newRequest)
	defer assertion.clear()
	if err != nil {
		return err
	}
	if !bytes.Equal(assertion.CredentialID, second.ID) {
		return conformance.Fail("GetAssertion returned a credential other than the replacement")
	}
	return nil
}

func residentKeyCreateCredentials(
	ctx context.Context,
	test *conformance.TestContext,
	session *residentKeySession,
	prefix string,
	count int,
	sharedUserID []byte,
) ([]residentKeyCredential, error) {
	credentials := make([]residentKeyCredential, 0, count)
	for index := 0; index < count; index++ {
		label := fmt.Sprintf("%s-%d", prefix, index)
		user := residentKeyUser(label, sharedUserID)
		created, err := residentKeyMakeCredential(
			ctx,
			test,
			session,
			residentKeyMakeCredentialRequest(label, residentKeyRPID, user, session.algorithms),
		)
		clear(user.ID)
		if err != nil {
			created.clear()
			clearResidentKeyCredentials(credentials)
			return nil, err
		}
		credentials = append(credentials, created)
	}
	return credentials, nil
}

func residentKeyDiscover(
	ctx context.Context,
	test *conformance.TestContext,
	session *residentKeySession,
	label string,
	rpID string,
	count int,
) ([]residentKeyAssertion, error) {
	first, err := residentKeyGetAssertion(
		ctx,
		test,
		session,
		residentKeyGetAssertionRequest(label, rpID),
	)
	if err != nil {
		first.clear()
		return nil, err
	}
	assertions := []residentKeyAssertion{first}
	for index := 1; index < count; index++ {
		next, err := residentKeyGetNextAssertion(ctx, test)
		if err != nil {
			next.clear()
			clearResidentKeyAssertions(assertions)
			return nil, err
		}
		assertions = append(assertions, next)
	}
	return assertions, nil
}

func residentKeyValidateCountFields(assertions []residentKeyAssertion, count uint) error {
	if len(assertions) == 0 || !assertions[0].NumberPresent || assertions[0].Number != count {
		return conformance.Failf("first assertion numberOfCredentials is not the required value %d", count)
	}
	for index := 1; index < len(assertions); index++ {
		if assertions[index].NumberPresent {
			return conformance.Failf("GetNextAssertion response %d contains numberOfCredentials", index)
		}
	}
	return nil
}

func residentKeyValidateCoverage(
	credentials []residentKeyCredential,
	assertions []residentKeyAssertion,
	authenticated bool,
) error {
	if len(credentials) != len(assertions) {
		return conformance.Failf("received %d assertions for %d credentials", len(assertions), len(credentials))
	}
	seenCredentials := make(map[string]struct{}, len(assertions))
	seenUsers := make(map[string]struct{}, len(assertions))
	for _, assertion := range assertions {
		if !assertion.UserPresent || len(assertion.UserID) == 0 {
			return conformance.Fail("discoverable assertion is missing the user entity or user ID")
		}
		credentialKey := string(assertion.CredentialID)
		userKey := string(assertion.UserID)
		if _, duplicate := seenCredentials[credentialKey]; duplicate {
			return conformance.Fail("discoverable assertion repeated a credential ID")
		}
		if _, duplicate := seenUsers[userKey]; duplicate {
			return conformance.Fail("discoverable assertion repeated a user ID")
		}
		seenCredentials[credentialKey] = struct{}{}
		seenUsers[userKey] = struct{}{}

		var expected *residentKeyCredential
		for index := range credentials {
			if bytes.Equal(credentials[index].ID, assertion.CredentialID) {
				expected = &credentials[index]
				break
			}
		}
		if expected == nil || !bytes.Equal(expected.UserID, assertion.UserID) {
			return conformance.Fail("assertion credential and user ID do not match a created account")
		}
		if assertion.UV != authenticated {
			return conformance.Failf("assertion UV bit is %t, want %t", assertion.UV, authenticated)
		}
		if !authenticated {
			if len(assertion.UserFieldKeys) != 1 {
				return conformance.Fail("unverified assertion user map contains fields other than id")
			}
			if _, present := assertion.UserFieldKeys["id"]; !present {
				return conformance.Fail("unverified assertion user map does not contain id")
			}
			continue
		}
		for key := range assertion.UserFieldKeys {
			switch key {
			case "id", "name", "displayName", "icon":
			default:
				return conformance.Failf("verified assertion user map contains unknown member %q", key)
			}
		}
		if _, present := assertion.UserFieldKeys["id"]; !present {
			return conformance.Fail("verified assertion user map does not contain id")
		}
		if _, present := assertion.UserFieldKeys["name"]; present && assertion.UserName != expected.Name {
			return conformance.Fail("verified assertion user name differs from the created account")
		}
		if _, present := assertion.UserFieldKeys["displayName"]; present &&
			assertion.UserDisplayName != expected.DisplayName {
			return conformance.Fail("verified assertion user displayName differs from the created account")
		}
		if _, present := assertion.UserFieldKeys["icon"]; present && assertion.UserIcon != "" {
			return conformance.Fail("verified assertion user icon differs from the created account")
		}
	}
	return nil
}

func residentKeyValidateSelected(
	expected residentKeyCredential,
	assertion residentKeyAssertion,
) error {
	if assertion.NumberPresent {
		return conformance.Fail("on-device account selection response contains numberOfCredentials")
	}
	if !assertion.SelectedPresent || !assertion.Selected {
		return conformance.Fail("on-device account selection response does not contain userSelected=true")
	}
	if !assertion.UV {
		return conformance.Fail("on-device account selection response does not set the UV bit")
	}
	if assertion.CredentialType != credential.PublicKeyCredentialTypePublicKey ||
		!assertion.UserPresent {
		return conformance.Fail("on-device account selection response omits its public-key credential or user entity")
	}
	if !bytes.Equal(assertion.CredentialID, expected.ID) ||
		!bytes.Equal(assertion.UserID, expected.UserID) {
		return conformance.Fail("authenticator returned an account other than the requested on-device selection")
	}
	for key := range assertion.UserFieldKeys {
		switch key {
		case "id", "name", "displayName", "icon":
		default:
			return conformance.Failf("selected account user map contains unknown member %q", key)
		}
	}
	if _, present := assertion.UserFieldKeys["id"]; !present {
		return conformance.Fail("selected account user map does not contain id")
	}
	if assertion.UserName != "" && assertion.UserName != expected.Name {
		return conformance.Fail("selected account user name differs from the created account")
	}
	if assertion.UserDisplayName != "" && assertion.UserDisplayName != expected.DisplayName {
		return conformance.Fail("selected account displayName differs from the created account")
	}
	return nil
}

func residentKeyUser(label string, fixedID []byte) credential.PublicKeyCredentialUserEntity {
	userID := fixedID
	if userID == nil {
		hash := sha256.Sum256([]byte("resident-key user " + label))
		userID = hash[:16]
	}
	return credential.PublicKeyCredentialUserEntity{
		ID:          append([]byte(nil), userID...),
		Name:        "resident-key-" + label,
		DisplayName: "Resident key " + label,
	}
}

func clearResidentKeyCredentials(credentials []residentKeyCredential) {
	for index := range credentials {
		credentials[index].clear()
	}
	clear(credentials)
}

func clearResidentKeyAssertions(assertions []residentKeyAssertion) {
	for index := range assertions {
		assertions[index].clear()
	}
	clear(assertions)
}

func residentKeyCleanupStep(test *conformance.TestContext, config Config) conformance.Step {
	return conformance.Step{
		ID:         "resident-key.cleanup",
		Name:       "Reset and rebind the authenticator after the resident-key case",
		References: []conformance.RequirementRef{resetReference(), clientPINPowerCycleReference()},
		Run: func(ctx context.Context) error {
			return residentKeyResetAndRebind(ctx, test, config)
		},
	}
}

func residentKeyReference(
	section string,
	clause string,
	anchor string,
	level conformance.RequirementLevel,
) conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            conformance.RequirementID("ctap-2.3-ps-20260226:" + section + ":" + clause),
		Specification: conformance.SpecificationCTAP23,
		Section:       section,
		Clause:        clause,
		URL: "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/" +
			"fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#" + anchor,
		Level: level,
	}
}

func residentKeyExpectNoCredentials(
	ctx context.Context,
	test *conformance.TestContext,
	session *residentKeySession,
	request protocol.AuthenticatorGetAssertionRequest,
) error {
	authorization, err := session.authorization(
		ctx,
		test,
		protocol.PermissionGetAssertion,
		request.RPID,
	)
	if err != nil {
		return err
	}
	defer clear(authorization.Value)
	if len(authorization.Value) != 0 {
		request.PinUvAuthParam = ctapcrypto.Authenticate(
			protocol.PinUvAuthProtocolTwo,
			authorization.Value,
			request.ClientDataHash,
		)
		defer clear(request.PinUvAuthParam)
		request.PinUvAuthProtocol = protocol.PinUvAuthProtocolTwo
	}
	response, err := exchangeGetAssertion(ctx, test.CBOR(), request)
	clear(response.Data)
	return expectCTAPStatus(err, ctaptransport.CTAP2_ERR_NO_CREDENTIALS)
}
