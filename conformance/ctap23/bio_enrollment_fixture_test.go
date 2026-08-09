package ctap23

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/client"
	ctapcrypto "github.com/telesma-app/ctap/crypto"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
)

func TestBioEnrollmentFixtureRejectsUnknownAndIncompleteSampleFeedback(t *testing.T) {
	unknown := protocol.LastEnrollSampleStatus(0x0c)
	good := protocol.LastEnrollSampleStatusFingerprintGood
	one := uint(1)
	zero := uint(0)

	tests := []struct {
		name     string
		response protocol.AuthenticatorBioEnrollmentResponse
		begin    bool
		message  string
	}{
		{
			name:     "missing begin template",
			response: protocol.AuthenticatorBioEnrollmentResponse{LastEnrollSampleStatus: &good, RemainingSamples: &one},
			begin:    true,
			message:  "empty templateId",
		},
		{
			name: "unknown status",
			response: protocol.AuthenticatorBioEnrollmentResponse{
				TemplateID:             []byte{1},
				LastEnrollSampleStatus: &unknown,
				RemainingSamples:       &one,
			},
			begin:   true,
			message: "unknown lastEnrollSampleStatus",
		},
		{
			name: "completed with bad feedback",
			response: protocol.AuthenticatorBioEnrollmentResponse{
				LastEnrollSampleStatus: &unknown,
				RemainingSamples:       &zero,
			},
			message: "unknown lastEnrollSampleStatus",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var err error
			if test.begin {
				err = validateBioEnrollmentBeginResponse(test.response)
			} else {
				err = validateBioEnrollmentCaptureResponse(test.response, 1)
			}
			var assertionError *conformance.AssertionError
			if !errors.As(err, &assertionError) || !bytes.Contains([]byte(err.Error()), []byte(test.message)) {
				t.Fatalf("error = %v, want conformance failure containing %q", err, test.message)
			}
		})
	}
}

type bioEnrollmentFixtureAuthenticator struct {
	*clientPIN2PermissionsAuthenticator

	templates               []protocol.TemplateInfo
	currentTemplateID       []byte
	remaining               uint
	nextTemplate            byte
	beginRemaining          uint
	maxFriendlyName         uint
	maxConcurrentTemplates  int
	bioWiresExact           bool
	bioOperations           []string
	authorizedRequests      int
	providedPINBuffers      [][]byte
	sensorInfoTemplateID    []byte
	sensorInfoTemplateInfos []protocol.TemplateInfo
	sampleEvents            []string
	statusSubCommand        protocol.BioEnrollmentSubCommand
	status                  ctaptransport.StatusCode
	transportSubCommand     protocol.BioEnrollmentSubCommand
	captureRemaining        []uint
	captureStatus           protocol.LastEnrollSampleStatus
	friendlyNames           []string
	enumerateEmptySuccess   bool
	malformedFriendlyName   bool
}

func newBioEnrollmentFixtureAuthenticator(t *testing.T) *bioEnrollmentFixtureAuthenticator {
	t.Helper()

	return &bioEnrollmentFixtureAuthenticator{
		clientPIN2PermissionsAuthenticator: newClientPIN2PermissionsAuthenticator(t),
		beginRemaining:                     2,
		maxFriendlyName:                    64,
		bioWiresExact:                      true,
		captureStatus:                      protocol.LastEnrollSampleStatusFingerprintGood,
	}
}

func (a *bioEnrollmentFixtureAuthenticator) CBOR(
	ctx context.Context,
	request []byte,
) (ctaptransport.CBORResponse, error) {
	a.t.Helper()
	if err := ctx.Err(); err != nil {
		return ctaptransport.CBORResponse{}, err
	}
	if len(request) == 0 {
		a.t.Fatal("empty CTAP request")
	}
	if protocol.Command(request[0]) != protocol.AuthenticatorBioEnrollment {
		return a.clientPIN2PermissionsAuthenticator.CBOR(ctx, request)
	}

	var body protocol.AuthenticatorBioEnrollmentRequest
	if err := getInfoDecMode.Unmarshal(request[1:], &body); err != nil {
		a.t.Fatal(err)
	}
	if body.SubCommand == a.transportSubCommand {
		return ctaptransport.CBORResponse{}, errors.New("device disconnected")
	}
	if body.SubCommand == a.statusSubCommand && a.status != ctaptransport.CTAP2_OK {
		return ctaptransport.ValidateCBORResponse(
			protocol.AuthenticatorBioEnrollment,
			ctaptransport.CBORResponse{StatusCode: a.status},
		)
	}

	response := a.bioEnrollmentResponse(request[1:], body)
	return ctaptransport.ValidateCBORResponse(protocol.AuthenticatorBioEnrollment, response)
}

func (a *bioEnrollmentFixtureAuthenticator) bioEnrollmentResponse(
	bodyBytes []byte,
	body protocol.AuthenticatorBioEnrollmentRequest,
) ctaptransport.CBORResponse {
	a.t.Helper()

	var fields map[uint64]cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(bodyBytes, &fields); err != nil {
		a.t.Fatal(err)
	}

	switch body.SubCommand {
	case protocol.BioEnrollmentSubCommandEnrollBegin:
		a.validateAuthorizedBioRequest(fields, body, protocol.BioEnrollmentSubCommandParams{
			TimeoutMilliseconds: bioEnrollmentTimeoutMilliseconds,
		})
		a.nextTemplate++
		a.currentTemplateID = []byte{0x74, a.nextTemplate}
		a.remaining = a.beginRemaining
		a.bioOperations = append(a.bioOperations, "begin")
		a.sampleEvents = append(a.sampleEvents, "begin")
		status := protocol.LastEnrollSampleStatusFingerprintGood

		return a.success(map[uint64]any{
			4: slices.Clone(a.currentTemplateID),
			5: status,
			6: a.remaining,
		})
	case protocol.BioEnrollmentSubCommandEnrollCaptureNextSample:
		a.validateAuthorizedBioRequest(fields, body, protocol.BioEnrollmentSubCommandParams{
			TemplateID:          body.SubCommandParams.TemplateID,
			TimeoutMilliseconds: bioEnrollmentTimeoutMilliseconds,
		})
		if !bytes.Equal(body.SubCommandParams.TemplateID, a.currentTemplateID) {
			a.t.Fatalf("capture templateId = %x, want %x", body.SubCommandParams.TemplateID, a.currentTemplateID)
		}
		if len(a.captureRemaining) != 0 {
			a.remaining = a.captureRemaining[0]
			a.captureRemaining = a.captureRemaining[1:]
		} else if a.remaining > 0 {
			a.remaining--
		}
		a.bioOperations = append(a.bioOperations, "capture")
		a.sampleEvents = append(a.sampleEvents, "capture")
		if a.remaining == 0 {
			a.templates = append(a.templates, protocol.TemplateInfo{
				TemplateID: slices.Clone(a.currentTemplateID),
			})
			a.maxConcurrentTemplates = max(a.maxConcurrentTemplates, len(a.templates))
		}

		return a.success(map[uint64]any{5: a.captureStatus, 6: a.remaining})
	case protocol.BioEnrollmentSubCommandCancelCurrentEnrollment:
		a.validateUnauthenticatedBioRequest(fields, body)
		a.bioOperations = append(a.bioOperations, "cancel")
		clear(a.currentTemplateID)
		a.currentTemplateID = nil
		a.remaining = 0

		return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_OK}
	case protocol.BioEnrollmentSubCommandEnumerateEnrollments:
		a.validateAuthorizedBioRequest(fields, body, protocol.BioEnrollmentSubCommandParams{})
		a.bioOperations = append(a.bioOperations, "enumerate")
		if len(a.templates) == 0 {
			if a.enumerateEmptySuccess {
				return a.success(map[uint64]any{7: []protocol.TemplateInfo{}})
			}
			return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_ERR_INVALID_OPTION}
		}
		if a.malformedFriendlyName {
			return a.success(map[uint64]any{7: []any{map[uint64]any{
				1: slices.Clone(a.templates[0].TemplateID),
				2: uint(1),
			}}})
		}
		infos := make([]protocol.TemplateInfo, len(a.templates))
		for index, info := range a.templates {
			infos[index] = protocol.TemplateInfo{
				TemplateID:           slices.Clone(info.TemplateID),
				TemplateFriendlyName: info.TemplateFriendlyName,
			}
		}

		return a.success(map[uint64]any{7: infos})
	case protocol.BioEnrollmentSubCommandSetFriendlyName:
		a.validateAuthorizedBioRequest(fields, body, body.SubCommandParams)
		a.bioOperations = append(a.bioOperations, "rename")
		a.friendlyNames = append(a.friendlyNames, *body.SubCommandParams.TemplateFriendlyName)
		for index := range a.templates {
			if bytes.Equal(a.templates[index].TemplateID, body.SubCommandParams.TemplateID) {
				a.templates[index].TemplateFriendlyName = *body.SubCommandParams.TemplateFriendlyName

				return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_OK}
			}
		}

		return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_ERR_INVALID_OPTION}
	case protocol.BioEnrollmentSubCommandRemoveEnrollment:
		a.validateAuthorizedBioRequest(fields, body, body.SubCommandParams)
		a.bioOperations = append(a.bioOperations, "remove")
		for index := range a.templates {
			if bytes.Equal(a.templates[index].TemplateID, body.SubCommandParams.TemplateID) {
				clear(a.templates[index].TemplateID)
				a.templates = slices.Delete(a.templates, index, index+1)

				return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_OK}
			}
		}

		return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_ERR_INVALID_OPTION}
	case protocol.BioEnrollmentSubCommandGetFingerprintSensorInfo:
		a.validateUnauthenticatedBioRequest(fields, body)
		a.bioOperations = append(a.bioOperations, "sensor-info")

		response := map[uint64]any{
			2: uint(1),
			3: uint(2),
			8: a.maxFriendlyName,
		}
		if a.sensorInfoTemplateID != nil {
			response[4] = a.sensorInfoTemplateID
		}
		if a.sensorInfoTemplateInfos != nil {
			response[7] = a.sensorInfoTemplateInfos
		}

		return a.success(response)
	default:
		a.t.Fatalf("unexpected biometric subcommand %d", body.SubCommand)
		return ctaptransport.CBORResponse{}
	}
}

func (a *bioEnrollmentFixtureAuthenticator) validateAuthorizedBioRequest(
	fields map[uint64]cbor.RawMessage,
	body protocol.AuthenticatorBioEnrollmentRequest,
	params protocol.BioEnrollmentSubCommandParams,
) {
	a.t.Helper()

	wantParams, err := ctap2EncMode.Marshal(params)
	if err != nil {
		a.t.Fatal(err)
	}
	hasParams := body.SubCommand != protocol.BioEnrollmentSubCommandEnumerateEnrollments
	wantFieldCount := 4
	if hasParams {
		wantFieldCount++
	}
	token := a.issuedTokens[protocol.PermissionBioEnrollment]
	authMessage := []byte{byte(protocol.BioModalityFingerprint), byte(body.SubCommand)}
	if hasParams {
		authMessage = slices.Concat(authMessage, wantParams)
	}
	wantAuth := ctapcrypto.Authenticate(protocol.PinUvAuthProtocolTwo, token, authMessage)
	defer clear(wantAuth)

	freshToken := len(a.permissionScopes) == a.authorizedRequests+1 &&
		a.permissionScopes[len(a.permissionScopes)-1] == protocol.PermissionBioEnrollment &&
		a.permissionRPIDs[len(a.permissionRPIDs)-1] == ""
	a.bioWiresExact = a.bioWiresExact &&
		freshToken &&
		len(fields) == wantFieldCount &&
		body.Modality == protocol.BioModalityFingerprint &&
		body.PinUvAuthProtocol == protocol.PinUvAuthProtocolTwo &&
		bytes.Equal(body.PinUvAuthParam, wantAuth) &&
		(fields[3] != nil) == hasParams &&
		(!hasParams || bytes.Equal(fields[3], wantParams))
	if !a.bioWiresExact {
		a.t.Fatalf("BioEnrollment request = %#v, fields = %#v", body, fields)
	}
	a.authorizedRequests++
}

func (a *bioEnrollmentFixtureAuthenticator) validateUnauthenticatedBioRequest(
	fields map[uint64]cbor.RawMessage,
	body protocol.AuthenticatorBioEnrollmentRequest,
) {
	a.t.Helper()

	a.bioWiresExact = a.bioWiresExact &&
		len(fields) == 2 &&
		body.Modality == protocol.BioModalityFingerprint &&
		body.PinUvAuthProtocol == 0 &&
		len(body.PinUvAuthParam) == 0
	if !a.bioWiresExact {
		a.t.Fatalf("unauthenticated BioEnrollment request = %#v, fields = %#v", body, fields)
	}
}

func (a *bioEnrollmentFixtureAuthenticator) reset() {
	a.clientPIN2NewPINAuthenticator.reset()
	for permission, token := range a.issuedTokens {
		clear(token)
		delete(a.issuedTokens, permission)
	}
	for index := range a.templates {
		clear(a.templates[index].TemplateID)
	}
	a.templates = nil
	clear(a.currentTemplateID)
	a.currentTemplateID = nil
	a.remaining = 0
}

func bioEnrollmentFixtureConfig(a *bioEnrollmentFixtureAuthenticator) Config {
	return Config{
		Transport: AuthenticatorTransportHID,
		PowerCycler: func(context.Context) error {
			a.powerCycles++

			return nil
		},
		Resetter: func(context.Context, *client.Client) error {
			a.reset()

			return nil
		},
		TemporaryPINProvider: func(_ context.Context, request TemporaryPINRequest) ([]byte, error) {
			if request.MinCodePoints != 4 || request.MaxCodePoints != 63 {
				return nil, fmt.Errorf("unexpected PIN bounds %d..%d", request.MinCodePoints, request.MaxCodePoints)
			}
			pin := []byte("1234")
			a.providedPINBuffers = append(a.providedPINBuffers, pin)

			return pin, nil
		},
		BiometricSampleProvider: func(context.Context) error {
			a.sampleEvents = append(a.sampleEvents, "sample")

			return nil
		},
	}
}

func runBioEnrollmentTests(
	t *testing.T,
	authenticator ctaptransport.CBOR,
	tests []conformance.Test,
) conformance.SuiteResult {
	t.Helper()

	runner, err := conformance.NewRunner(authenticator)
	if err != nil {
		t.Fatal(err)
	}
	result, err := runner.Run(t.Context(), conformance.Suite{
		ID:    "bio-enrollment-test",
		Name:  "biometric enrollment test",
		Tests: tests,
	})
	if err != nil {
		t.Fatal(err)
	}

	return result
}

func assertBioEnrollmentFixtureOwnership(t *testing.T, a *bioEnrollmentFixtureAuthenticator) {
	t.Helper()

	if !a.bioWiresExact || !a.permissionWiresExact {
		t.Fatal("biometric enrollment or permission-token wire request was not exact")
	}
	for _, rpID := range a.permissionRPIDs {
		if rpID != "" {
			t.Fatalf("biometric enrollment permission token used RP ID %q", rpID)
		}
	}
	for _, scope := range a.permissionScopes {
		if scope != protocol.PermissionBioEnrollment {
			t.Fatalf("permission scope = %#x, want be only", scope)
		}
	}
	for index, pin := range a.providedPINBuffers {
		if !allZero(pin) {
			t.Fatalf("PIN buffer %d retained: %x", index, pin)
		}
	}
}

func TestBioEnrollmentFixtureLifecycleWipesOwnedPINTokenAndTemplateBuffers(t *testing.T) {
	authenticator := newBioEnrollmentFixtureAuthenticator(t)
	config := bioEnrollmentFixtureConfig(authenticator)
	var (
		retainedPIN              []byte
		retainedBeginToken       []byte
		retainedCaptureToken     []byte
		retainedTemplateID       []byte
		retainedResponseTemplate []byte
		lastRemaining            uint
	)
	test := conformance.Test{
		ID:   "bio-enrollment-fixture-test.ownership",
		Name: "Biometric enrollment fixture ownership",
		Run: func(test *conformance.TestContext) {
			var fixture *bioEnrollmentFixture
			if !test.Step(bioEnrollmentPrepareStep(test, config, &fixture)) {
				return
			}
			retainedPIN = fixture.pin

			if !test.Step(conformance.Step{
				ID:   "bio-enrollment-fixture-test.ownership.begin",
				Name: "Begin enrollment and retain fixture-owned buffers",
				Run: func(ctx context.Context) error {
					response, err := fixture.begin(ctx)
					defer clearBioEnrollmentResponse(&response)
					if err != nil {
						return err
					}
					if err := validateBioEnrollmentBeginResponse(response); err != nil {
						return err
					}

					retainedBeginToken = fixture.token
					retainedTemplateID = fixture.templateID
					retainedResponseTemplate = response.TemplateID
					lastRemaining = *response.RemainingSamples

					return nil
				},
			}) {
				return
			}

			test.Step(conformance.Step{
				ID:   "bio-enrollment-fixture-test.ownership.capture",
				Name: "Refresh authorization and retain the replacement token",
				Run: func(ctx context.Context) error {
					response, err := fixture.capture(ctx)
					defer clearBioEnrollmentResponse(&response)
					if err != nil {
						return err
					}
					retainedCaptureToken = fixture.token

					return validateBioEnrollmentCaptureResponse(response, lastRemaining)
				},
			})
		},
	}

	result := runBioEnrollmentTests(t, authenticator, []conformance.Test{test})
	if result.Status != conformance.StatusPassed {
		t.Fatalf("result = %#v", result)
	}
	if !allZero(retainedPIN) || !allZero(retainedBeginToken) ||
		!allZero(retainedCaptureToken) || !allZero(retainedTemplateID) ||
		!allZero(retainedResponseTemplate) {
		t.Fatalf(
			"fixture-owned buffers retained: PIN=%x tokens=%x/%x template=%x response=%x",
			retainedPIN,
			retainedBeginToken,
			retainedCaptureToken,
			retainedTemplateID,
			retainedResponseTemplate,
		)
	}
	assertBioEnrollmentFixtureOwnership(t, authenticator)
}

func TestClearBioEnrollmentResponseWipesDirectAndNestedTemplateIDs(t *testing.T) {
	retainedDirect := []byte{0x71, 0x72}
	retainedNestedFirst := []byte{0x73, 0x74}
	retainedNestedSecond := []byte{0x75, 0x76}
	response := protocol.AuthenticatorBioEnrollmentResponse{
		TemplateID: retainedDirect,
		TemplateInfos: []protocol.TemplateInfo{
			{TemplateID: retainedNestedFirst},
			{TemplateID: retainedNestedSecond},
		},
	}

	clearBioEnrollmentResponse(&response)
	if !allZero(retainedDirect) || !allZero(retainedNestedFirst) || !allZero(retainedNestedSecond) {
		t.Fatalf(
			"response buffers retained: direct=%x nested=%x/%x",
			retainedDirect,
			retainedNestedFirst,
			retainedNestedSecond,
		)
	}
	if response.TemplateID != nil || response.TemplateInfos != nil {
		t.Fatalf("cleared response = %#v", response)
	}
}

var _ ctaptransport.CBOR = (*bioEnrollmentFixtureAuthenticator)(nil)
