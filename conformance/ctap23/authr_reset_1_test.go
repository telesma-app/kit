package ctap23

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/telesma-app/ctap/client"
	ctapcrypto "github.com/telesma-app/ctap/crypto"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
)

func TestAuthrReset1DefinitionAndReferences(t *testing.T) {
	tests := authrReset1Tests(Config{})
	if len(tests) != 1 {
		t.Fatalf("tests = %d, want 1", len(tests))
	}
	test := tests[0]
	if test.ID != TestIDAuthrReset1P1 || test.Source.Path != authrReset1SourcePath ||
		test.Source.Case != "P-1" || !test.Destructive {
		t.Fatalf("test = %#v", test)
	}

	wantReferences := []conformance.RequirementID{
		authrMakeCredReq1CommandReference().ID,
		authrGetAssertionReq1CommandReference().ID,
		authrGetAssertionReq1ResponseCredentialReference().ID,
		resetReference().ID,
		authrReset1ResetWindowReference().ID,
		authrReset1CredentialInvalidationReference().ID,
		authrGetAssertionReq3NoCredentialsReference().ID,
	}
	for _, id := range wantReferences {
		if !authrReset1HasReference(test.References, id) {
			t.Errorf("missing reference %q in %#v", id, test.References)
		}
	}
	windowReference := authrReset1ResetWindowReference()
	if windowReference.Section != "6.6" || windowReference.Level != conformance.RequirementMust ||
		windowReference.URL != resetReference().URL {
		t.Fatalf("reset-window reference = %#v", windowReference)
	}
	stateReference := authrReset1CredentialInvalidationReference()
	if stateReference.Section != "6.6" ||
		stateReference.Level != conformance.RequirementConstraint ||
		stateReference.URL != resetReference().URL {
		t.Fatalf("credential-invalidation reference = %#v", stateReference)
	}
}

func TestAuthrReset1DeletesCredentialAndWipesTokens(t *testing.T) {
	events := []string{}
	device := newAuthrReset1Device(t, &events)
	tokens := [][]byte{
		bytes.Repeat([]byte{0x41}, 32),
		bytes.Repeat([]byte{0x52}, 32),
		bytes.Repeat([]byte{0x63}, 32),
	}
	wantPostResetHMAC := ctapcrypto.Authenticate(
		protocol.PinUvAuthProtocolTwo,
		tokens[2],
		authrReset1PostResetClientDataHash[:],
	)
	stalePostResetHMAC := ctapcrypto.Authenticate(
		protocol.PinUvAuthProtocolTwo,
		tokens[1],
		authrReset1PostResetClientDataHash[:],
	)
	providerCalls := 0
	config := authrReset1Config(&events, func(
		_ context.Context,
		_ *client.Client,
		request PinUvAuthTokenRequest,
	) (PinUvAuthToken, error) {
		if request.RPID != authrReset1RPID {
			t.Fatalf("token RP ID = %q", request.RPID)
		}
		wantPermission := protocol.PermissionGetAssertion
		if providerCalls == 0 {
			wantPermission = protocol.PermissionMakeCredential
		} else {
			authrReset1AssertZeroed(t, tokens[providerCalls-1])
		}
		if request.Permission != wantPermission {
			t.Fatalf("token request = %#v, want %s", request, wantPermission)
		}

		token := tokens[providerCalls]
		providerCalls++

		return PinUvAuthToken{Protocol: protocol.PinUvAuthProtocolTwo, Value: token}, nil
	})

	result := runAuthrReset1Test(t, device, config)
	if result.Status != conformance.StatusPassed {
		t.Fatalf("status = %s; result = %#v", result.Status, result)
	}
	if providerCalls != 3 {
		t.Fatalf("provider calls = %d, want 3", providerCalls)
	}
	for _, token := range tokens {
		authrReset1AssertZeroed(t, token)
	}

	wantEvents := []string{
		"power-cycle",
		"reset",
		"power-cycle",
		"get-info",
		"token:mc",
		"make-credential",
		"token:ga",
		"get-assertion",
		"power-cycle",
		"reset",
		"token:ga",
		"get-assertion",
		"power-cycle",
		"reset",
	}
	if !slices.Equal(events, wantEvents) {
		t.Fatalf("events = %v, want %v", events, wantEvents)
	}
	if device.resetCalls != 3 || device.getAssertionCalls != 2 {
		t.Fatalf("calls = reset %d, assertion %d", device.resetCalls, device.getAssertionCalls)
	}
	if len(device.getAssertionRequests) != 2 {
		t.Fatalf("GetAssertion requests = %d, want 2", len(device.getAssertionRequests))
	}
	for index, request := range device.getAssertionRequests {
		if request.RPID != authrReset1RPID {
			t.Fatalf("GetAssertion request %d RP ID = %q, want %q", index, request.RPID, authrReset1RPID)
		}
		if len(request.AllowList) != 1 ||
			!bytes.Equal(request.AllowList[0].ID, device.fixture.credentialID) {
			t.Fatalf(
				"GetAssertion request %d allowList = %#v, want created credential ID %x",
				index,
				request.AllowList,
				device.fixture.credentialID,
			)
		}
	}
	preResetRequest := device.getAssertionRequests[0]
	postResetRequest := device.getAssertionRequests[1]
	if !bytes.Equal(preResetRequest.ClientDataHash, getAssertionFixtureClientDataHash[:]) {
		t.Fatalf("pre-reset clientDataHash = %x", preResetRequest.ClientDataHash)
	}
	if bytes.Equal(postResetRequest.ClientDataHash, preResetRequest.ClientDataHash) {
		t.Fatal("post-reset clientDataHash equals pre-reset clientDataHash")
	}
	if !bytes.Equal(postResetRequest.ClientDataHash, authrReset1PostResetClientDataHash[:]) {
		t.Fatalf("post-reset clientDataHash = %x", postResetRequest.ClientDataHash)
	}
	if postResetRequest.PinUvAuthProtocol != protocol.PinUvAuthProtocolTwo {
		t.Fatalf(
			"post-reset pinUvAuthProtocol = %d, want 2",
			postResetRequest.PinUvAuthProtocol,
		)
	}
	if !bytes.Equal(postResetRequest.PinUvAuthParam, wantPostResetHMAC) {
		t.Fatalf("post-reset pinUvAuthParam = %x, want fresh-token HMAC", postResetRequest.PinUvAuthParam)
	}
	if bytes.Equal(postResetRequest.PinUvAuthParam, stalePostResetHMAC) {
		t.Fatal("post-reset pinUvAuthParam uses the pre-reset GetAssertion token")
	}
	if countGetAssertionFixtureSteps(result.Tests[0].Steps, "make-credential-fixture.cleanup") != 1 {
		t.Fatalf("cleanup steps = %#v", result.Tests[0].Steps)
	}
}

func TestAuthrReset1ClassifiesResetAndPostResetFailures(t *testing.T) {
	transportFailure := errors.New("transport failed")
	tests := []struct {
		name                     string
		resetStatus              ctaptransport.StatusCode
		resetError               error
		postResetAssertionStatus ctaptransport.StatusCode
		postResetAssertionError  error
		want                     conformance.Status
	}{
		{name: "reset CTAP status", resetStatus: ctaptransport.CTAP2_ERR_NOT_ALLOWED, want: conformance.StatusFailed},
		{name: "reset transport", resetError: transportFailure, want: conformance.StatusError},
		{name: "credential survived reset", postResetAssertionStatus: ctaptransport.CTAP2_OK, want: conformance.StatusFailed},
		{name: "wrong post-reset status", postResetAssertionStatus: ctaptransport.CTAP2_ERR_INVALID_CBOR, want: conformance.StatusFailed},
		{name: "post-reset transport", postResetAssertionError: transportFailure, want: conformance.StatusError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			events := []string{}
			device := newAuthrReset1Device(t, &events)
			device.subjectResetStatus = tt.resetStatus
			device.subjectResetError = tt.resetError
			device.postResetAssertionStatus = tt.postResetAssertionStatus
			device.postResetAssertionError = tt.postResetAssertionError
			config := authrReset1Config(&events, authrReset1TokenProvider(t))

			result := runAuthrReset1Test(t, device, config)
			if result.Status != tt.want {
				t.Fatalf("status = %s, want %s; result = %#v", result.Status, tt.want, result)
			}
			if !slices.Equal(events[len(events)-2:], []string{"power-cycle", "reset"}) {
				t.Fatalf("cleanup events = %v", events)
			}
		})
	}
}

func TestAuthrReset1ProviderAndCleanupErrorsRemainVisible(t *testing.T) {
	t.Run("post-reset provider error wipes returned token", func(t *testing.T) {
		events := []string{}
		device := newAuthrReset1Device(t, &events)
		returned := bytes.Repeat([]byte{0x73}, 32)
		providerCalls := 0
		config := authrReset1Config(&events, func(
			_ context.Context,
			_ *client.Client,
			request PinUvAuthTokenRequest,
		) (PinUvAuthToken, error) {
			providerCalls++
			events = append(events, "token:"+request.Permission.String())
			if providerCalls == 3 {
				return PinUvAuthToken{
					Protocol: protocol.PinUvAuthProtocolTwo,
					Value:    returned,
				}, errors.New("provider failed")
			}

			return PinUvAuthToken{
				Protocol: protocol.PinUvAuthProtocolTwo,
				Value:    bytes.Repeat([]byte{byte(providerCalls)}, 32),
			}, nil
		})

		result := runAuthrReset1Test(t, device, config)
		if result.Status != conformance.StatusError {
			t.Fatalf("status = %s; result = %#v", result.Status, result)
		}
		authrReset1AssertZeroed(t, returned)
		if !slices.Equal(events[len(events)-2:], []string{"power-cycle", "reset"}) {
			t.Fatalf("cleanup events = %v", events)
		}
	})

	t.Run("cleanup error", func(t *testing.T) {
		events := []string{}
		device := newAuthrReset1Device(t, &events)
		powerCycles := 0
		config := authrReset1Config(&events, authrReset1TokenProvider(t))
		config.PowerCycler = func(context.Context) error {
			powerCycles++
			events = append(events, "power-cycle")
			if powerCycles == 4 {
				return errors.New("cleanup cycle failed")
			}

			return nil
		}

		result := runAuthrReset1Test(t, device, config)
		if result.Status != conformance.StatusError {
			t.Fatalf("status = %s; result = %#v", result.Status, result)
		}
	})

	t.Run("missing power cycle", func(t *testing.T) {
		events := []string{}
		device := newAuthrReset1Device(t, &events)
		config := authrReset1Config(&events, authrReset1TokenProvider(t))
		config.PowerCycler = nil

		result := runAuthrReset1Test(t, device, config)
		if result.Status != conformance.StatusError {
			t.Fatalf("status = %s; result = %#v", result.Status, result)
		}
		if len(events) != 0 || len(device.commands()) != 0 {
			t.Fatalf("events = %v; commands = %v", events, device.commands())
		}
	})
}

type authrReset1Device struct {
	t                        testing.TB
	events                   *[]string
	fixture                  *getAssertionFixtureDevice
	credentialAvailable      bool
	resetCalls               int
	getAssertionCalls        int
	subjectResetUsed         bool
	subjectResetStatus       ctaptransport.StatusCode
	subjectResetError        error
	postResetAssertionStatus ctaptransport.StatusCode
	postResetAssertionError  error
	getAssertionRequests     []protocol.AuthenticatorGetAssertionRequest
}

func newAuthrReset1Device(t testing.TB, events *[]string) *authrReset1Device {
	return &authrReset1Device{
		t:                        t,
		events:                   events,
		fixture:                  newGetAssertionFixtureDevice(t, events, true),
		postResetAssertionStatus: ctaptransport.CTAP2_ERR_NO_CREDENTIALS,
	}
}

func (d *authrReset1Device) CBOR(
	ctx context.Context,
	request []byte,
) (ctaptransport.CBORResponse, error) {
	d.t.Helper()
	if len(request) == 0 {
		d.t.Fatal("empty request")
	}

	switch protocol.Command(request[0]) {
	case protocol.AuthenticatorReset:
		if !bytes.Equal(request, []byte{byte(protocol.AuthenticatorReset)}) {
			d.t.Fatalf("Reset request = %x, want 07", request)
		}
		d.resetCalls++
		d.fixture.commands = append(d.fixture.commands, protocol.AuthenticatorReset)
		*d.events = append(*d.events, "reset")
		if d.credentialAvailable && !d.subjectResetUsed {
			d.subjectResetUsed = true
			if d.subjectResetError != nil {
				return ctaptransport.CBORResponse{}, d.subjectResetError
			}
			if d.subjectResetStatus != ctaptransport.CTAP2_OK {
				return ctaptransport.CBORResponse{StatusCode: d.subjectResetStatus}, nil
			}
		}
		d.credentialAvailable = false

		return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_OK}, nil
	case protocol.AuthenticatorMakeCredential:
		response, err := d.fixture.CBOR(ctx, request)
		if err == nil && response.StatusCode == ctaptransport.CTAP2_OK {
			d.credentialAvailable = true
		}

		return response, err
	case protocol.AuthenticatorGetAssertion:
		d.getAssertionCalls++
		var decoded protocol.AuthenticatorGetAssertionRequest
		if err := getInfoDecMode.Unmarshal(request[1:], &decoded); err != nil {
			d.t.Fatal(err)
		}
		d.getAssertionRequests = append(d.getAssertionRequests, decoded)

		if d.credentialAvailable {
			return d.fixture.CBOR(ctx, request)
		}
		d.fixture.commands = append(d.fixture.commands, protocol.AuthenticatorGetAssertion)
		*d.events = append(*d.events, "get-assertion")
		if d.postResetAssertionError != nil {
			return ctaptransport.CBORResponse{}, d.postResetAssertionError
		}
		if d.postResetAssertionStatus == ctaptransport.CTAP2_OK {
			return getAssertionFixtureResponse(d.t, d.fixture.credentialID), nil
		}

		return ctaptransport.CBORResponse{StatusCode: d.postResetAssertionStatus}, nil
	default:
		return d.fixture.CBOR(ctx, request)
	}
}

func (d *authrReset1Device) commands() []protocol.Command {
	return d.fixture.commands
}

func authrReset1Config(events *[]string, provider PinUvAuthTokenProvider) Config {
	return Config{
		PowerCycler: func(context.Context) error {
			*events = append(*events, "power-cycle")

			return nil
		},
		TokenProvider: func(
			ctx context.Context,
			client *client.Client,
			request PinUvAuthTokenRequest,
		) (PinUvAuthToken, error) {
			*events = append(*events, "token:"+request.Permission.String())

			return provider(ctx, client, request)
		},
	}
}

func authrReset1TokenProvider(t testing.TB) PinUvAuthTokenProvider {
	t.Helper()

	return func(
		context.Context,
		*client.Client,
		PinUvAuthTokenRequest,
	) (PinUvAuthToken, error) {
		return PinUvAuthToken{
			Protocol: protocol.PinUvAuthProtocolTwo,
			Value:    bytes.Repeat([]byte{0x81}, 32),
		}, nil
	}
}

func runAuthrReset1Test(
	t *testing.T,
	device ctaptransport.CBOR,
	config Config,
) conformance.SuiteResult {
	t.Helper()

	runner, err := conformance.NewRunner(device)
	if err != nil {
		t.Fatal(err)
	}
	result, err := runner.Run(t.Context(), conformance.Suite{
		ID:    "authr-reset-1-test",
		Name:  "Authenticator Reset 1 test",
		Tests: authrReset1Tests(config),
	})
	if err != nil {
		t.Fatal(err)
	}

	return result
}

func authrReset1HasReference(
	references []conformance.RequirementRef,
	id conformance.RequirementID,
) bool {
	return slices.ContainsFunc(references, func(reference conformance.RequirementRef) bool {
		return reference.ID == id
	})
}

func authrReset1AssertZeroed(t testing.TB, value []byte) {
	t.Helper()
	for i, b := range value {
		if b != 0 {
			t.Fatalf("byte %d was not cleared", i)
		}
	}
}
