package ctap23

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/client"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
)

const authrGetAssertionReq3PresenceOnlyMetadata = `{
	"userVerificationDetails": [[{"userVerificationMethod": "presence_internal"}]]
}`

func TestAuthrGetAssertionReq3Definitions(t *testing.T) {
	want := []struct {
		id         conformance.TestID
		marker     string
		references []conformance.RequirementRef
	}{
		{
			id:     TestIDAuthrGetAssertionReq3P1,
			marker: "P-1",
			references: []conformance.RequirementRef{
				authrGetAssertionReq1CommandReference(),
				authrGetAssertionReq1ParameterReference("allow-list-optional-array"),
				authrGetAssertionReq3UnknownCredentialTypeReference(),
				authrGetAssertionReq1ResponseCredentialReference(),
			},
		},
		{
			id:         TestIDAuthrGetAssertionReq3F1,
			marker:     "F-1",
			references: authrGetAssertionReq3MalformedReferences(),
		},
		{
			id:         TestIDAuthrGetAssertionReq3F2,
			marker:     "F-2",
			references: authrGetAssertionReq3MalformedReferences(),
		},
		{
			id:         TestIDAuthrGetAssertionReq3F3,
			marker:     "F-3",
			references: authrGetAssertionReq3MalformedReferences(),
		},
		{
			id:         TestIDAuthrGetAssertionReq3F4,
			marker:     "F-4",
			references: authrGetAssertionReq3MalformedReferences(),
		},
		{
			id:         TestIDAuthrGetAssertionReq3F5,
			marker:     "F-5",
			references: authrGetAssertionReq3MalformedReferences(),
		},
		{
			id:     TestIDAuthrGetAssertionReq3F6,
			marker: "F-6",
			references: slices.Concat(
				[]conformance.RequirementRef{authrGetAssertionReq1CommandReference()},
				authrGetAssertionReq3F6References(
					authrGetAssertionReq1ParameterReference("allow-list-optional-array"),
				),
			),
		},
	}

	tests := authrGetAssertionReq3Tests(Config{})
	if len(tests) != len(want) {
		t.Fatalf("tests = %d, want %d", len(tests), len(want))
	}

	for index, test := range tests {
		if test.ID != want[index].id || test.Source.Path != authrGetAssertionReq3SourcePath ||
			test.Source.Case != want[index].marker || !test.Destructive {
			t.Fatalf("test %d = %#v", index, test)
		}
		if !slices.Equal(test.References, want[index].references) {
			t.Fatalf(
				"references for %s = %#v, want %#v",
				test.ID,
				test.References,
				want[index].references,
			)
		}
	}
}

func TestAuthrGetAssertionReq3CasesPassWithExactStatus(t *testing.T) {
	cases := []struct {
		id     conformance.TestID
		marker string
		status ctaptransport.StatusCode
	}{
		{TestIDAuthrGetAssertionReq3P1, "P-1", ctaptransport.CTAP2_OK},
		{TestIDAuthrGetAssertionReq3F1, "F-1", ctaptransport.CTAP2_ERR_CBOR_UNEXPECTED_TYPE},
		{TestIDAuthrGetAssertionReq3F2, "F-2", ctaptransport.CTAP2_ERR_CBOR_UNEXPECTED_TYPE},
		{TestIDAuthrGetAssertionReq3F3, "F-3", ctaptransport.CTAP2_ERR_CBOR_UNEXPECTED_TYPE},
		{TestIDAuthrGetAssertionReq3F4, "F-4", ctaptransport.CTAP2_ERR_CBOR_UNEXPECTED_TYPE},
		{TestIDAuthrGetAssertionReq3F5, "F-5", ctaptransport.CTAP2_ERR_CBOR_UNEXPECTED_TYPE},
		{TestIDAuthrGetAssertionReq3F6, "F-6", ctaptransport.CTAP2_ERR_NO_CREDENTIALS},
	}

	for _, testCase := range cases {
		t.Run(testCase.marker, func(t *testing.T) {
			device := newAuthrGetAssertionReq1Device(t)
			device.getAssertionStatus = testCase.status
			lifecycle := &authrGetAssertionReq3Lifecycle{t: t}

			result := runAuthrGetAssertionReq3Test(
				t,
				device,
				lifecycle.config(authrGetAssertionReq3PresenceOnlyMetadata),
				testCase.id,
			)

			assertAuthrGetAssertionReq3Status(t, result, conformance.StatusPassed)
			assertAuthrGetAssertionReq3Lifecycle(t, device, lifecycle)
			assertAuthrGetAssertionReq3WireMutation(t, testCase.marker, device.getAssertionRequest)
		})
	}
}

func TestAuthrGetAssertionReq3MalformedCasesRequireExactStatus(t *testing.T) {
	for _, id := range []conformance.TestID{
		TestIDAuthrGetAssertionReq3F1,
		TestIDAuthrGetAssertionReq3F2,
		TestIDAuthrGetAssertionReq3F3,
		TestIDAuthrGetAssertionReq3F4,
		TestIDAuthrGetAssertionReq3F5,
		TestIDAuthrGetAssertionReq3F6,
	} {
		for _, testCase := range []struct {
			name   string
			status ctaptransport.StatusCode
		}{
			{name: "success", status: ctaptransport.CTAP2_OK},
			{name: "different CTAP status", status: ctaptransport.CTAP2_ERR_INVALID_CBOR},
		} {
			t.Run(string(id)+"/"+testCase.name, func(t *testing.T) {
				device := newAuthrGetAssertionReq1Device(t)
				device.getAssertionStatus = testCase.status
				lifecycle := &authrGetAssertionReq3Lifecycle{t: t}

				result := runAuthrGetAssertionReq3Test(
					t,
					device,
					lifecycle.config(authrGetAssertionReq3PresenceOnlyMetadata),
					id,
				)

				assertAuthrGetAssertionReq3Status(t, result, conformance.StatusFailed)
				assertAuthrGetAssertionReq3Lifecycle(t, device, lifecycle)
			})
		}
	}
}

func TestAuthrGetAssertionReq3PositiveRequiresSuccessAndCreatedCredential(t *testing.T) {
	t.Run("CTAP error", func(t *testing.T) {
		device := newAuthrGetAssertionReq1Device(t)
		device.getAssertionStatus = ctaptransport.CTAP2_ERR_NO_CREDENTIALS
		lifecycle := &authrGetAssertionReq3Lifecycle{t: t}

		result := runAuthrGetAssertionReq3Test(
			t,
			device,
			lifecycle.config(authrGetAssertionReq3PresenceOnlyMetadata),
			TestIDAuthrGetAssertionReq3P1,
		)

		assertAuthrGetAssertionReq3Status(t, result, conformance.StatusFailed)
		assertAuthrGetAssertionReq3Lifecycle(t, device, lifecycle)
	})

	t.Run("different credential ID", func(t *testing.T) {
		device := newAuthrGetAssertionReq1Device(t)
		device.responseCredentialID = []byte{0xff}
		lifecycle := &authrGetAssertionReq3Lifecycle{t: t}

		result := runAuthrGetAssertionReq3Test(
			t,
			device,
			lifecycle.config(authrGetAssertionReq3PresenceOnlyMetadata),
			TestIDAuthrGetAssertionReq3P1,
		)

		assertAuthrGetAssertionReq3Status(t, result, conformance.StatusFailed)
		assertAuthrGetAssertionReq3Lifecycle(t, device, lifecycle)
		if got := result.Tests[0].Steps[1].Message; got !=
			"authenticatorGetAssertion returned a different credential ID" {
			t.Fatalf("message = %q", got)
		}
	})
}

func TestAuthrGetAssertionReq3F6ValidNonmatchingMetadataSkipsBeforeDeviceUse(t *testing.T) {
	cases := []struct {
		name      string
		statement string
	}{
		{
			name: "different registered method",
			statement: `{
				"userVerificationDetails": [[{"userVerificationMethod": "fingerprint_internal"}]]
			}`,
		},
		{
			name: "two alternatives",
			statement: `{
				"userVerificationDetails": [
					[{"userVerificationMethod": "presence_internal"}],
					[{"userVerificationMethod": "fingerprint_internal"}]
				]
			}`,
		},
		{
			name: "two descriptors",
			statement: `{
				"userVerificationDetails": [[
					{"userVerificationMethod": "presence_internal"},
					{"userVerificationMethod": "fingerprint_internal"}
				]]
			}`,
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			device := newAuthrGetAssertionReq1Device(t)

			result := runAuthrGetAssertionReq3Test(
				t,
				device,
				Config{Metadata: Metadata{StatementJSON: testCase.statement}},
				TestIDAuthrGetAssertionReq3F6,
			)

			assertAuthrGetAssertionReq3Status(t, result, conformance.StatusSkipped)
			if len(device.commands) != 0 {
				t.Fatalf("commands = %v, want none", device.commands)
			}
		})
	}
}

func TestAuthrGetAssertionReq3F6MissingOrMalformedMetadataErrorsBeforeDeviceUse(t *testing.T) {
	cases := []struct {
		name      string
		statement string
	}{
		{name: "missing statement"},
		{name: "malformed statement", statement: "{"},
		{name: "missing userVerificationDetails", statement: `{}`},
		{name: "non-array userVerificationDetails", statement: `{"userVerificationDetails": {}}`},
		{name: "empty userVerificationDetails", statement: `{"userVerificationDetails": []}`},
		{name: "non-array alternative", statement: `{"userVerificationDetails": ["presence_internal"]}`},
		{name: "empty alternative", statement: `{"userVerificationDetails": [[]]}`},
		{name: "non-object descriptor", statement: `{"userVerificationDetails": [[true]]}`},
		{name: "missing method", statement: `{"userVerificationDetails": [[{}]]}`},
		{name: "wrong-typed method", statement: `{"userVerificationDetails": [[{"userVerificationMethod": 1}]]}`},
		{name: "unregistered method", statement: `{"userVerificationDetails": [[{"userVerificationMethod": "unknown"}]]}`},
		{name: "invalid registered method", statement: `{"userVerificationDetails": [[{"userVerificationMethod": "all"}]]}`},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			device := newAuthrGetAssertionReq1Device(t)

			result := runAuthrGetAssertionReq3Test(
				t,
				device,
				Config{Metadata: Metadata{StatementJSON: testCase.statement}},
				TestIDAuthrGetAssertionReq3F6,
			)

			assertAuthrGetAssertionReq3Status(t, result, conformance.StatusError)
			if len(device.commands) != 0 {
				t.Fatalf("commands = %v, want none", device.commands)
			}
		})
	}
}

func TestAuthrGetAssertionReq3F6DoesNotUseMetadataBitmask(t *testing.T) {
	device := newAuthrGetAssertionReq1Device(t)

	result := runAuthrGetAssertionReq3Test(
		t,
		device,
		Config{Metadata: Metadata{UserVerificationMethods: protocol.UserVerifyPresenceInternal}},
		TestIDAuthrGetAssertionReq3F6,
	)

	assertAuthrGetAssertionReq3Status(t, result, conformance.StatusError)
	if len(device.commands) != 0 {
		t.Fatalf("commands = %v, want none", device.commands)
	}
}

func TestAuthrGetAssertionReq3TransportErrorIsExecutionError(t *testing.T) {
	transportFailure := errors.New("device disconnected")
	device := newAuthrGetAssertionReq1Device(t)
	device.getAssertionError = transportFailure
	lifecycle := &authrGetAssertionReq3Lifecycle{t: t}

	result := runAuthrGetAssertionReq3Test(
		t,
		device,
		lifecycle.config(authrGetAssertionReq3PresenceOnlyMetadata),
		TestIDAuthrGetAssertionReq3F3,
	)

	assertAuthrGetAssertionReq3Status(t, result, conformance.StatusError)
	assertAuthrGetAssertionReq3Lifecycle(t, device, lifecycle)
	if got := result.Tests[0].Steps[1].Message; got != transportFailure.Error() {
		t.Fatalf("action error = %q", got)
	}
}

func TestAuthrGetAssertionReq3CleanupErrorIsVisibleAndTokensAreWiped(t *testing.T) {
	cleanupFailure := errors.New("cleanup power cycle failed")
	device := newAuthrGetAssertionReq1Device(t)
	lifecycle := &authrGetAssertionReq3Lifecycle{t: t, cleanupFailure: cleanupFailure}

	result := runAuthrGetAssertionReq3Test(
		t,
		device,
		lifecycle.config(authrGetAssertionReq3PresenceOnlyMetadata),
		TestIDAuthrGetAssertionReq3P1,
	)

	assertAuthrGetAssertionReq3Status(t, result, conformance.StatusError)
	assertAuthrGetAssertionReq3TokensWiped(t, lifecycle.tokens)
	if lifecycle.powerCycles != 3 || device.resets != 1 {
		t.Fatalf("power cycles/resets = %d/%d, want 3/1", lifecycle.powerCycles, device.resets)
	}
	steps := result.Tests[0].Steps
	last := steps[len(steps)-1]
	if last.ID != "make-credential-fixture.cleanup" || last.Status != conformance.StatusError ||
		last.Message != cleanupFailure.Error() {
		t.Fatalf("cleanup = %#v", last)
	}
}

type authrGetAssertionReq3Lifecycle struct {
	t              testing.TB
	powerCycles    int
	tokens         [][]byte
	cleanupFailure error
}

func (l *authrGetAssertionReq3Lifecycle) config(statement string) Config {
	return Config{
		Metadata: Metadata{StatementJSON: statement},
		PowerCycler: func(context.Context) error {
			l.powerCycles++
			if l.powerCycles == 3 && l.cleanupFailure != nil {
				return l.cleanupFailure
			}

			return nil
		},
		TokenProvider: func(
			_ context.Context,
			_ *client.Client,
			request PinUvAuthTokenRequest,
		) (PinUvAuthToken, error) {
			wantPermissions := []protocol.Permission{
				protocol.PermissionMakeCredential,
				protocol.PermissionGetAssertion,
			}
			if len(l.tokens) >= len(wantPermissions) ||
				request.Permission != wantPermissions[len(l.tokens)] ||
				request.RPID != authrGetAssertionReq3RPID {
				l.t.Fatalf("token request %d = %#v", len(l.tokens), request)
			}
			if len(l.tokens) == 1 &&
				slices.ContainsFunc(l.tokens[0], func(value byte) bool { return value != 0 }) {
				l.t.Fatal("MakeCredential token was not wiped before GetAssertion authorization")
			}

			token := bytes.Repeat([]byte{byte(0x73 + len(l.tokens))}, 32)
			l.tokens = append(l.tokens, token)

			return PinUvAuthToken{
				Protocol: protocol.PinUvAuthProtocolTwo,
				Value:    token,
			}, nil
		},
	}
}

func runAuthrGetAssertionReq3Test(
	t *testing.T,
	device *authrGetAssertionReq1Device,
	config Config,
	id conformance.TestID,
) conformance.SuiteResult {
	t.Helper()

	var selected conformance.Test
	for _, test := range authrGetAssertionReq3Tests(config) {
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
		ID:    "authr-get-assertion-req-3-test",
		Name:  "Authr GetAssertion Req 3 test",
		Tests: []conformance.Test{selected},
	})
	if err != nil {
		t.Fatal(err)
	}

	return result
}

func assertAuthrGetAssertionReq3WireMutation(t *testing.T, marker string, request []byte) {
	t.Helper()
	if len(request) == 0 || protocol.Command(request[0]) != protocol.AuthenticatorGetAssertion {
		t.Fatalf("request = %x", request)
	}

	var fields map[uint64]cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(request[1:], &fields); err != nil {
		t.Fatal(err)
	}

	wantFields := 5
	if marker == "F-6" {
		wantFields = 4
	}
	if len(fields) != wantFields {
		t.Fatalf("fields = %#v, want %d entries", fields, wantFields)
	}
	for _, key := range []uint64{1, 2, 6, 7} {
		if _, present := fields[key]; !present {
			t.Fatalf("field %d is absent", key)
		}
	}
	allowListRaw, present := fields[3]
	if marker == "F-6" {
		if present {
			t.Fatalf("allowList = %x, want absent", allowListRaw)
		}

		return
	}
	if !present {
		t.Fatal("allowList is absent")
	}

	var allowList []cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(allowListRaw, &allowList); err != nil {
		t.Fatal(err)
	}
	if len(allowList) != 2 {
		t.Fatalf("allowList = %x, want two descriptors", allowListRaw)
	}
	assertAuthrGetAssertionReq3ValidDescriptor(t, allowList[0])

	if marker == "F-1" {
		if allowList[1][0]>>5 == 5 {
			t.Fatalf("second allowList member = %x, want non-map", allowList[1])
		}

		return
	}

	var descriptor map[string]cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(allowList[1], &descriptor); err != nil {
		t.Fatal(err)
	}
	switch marker {
	case "P-1":
		assertAuthrGetAssertionReq3DescriptorField(
			t,
			descriptor,
			"type",
			3,
			"ctap23-unknown-credential-type",
		)
		assertAuthrGetAssertionReq3DescriptorField(
			t,
			descriptor,
			"id",
			2,
			bytes.Repeat([]byte{0xa3}, 32),
		)
	case "F-2":
		if _, present := descriptor["type"]; present {
			t.Fatalf("descriptor = %#v, want missing type", descriptor)
		}
		assertAuthrGetAssertionReq3DescriptorField(
			t,
			descriptor,
			"id",
			2,
			bytes.Repeat([]byte{0xa3}, 32),
		)
	case "F-3":
		assertAuthrGetAssertionReq3DescriptorField(t, descriptor, "type", 0, uint64(7))
		assertAuthrGetAssertionReq3DescriptorField(
			t,
			descriptor,
			"id",
			2,
			bytes.Repeat([]byte{0xa3}, 32),
		)
	case "F-4":
		assertAuthrGetAssertionReq3DescriptorField(t, descriptor, "type", 3, "public-key")
		if _, present := descriptor["id"]; present {
			t.Fatalf("descriptor = %#v, want missing id", descriptor)
		}
	case "F-5":
		assertAuthrGetAssertionReq3DescriptorField(t, descriptor, "type", 3, "public-key")
		assertAuthrGetAssertionReq3DescriptorField(t, descriptor, "id", 3, "not-a-byte-string")
	default:
		t.Fatalf("unknown marker %q", marker)
	}
}

func assertAuthrGetAssertionReq3ValidDescriptor(t testing.TB, raw cbor.RawMessage) {
	t.Helper()

	var descriptor map[string]cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(raw, &descriptor); err != nil {
		t.Fatal(err)
	}
	assertAuthrGetAssertionReq3DescriptorField(t, descriptor, "type", 3, "public-key")

	credentialID, present := descriptor["id"]
	if !present || len(credentialID) == 0 || credentialID[0]>>5 != 2 {
		t.Fatalf("descriptor id = %x, want byte string", credentialID)
	}
}

func assertAuthrGetAssertionReq3DescriptorField(
	t testing.TB,
	descriptor map[string]cbor.RawMessage,
	name string,
	majorType byte,
	want any,
) {
	t.Helper()

	raw, present := descriptor[name]
	if !present || len(raw) == 0 || raw[0]>>5 != majorType {
		t.Fatalf("descriptor %s = %x, want CBOR major type %d", name, raw, majorType)
	}

	var got any
	if err := getInfoDecMode.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if !authrGetAssertionReq3EqualWireValue(got, want) {
		t.Fatalf("descriptor %s = %#v, want %#v", name, got, want)
	}
}

func authrGetAssertionReq3EqualWireValue(got, want any) bool {
	gotBytes, gotIsBytes := got.([]byte)
	wantBytes, wantIsBytes := want.([]byte)
	if gotIsBytes || wantIsBytes {
		return gotIsBytes && wantIsBytes && bytes.Equal(gotBytes, wantBytes)
	}

	return got == want
}

func assertAuthrGetAssertionReq3Lifecycle(
	t *testing.T,
	device *authrGetAssertionReq1Device,
	lifecycle *authrGetAssertionReq3Lifecycle,
) {
	t.Helper()

	if lifecycle.powerCycles != 3 || device.resets != 2 || device.makeCredentialRequests != 1 {
		t.Fatalf(
			"power cycles/resets/MakeCredential = %d/%d/%d, want 3/2/1",
			lifecycle.powerCycles,
			device.resets,
			device.makeCredentialRequests,
		)
	}
	if !slices.Equal(device.commands, []protocol.Command{
		protocol.AuthenticatorReset,
		protocol.AuthenticatorGetInfo,
		protocol.AuthenticatorMakeCredential,
		protocol.AuthenticatorGetAssertion,
		protocol.AuthenticatorReset,
	}) {
		t.Fatalf("commands = %v", device.commands)
	}
	assertAuthrGetAssertionReq3TokensWiped(t, lifecycle.tokens)
}

func assertAuthrGetAssertionReq3TokensWiped(t testing.TB, tokens [][]byte) {
	t.Helper()

	if len(tokens) != 2 {
		t.Fatalf("tokens = %d, want 2", len(tokens))
	}
	for index, token := range tokens {
		if len(token) != 32 || slices.ContainsFunc(token, func(value byte) bool { return value != 0 }) {
			t.Fatalf("token %d was not wiped", index)
		}
	}
}

func assertAuthrGetAssertionReq3Status(
	t *testing.T,
	result conformance.SuiteResult,
	want conformance.Status,
) {
	t.Helper()

	if result.Status != want || len(result.Tests) != 1 || result.Tests[0].Status != want {
		t.Fatalf("result = %#v, want %s", result, want)
	}
}

func authrGetAssertionReq3MalformedReferences() []conformance.RequirementRef {
	return []conformance.RequirementRef{
		authrGetAssertionReq1CommandReference(),
		authrGetAssertionReq1ParameterReference("allow-list-optional-array"),
		authrGetAssertionReq3CredentialDescriptorReference(),
		authrGetAssertionReq3MalformedStructureReference(),
	}
}
