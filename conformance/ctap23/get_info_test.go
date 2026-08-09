package ctap23_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
	"github.com/telesma-app/ctap/extension"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
	"github.com/telesma-app/kit/conformance/ctap23"
)

type cborDevice struct {
	response ctaptransport.CBORResponse
	err      error
	requests [][]byte
}

func (d *cborDevice) CBOR(_ context.Context, data []byte) (ctaptransport.CBORResponse, error) {
	d.requests = append(d.requests, data)

	return d.response, d.err
}

func TestGetInfoP1PassesForMatchingCTAP23ResponseAndMetadata(t *testing.T) {
	info := validGetInfo()
	result, device := runGetInfoSuite(t, info, ctap23.Metadata{
		GetInfo:       info,
		GetInfoFields: []uint64{1, 2, 3},
	})

	if result.Status != conformance.StatusPassed {
		t.Fatalf("suite status = %q, want passed: %#v", result.Status, result.Tests)
	}
	if len(result.Tests) != 1 || result.Tests[0].Status != conformance.StatusPassed {
		t.Fatalf("tests = %#v, want one passed test", result.Tests)
	}
	if result.Tests[0].ID != ctap23.TestIDAuthrGeneric1P1 {
		t.Fatalf("test ID = %q, want %q", result.Tests[0].ID, ctap23.TestIDAuthrGeneric1P1)
	}
	if len(result.Tests[0].Steps) != 6 {
		t.Fatalf("steps = %#v, want six passed steps", result.Tests[0].Steps)
	}
	for _, step := range result.Tests[0].Steps {
		if step.Status != conformance.StatusPassed {
			t.Fatalf("step %q status = %q, want passed", step.ID, step.Status)
		}
	}
	if len(device.requests) != 1 || len(device.requests[0]) != 1 || device.requests[0][0] != byte(protocol.AuthenticatorGetInfo) {
		t.Fatalf("requests = %x, want one authenticatorGetInfo command", device.requests)
	}
}

func TestGetInfoP1ReportsCapabilityFindingAsFailure(t *testing.T) {
	info := validGetInfo()
	info.Extensions = []extension.ExtensionIdentifier{"example-extension"}
	result, _ := runGetInfoSuite(t, info, ctap23.Metadata{
		GetInfo:       info,
		GetInfoFields: []uint64{1, 2, 3},
	})

	testResult := result.Tests[0]
	if result.Status != conformance.StatusFailed || testResult.Status != conformance.StatusFailed {
		t.Fatalf("result = %#v, want failed", result)
	}
	last := testResult.Steps[len(testResult.Steps)-1]
	if last.ID != "get-info.requirements" || last.Status != conformance.StatusFailed {
		t.Fatalf("last step = %#v, want failed requirements", last)
	}
	if !strings.Contains(last.Message, string(conformance.RuleProfileHMACSecretRequired)) {
		t.Fatalf("message = %q, want hmac-secret rule", last.Message)
	}
}

func TestGetInfoP1NormalizesLegacyUvTokenForMetadataComparison(t *testing.T) {
	info := validGetInfo()
	info.Options = map[protocol.Option]bool{
		protocol.OptionUvToken:        true,
		protocol.OptionPinUvAuthToken: true,
	}
	metadataInfo := info
	metadataInfo.Options = map[protocol.Option]bool{
		protocol.OptionPinUvAuthToken: true,
	}
	result, _ := runGetInfoSuite(t, info, ctap23.Metadata{
		GetInfo:       metadataInfo,
		GetInfoFields: []uint64{1, 2, 3, 4},
	})

	if result.Status != conformance.StatusPassed {
		t.Fatalf("suite status = %q, want passed: %#v", result.Status, result.Tests)
	}
}

func TestGetInfoP1ReportsMetadataMismatchWithoutLeakingValues(t *testing.T) {
	info := validGetInfo()
	metadataInfo := info
	metadataInfo.AAGUID = uuid.MustParse("ffeeddcc-bbaa-9988-7766-554433221100")
	result, _ := runGetInfoSuite(t, info, ctap23.Metadata{
		GetInfo:       metadataInfo,
		GetInfoFields: []uint64{1, 2, 3},
	})

	testResult := result.Tests[0]
	if result.Status != conformance.StatusFailed || testResult.Status != conformance.StatusFailed {
		t.Fatalf("result = %#v, want failed", result)
	}
	last := testResult.Steps[len(testResult.Steps)-1]
	if last.ID != "get-info.metadata" || last.Message != "GetInfo field AAGUID differs from authenticator metadata" {
		t.Fatalf("metadata step = %#v", last)
	}
	if strings.Contains(last.Message, info.AAGUID.String()) || strings.Contains(last.Message, metadataInfo.AAGUID.String()) {
		t.Fatalf("metadata mismatch leaked identifier: %q", last.Message)
	}
}

func TestGetInfoP1ClassifiesTransportFailureAsExecutionError(t *testing.T) {
	device := &cborDevice{err: errors.New("device disconnected")}
	runner, err := conformance.NewRunner(device)
	if err != nil {
		t.Fatal(err)
	}

	result, err := runner.Run(context.Background(), suiteWithTest(t, ctap23.Config{
		Metadata: ctap23.Metadata{
			GetInfo:       validGetInfo(),
			GetInfoFields: []uint64{1, 2, 3},
		},
	}, ctap23.TestIDAuthrGeneric1P1))
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != conformance.StatusError || result.Tests[0].Status != conformance.StatusError {
		t.Fatalf("result = %#v, want execution error", result)
	}
	step := result.Tests[0].Steps[0]
	if step.ID != "get-info.request" || step.Status != conformance.StatusError || step.Message != "device disconnected" {
		t.Fatalf("request step = %#v", step)
	}
}

func TestGetInfoP1RejectsPresentZeroValuedOptionalField(t *testing.T) {
	info := validGetInfo()
	data := encodeCBOR(t, map[uint64]any{
		1: []string{string(protocol.FIDO_2_3)},
		2: []string{string(extension.ExtensionIdentifierHMACSecret)},
		3: info.AAGUID[:],
		5: uint64(0),
	})
	device := &cborDevice{response: ctaptransport.CBORResponse{
		StatusCode: ctaptransport.CTAP2_OK,
		Data:       data,
	}}
	runner, err := conformance.NewRunner(device)
	if err != nil {
		t.Fatal(err)
	}

	result, err := runner.Run(context.Background(), suiteWithTest(t, ctap23.Config{
		Metadata: ctap23.Metadata{
			GetInfo:       info,
			GetInfoFields: []uint64{1, 2, 3, 5},
		},
	}, ctap23.TestIDAuthrGeneric1P1))
	if err != nil {
		t.Fatal(err)
	}
	testResult := result.Tests[0]
	if testResult.Status != conformance.StatusFailed {
		t.Fatalf("test = %#v, want failed", testResult)
	}
	last := testResult.Steps[len(testResult.Steps)-1]
	if last.ID != "get-info.declared-fields" || last.Message != "maxMsgSize must be greater than zero" {
		t.Fatalf("declared-fields step = %#v", last)
	}
}

func TestGetInfoP1ForcePINChangeFalseIsEquivalentToAbsent(t *testing.T) {
	for _, test := range []struct {
		name  string
		value bool
		want  conformance.Status
	}{
		{name: "false", want: conformance.StatusPassed},
		{name: "true", value: true, want: conformance.StatusFailed},
	} {
		t.Run(test.name, func(t *testing.T) {
			info := validGetInfo()
			info.ForcePINChange = test.value
			data := encodeCBOR(t, map[uint64]any{
				1:  []string{string(protocol.FIDO_2_3)},
				2:  []string{string(extension.ExtensionIdentifierHMACSecret)},
				3:  info.AAGUID[:],
				12: test.value,
			})
			device := &cborDevice{response: ctaptransport.CBORResponse{
				StatusCode: ctaptransport.CTAP2_OK,
				Data:       data,
			}}
			runner, err := conformance.NewRunner(device)
			if err != nil {
				t.Fatal(err)
			}

			result, err := runner.Run(context.Background(), suiteWithTest(t, ctap23.Config{
				Metadata: ctap23.Metadata{
					GetInfo:       info,
					GetInfoFields: []uint64{1, 2, 3, 12},
				},
			}, ctap23.TestIDAuthrGeneric1P1))
			if err != nil {
				t.Fatal(err)
			}
			if result.Status != test.want || result.Tests[0].Status != test.want {
				t.Fatalf("result = %#v, want %q", result, test.want)
			}
			if test.value {
				last := result.Tests[0].Steps[len(result.Tests[0].Steps)-1]
				if last.ID != "get-info.declared-fields" || last.Message != "forcePINChange requires pinUvAuthProtocols" {
					t.Fatalf("declared-fields step = %#v", last)
				}
			}
		})
	}
}

func TestGetInfoP1AllowsZeroFirmwareVersion(t *testing.T) {
	info := validGetInfo()
	firmwareVersion := uint(0)
	info.FirmwareVersion = &firmwareVersion
	data := encodeCBOR(t, map[uint64]any{
		1:  []string{string(protocol.FIDO_2_3)},
		2:  []string{string(extension.ExtensionIdentifierHMACSecret)},
		3:  info.AAGUID[:],
		14: uint64(0),
	})
	device := &cborDevice{response: ctaptransport.CBORResponse{
		StatusCode: ctaptransport.CTAP2_OK,
		Data:       data,
	}}
	runner, err := conformance.NewRunner(device)
	if err != nil {
		t.Fatal(err)
	}

	result, err := runner.Run(context.Background(), suiteWithTest(t, ctap23.Config{
		Metadata: ctap23.Metadata{
			GetInfo:       info,
			GetInfoFields: []uint64{1, 2, 3, 14},
		},
	}, ctap23.TestIDAuthrGeneric1P1))
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != conformance.StatusPassed || result.Tests[0].Status != conformance.StatusPassed {
		t.Fatalf("result = %#v, want passed", result)
	}
}

func runGetInfoSuite(
	t *testing.T,
	info protocol.AuthenticatorGetInfoResponse,
	metadata ctap23.Metadata,
) (conformance.SuiteResult, *cborDevice) {
	t.Helper()

	device := &cborDevice{response: ctaptransport.CBORResponse{
		StatusCode: ctaptransport.CTAP2_OK,
		Data:       encodeCBOR(t, info),
	}}
	runner, err := conformance.NewRunner(device)
	if err != nil {
		t.Fatal(err)
	}
	result, err := runner.Run(
		context.Background(),
		suiteWithTest(t, ctap23.Config{Metadata: metadata}, ctap23.TestIDAuthrGeneric1P1),
	)
	if err != nil {
		t.Fatal(err)
	}

	return result, device
}

func suiteWithTest(t *testing.T, config ctap23.Config, testID conformance.TestID) conformance.Suite {
	t.Helper()

	suite := ctap23.Suite(config)
	for _, test := range suite.Tests {
		if test.ID == testID {
			suite.Tests = []conformance.Test{test}

			return suite
		}
	}

	t.Fatalf("suite does not contain test %q", testID)

	return conformance.Suite{}
}

func validGetInfo() protocol.AuthenticatorGetInfoResponse {
	return protocol.AuthenticatorGetInfoResponse{
		Versions:   protocol.Versions{protocol.FIDO_2_3},
		Extensions: []extension.ExtensionIdentifier{extension.ExtensionIdentifierHMACSecret},
		AAGUID:     uuid.MustParse("00112233-4455-6677-8899-aabbccddeeff"),
	}
}

func encodeCBOR(t *testing.T, value any) []byte {
	t.Helper()

	mode, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		t.Fatal(err)
	}
	data, err := mode.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}

	return data
}
