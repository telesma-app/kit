package ctap23

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/telesma-app/kit/conformance"
)

type ble1TestSession struct {
	services map[string]BLEService
	length   uint16
	revision byte
	pingErr  error
	pingSeen []byte
}

func newBLE1TestSession() *ble1TestSession {
	return &ble1TestSession{
		services: map[string]BLEService{
			bleDeviceInformationService: {},
			bleFIDOService: {
				Primary: true,
				Characteristics: map[string]BLECharacteristic{
					bleControlPoint:            {Properties: []string{"write", "writeWithoutResponse"}},
					bleStatus:                  {Properties: []string{"notify"}},
					bleControlPointLength:      {Properties: []string{"read"}},
					bleServiceRevisionBitfield: {Properties: []string{"read", "write"}},
				},
			},
		},
		length:   64,
		revision: 0x20,
	}
}

func (s *ble1TestSession) Services(context.Context) (map[string]BLEService, error) {
	return s.services, nil
}

func (s *ble1TestSession) ControlPointLength(context.Context) (uint16, error) {
	return s.length, nil
}

func (s *ble1TestSession) ServiceRevisionBitfield(context.Context) (byte, error) {
	return s.revision, nil
}

func (s *ble1TestSession) Ping(_ context.Context, payload []byte) ([]byte, error) {
	s.pingSeen = slices.Clone(payload)
	if s.pingErr != nil {
		return nil, s.pingErr
	}

	return slices.Clone(payload), nil
}

func TestBLE1Definitions(t *testing.T) {
	tests := ble1Tests(Config{})
	wantIDs := []conformance.TestID{
		TestIDBLE1P1, TestIDBLE1P2, TestIDBLE1P3, TestIDBLE1P4, TestIDBLE1P5,
		TestIDBLE1P6, TestIDBLE1P7, TestIDBLE1P8, TestIDBLE1P9, TestIDBLE1P10,
	}
	if len(tests) != len(wantIDs) {
		t.Fatalf("tests = %d, want %d", len(tests), len(wantIDs))
	}
	for index, test := range tests {
		if test.ID != wantIDs[index] || test.Source.Path != ble1SourcePath {
			t.Fatalf("test %d = %#v", index, test)
		}
		if test.Source.Case == "" || len(test.References) != 1 || test.References[0].Section != "11.4" {
			t.Fatalf("test %d metadata = %#v", index, test)
		}
	}
}

func TestBLE1ActualCases(t *testing.T) {
	for index, test := range ble1Tests(Config{
		Transport: AuthenticatorTransportBLE,
		BLESessionProvider: func(ctx context.Context, run func(context.Context, BLESession) error) error {
			return run(ctx, newBLE1TestSession())
		},
	}) {
		result := runBLE1Test(t, test)
		want := conformance.StatusPassed
		if index == 1 || index == 2 || index == 9 {
			want = conformance.StatusSkipped
		}
		if result.Status != want {
			t.Fatalf("test %d = %#v, want %s", index, result, want)
		}
	}
}

func TestBLE1ApplicabilityStopsBeforeProvider(t *testing.T) {
	calls := 0
	provider := func(ctx context.Context, run func(context.Context, BLESession) error) error {
		calls++
		return run(ctx, newBLE1TestSession())
	}
	result := runBLE1Test(t, ble1Tests(Config{Transport: AuthenticatorTransportHID, BLESessionProvider: provider})[0])
	if result.Status != conformance.StatusSkipped || calls != 0 {
		t.Fatalf("wrong transport = %#v, provider calls %d", result, calls)
	}
	result = runBLE1Test(t, ble1Tests(Config{Transport: AuthenticatorTransportBLE})[0])
	if result.Status != conformance.StatusSkipped {
		t.Fatalf("missing provider = %#v", result)
	}
}

func TestBLE1RejectsInvalidObservationsAndClassifiesProviderErrors(t *testing.T) {
	cases := []struct {
		index  int
		mutate func(*ble1TestSession)
	}{
		{0, func(session *ble1TestSession) { delete(session.services, bleDeviceInformationService) }},
		{3, func(session *ble1TestSession) { delete(session.services[bleFIDOService].Characteristics, bleStatus) }},
		{4, func(session *ble1TestSession) {
			session.services[bleFIDOService].Characteristics[bleControlPoint] = BLECharacteristic{}
		}},
		{5, func(session *ble1TestSession) {
			session.services[bleFIDOService].Characteristics[bleStatus] = BLECharacteristic{}
		}},
		{4, func(session *ble1TestSession) {
			session.services[bleFIDOService].Characteristics[bleControlPoint] = BLECharacteristic{Properties: []string{"write", "writeWithoutResponse", "read"}}
		}},
		{5, func(session *ble1TestSession) {
			session.services[bleFIDOService].Characteristics[bleStatus] = BLECharacteristic{Properties: []string{"notify", "write"}}
		}},
		{6, func(session *ble1TestSession) {
			session.services[bleFIDOService].Characteristics[bleControlPointLength] = BLECharacteristic{Properties: []string{"read", "write"}}
		}},
		{6, func(session *ble1TestSession) { session.length = 19 }},
		{7, func(session *ble1TestSession) { session.revision = 0x10 }},
	}
	for _, testCase := range cases {
		testConfig := Config{
			Transport: AuthenticatorTransportBLE,
			BLESessionProvider: func(ctx context.Context, run func(context.Context, BLESession) error) error {
				session := newBLE1TestSession()
				testCase.mutate(session)
				return run(ctx, session)
			},
		}
		result := runBLE1Test(t, ble1Tests(testConfig)[testCase.index])
		if result.Status != conformance.StatusFailed {
			t.Fatalf("case %d = %#v", testCase.index, result)
		}
	}

	providerErr := errors.New("raw BLE unavailable")
	config := Config{
		Transport: AuthenticatorTransportBLE,
		BLESessionProvider: func(context.Context, func(context.Context, BLESession) error) error {
			return providerErr
		},
	}
	result := runBLE1Test(t, ble1Tests(config)[0])
	if result.Status != conformance.StatusError || result.Tests[0].Steps[0].Message != providerErr.Error() {
		t.Fatalf("provider error = %#v", result)
	}
}

func runBLE1Test(t *testing.T, test conformance.Test) conformance.SuiteResult {
	t.Helper()
	runner, err := conformance.NewRunner(authrMakeCredReq3NoIO{})
	if err != nil {
		t.Fatal(err)
	}

	result, err := runner.Run(t.Context(), conformance.Suite{ID: SuiteIDAuthenticator, Tests: []conformance.Test{test}})
	if err != nil {
		t.Fatal(err)
	}

	return result
}
