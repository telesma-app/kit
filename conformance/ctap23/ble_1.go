package ctap23

import (
	"context"
	"slices"

	"github.com/telesma-app/kit/conformance"
)

const (
	ble1SourcePath = "tests/CTAP2/Transports/ble-1.js"

	bleDeviceInformationService = "180a"
	bleFIDOService              = "fffd"
	bleControlPoint             = "f1d0fff1deaaeceeb42fc9ba7ed623bb"
	bleStatus                   = "f1d0fff2deaaeceeb42fc9ba7ed623bb"
	bleControlPointLength       = "f1d0fff3deaaeceeb42fc9ba7ed623bb"
	bleServiceRevisionBitfield  = "f1d0fff4deaaeceeb42fc9ba7ed623bb"

	TestIDBLE1P1  conformance.TestID = "fido.ctap2.3.ble-1.p-1"
	TestIDBLE1P2  conformance.TestID = "fido.ctap2.3.ble-1.p-2"
	TestIDBLE1P3  conformance.TestID = "fido.ctap2.3.ble-1.p-3"
	TestIDBLE1P4  conformance.TestID = "fido.ctap2.3.ble-1.p-4"
	TestIDBLE1P5  conformance.TestID = "fido.ctap2.3.ble-1.p-5"
	TestIDBLE1P6  conformance.TestID = "fido.ctap2.3.ble-1.p-6"
	TestIDBLE1P7  conformance.TestID = "fido.ctap2.3.ble-1.p-7"
	TestIDBLE1P8  conformance.TestID = "fido.ctap2.3.ble-1.p-8"
	TestIDBLE1P9  conformance.TestID = "fido.ctap2.3.ble-1.p-9"
	TestIDBLE1P10 conformance.TestID = "fido.ctap2.3.ble-1.p-10"
)

type ble1Case struct {
	id     conformance.TestID
	marker string
	name   string
	run    func(context.Context, BLESession) error
	skip   string
}

func ble1Tests(config Config) []conformance.Test {
	reference := ble1Reference()
	definitions := []ble1Case{
		{TestIDBLE1P1, "P-1", "Expose the BLE Device Information service", ble1P1, ""},
		{TestIDBLE1P2, "P-2", "Expose the Generic Access service", nil, "upstream case has no executable body"},
		{TestIDBLE1P3, "P-3", "Expose the FIDO service as primary", nil, "upstream case has no executable body"},
		{TestIDBLE1P4, "P-4", "Expose the required FIDO characteristics", ble1P4, ""},
		{TestIDBLE1P5, "P-5", "Allow writes to the FIDO control point", ble1P5, ""},
		{TestIDBLE1P6, "P-6", "Allow notifications from FIDO status", ble1P6, ""},
		{TestIDBLE1P7, "P-7", "Report a valid control-point length", ble1P7, ""},
		{TestIDBLE1P8, "P-8", "Advertise the FIDO2 service revision", ble1P8, ""},
		{TestIDBLE1P9, "P-9", "Echo a single-frame BLE ping", ble1P9, ""},
		{TestIDBLE1P10, "P-10", "Report user-presence keepalives", nil, "upstream case has no executable body"},
	}

	tests := make([]conformance.Test, 0, len(definitions))
	for _, definition := range definitions {
		tests = append(tests, conformance.Test{
			ID:          definition.id,
			Name:        definition.name,
			Description: definition.name,
			Source:      conformance.SourceLocation{Path: ble1SourcePath, Case: definition.marker},
			References:  []conformance.RequirementRef{reference},
			Run: func(test *conformance.TestContext) {
				test.Step(conformance.Step{
					ID:         conformance.StepID("ble-1." + definition.marker),
					Name:       definition.name,
					References: []conformance.RequirementRef{reference},
					Run: func(ctx context.Context) error {
						if definition.skip != "" {
							return conformance.Skip(definition.skip)
						}
						if config.Transport != AuthenticatorTransportBLE {
							return conformance.Skip("case requires the BLE transport")
						}
						if config.BLESessionProvider == nil {
							return conformance.Skip("raw BLE observations are unavailable")
						}

						return config.BLESessionProvider(ctx, definition.run)
					},
				})
			},
		})
	}

	return tests
}

func ble1P1(ctx context.Context, session BLESession) error {
	services, err := session.Services(ctx)
	if err != nil {
		return err
	}
	if _, ok := services[bleDeviceInformationService]; !ok {
		return conformance.Fail("BLE Device Information service is absent")
	}

	return nil
}

func ble1P4(ctx context.Context, session BLESession) error {
	service, err := bleFIDOServiceSnapshot(ctx, session)
	if err != nil {
		return err
	}
	for _, uuid := range []string{bleControlPoint, bleStatus, bleControlPointLength, bleServiceRevisionBitfield} {
		if _, ok := service.Characteristics[uuid]; !ok {
			return conformance.Failf("FIDO BLE characteristic %s is absent", uuid)
		}
	}

	return nil
}

func ble1P5(ctx context.Context, session BLESession) error {
	return requireBLECharacteristicProperties(ctx, session, bleControlPoint, []string{"write", "writeWithoutResponse"})
}

func ble1P6(ctx context.Context, session BLESession) error {
	return requireBLECharacteristicProperties(ctx, session, bleStatus, []string{"notify"})
}

func ble1P7(ctx context.Context, session BLESession) error {
	if err := requireBLECharacteristicProperties(ctx, session, bleControlPointLength, []string{"read"}); err != nil {
		return err
	}
	length, err := session.ControlPointLength(ctx)
	if err != nil {
		return err
	}
	if length < 20 || length > 512 {
		return conformance.Failf("BLE control-point length = %d, want 20..512", length)
	}

	return nil
}

func ble1P8(ctx context.Context, session BLESession) error {
	if err := requireBLECharacteristicProperty(ctx, session, bleServiceRevisionBitfield, "read"); err != nil {
		return err
	}
	if err := requireBLECharacteristicProperty(ctx, session, bleServiceRevisionBitfield, "write"); err != nil {
		return err
	}
	value, err := session.ServiceRevisionBitfield(ctx)
	if err != nil {
		return err
	}
	if value&0x20 == 0 {
		return conformance.Failf("BLE service revision bitfield = 0x%02x, want FIDO2 bit 0x20", value)
	}

	return nil
}

func ble1P9(ctx context.Context, session BLESession) error {
	length, err := session.ControlPointLength(ctx)
	if err != nil {
		return err
	}
	if length < 20 || length > 512 {
		return conformance.Failf("BLE control-point length = %d, want 20..512", length)
	}
	payload := make([]byte, int(length)-3)
	for index := range payload {
		payload[index] = byte(index*29 + 7)
	}
	response, err := session.Ping(ctx, payload)
	if err != nil {
		return err
	}
	if !slices.Equal(response, payload) {
		return conformance.Fail("BLE ping response does not equal the request payload")
	}

	return nil
}

func bleFIDOServiceSnapshot(ctx context.Context, session BLESession) (BLEService, error) {
	services, err := session.Services(ctx)
	if err != nil {
		return BLEService{}, err
	}
	service, ok := services[bleFIDOService]
	if !ok {
		return BLEService{}, conformance.Fail("FIDO BLE service is absent")
	}

	return service, nil
}

func requireBLECharacteristicProperty(
	ctx context.Context,
	session BLESession,
	uuid string,
	property string,
) error {
	service, err := bleFIDOServiceSnapshot(ctx, session)
	if err != nil {
		return err
	}
	characteristic, ok := service.Characteristics[uuid]
	if !ok {
		return conformance.Failf("FIDO BLE characteristic %s is absent", uuid)
	}
	if !slices.Contains(characteristic.Properties, property) {
		return conformance.Failf("FIDO BLE characteristic %s lacks %q", uuid, property)
	}

	return nil
}

func requireBLECharacteristicProperties(
	ctx context.Context,
	session BLESession,
	uuid string,
	want []string,
) error {
	service, err := bleFIDOServiceSnapshot(ctx, session)
	if err != nil {
		return err
	}
	characteristic, ok := service.Characteristics[uuid]
	if !ok {
		return conformance.Failf("FIDO BLE characteristic %s is absent", uuid)
	}
	if len(characteristic.Properties) != len(want) {
		return conformance.Failf("FIDO BLE characteristic %s properties = %v, want %v", uuid, characteristic.Properties, want)
	}
	for _, property := range want {
		if !slices.Contains(characteristic.Properties, property) {
			return conformance.Failf("FIDO BLE characteristic %s properties = %v, want %v", uuid, characteristic.Properties, want)
		}
	}

	return nil
}

func ble1Reference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "ctap-2.3-ps-20260226:11.4:ble",
		Specification: "CTAP 2.3 Proposed Standard (2026-02-26)",
		URL:           "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#ble",
		Section:       "11.4",
		Clause:        "ble",
		Level:         conformance.RequirementMust,
	}
}
