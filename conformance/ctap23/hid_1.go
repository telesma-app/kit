package ctap23

import (
	"context"
	"encoding/binary"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/ctap/transport/ctaphid"
	"github.com/telesma-app/kit/conformance"
)

const (
	hid1SourcePath = "tests/CTAP2/Transports/hid-1.js"
	hidInitVersion = 2

	TestIDHID1P1  conformance.TestID = "fido.ctap2.3.hid-1.p-1"
	TestIDHID1P2  conformance.TestID = "fido.ctap2.3.hid-1.p-2"
	TestIDHID1P3  conformance.TestID = "fido.ctap2.3.hid-1.p-3"
	TestIDHID1P4  conformance.TestID = "fido.ctap2.3.hid-1.p-4"
	TestIDHID1P5  conformance.TestID = "fido.ctap2.3.hid-1.p-5"
	TestIDHID1P6  conformance.TestID = "fido.ctap2.3.hid-1.p-6"
	TestIDHID1P7  conformance.TestID = "fido.ctap2.3.hid-1.p-7"
	TestIDHID1P8  conformance.TestID = "fido.ctap2.3.hid-1.p-8"
	TestIDHID1P9  conformance.TestID = "fido.ctap2.3.hid-1.p-9"
	TestIDHID1P10 conformance.TestID = "fido.ctap2.3.hid-1.p-10"
	TestIDHID1P11 conformance.TestID = "fido.ctap2.3.hid-1.p-11"
	TestIDHID1P12 conformance.TestID = "fido.ctap2.3.hid-1.p-12"
	TestIDHID1P13 conformance.TestID = "fido.ctap2.3.hid-1.p-13"
	TestIDHID1P14 conformance.TestID = "fido.ctap2.3.hid-1.p-14"
	TestIDHID1P15 conformance.TestID = "fido.ctap2.3.hid-1.p-15"
	TestIDHID1F1  conformance.TestID = "fido.ctap2.3.hid-1.f-1"
	TestIDHID1F2  conformance.TestID = "fido.ctap2.3.hid-1.f-2"
	TestIDHID1F3  conformance.TestID = "fido.ctap2.3.hid-1.f-3"
	TestIDHID1F4  conformance.TestID = "fido.ctap2.3.hid-1.f-4"
)

var hidCIDZero ctaphid.ChannelID

type hid1Case struct {
	id          conformance.TestID
	marker      string
	name        string
	run         func(context.Context, *conformance.TestContext, Config, HIDSession) error
	skip        string
	destructive bool
}

func hid1Tests(config Config) []conformance.Test {
	reference := hid1Reference()
	definitions := slices.Concat(hid1FirstCases(), hid1TailCases())

	tests := make([]conformance.Test, 0, len(definitions))
	for _, definition := range definitions {
		definition := definition
		tests = append(tests, conformance.Test{
			ID:          definition.id,
			Name:        definition.name,
			Description: definition.name,
			Source:      conformance.SourceLocation{Path: hid1SourcePath, Case: definition.marker},
			References:  []conformance.RequirementRef{reference},
			Destructive: definition.destructive,
			Run: func(test *conformance.TestContext) {
				test.Step(conformance.Step{
					ID:         conformance.StepID("hid-1." + strings.ToLower(definition.marker)),
					Name:       definition.name,
					References: []conformance.RequirementRef{reference},
					Run: func(ctx context.Context) error {
						if definition.skip != "" {
							return conformance.Skip(definition.skip)
						}
						if config.Transport != AuthenticatorTransportHID {
							return conformance.Skip("case requires the HID transport")
						}
						if config.HIDSessionProvider == nil {
							return conformance.Skip("raw HID observations are unavailable")
						}
						if definition.id == TestIDHID1P9 || definition.id == TestIDHID1P10 {
							return runHIDMakeCredentialTransportCase(
								ctx,
								test,
								config,
								definition.id == TestIDHID1P10,
							)
						}

						return config.HIDSessionProvider(ctx, func(sessionCtx context.Context, session HIDSession) error {
							return definition.run(sessionCtx, test, config, session)
						})
					},
				})
			},
		})
	}

	return tests
}

func hid1P1(ctx context.Context, _ *conformance.TestContext, _ Config, session HIDSession) error {
	_, received, err := session.ReadMessage(ctx, 3*time.Second)
	if err != nil {
		return err
	}
	if received {
		return conformance.Fail("authenticator sent HID data while idle")
	}

	return nil
}

func hid1P2(ctx context.Context, _ *conformance.TestContext, _ Config, session HIDSession) error {
	var report HIDReport
	report[1], report[2], report[3], report[4] = 0x10, 0x20, 0x30, 0x40
	report[5] = 0
	for index := 6; index < len(report); index++ {
		report[index] = byte(index*37 + 11)
	}
	if err := session.WriteReports(ctx, []HIDReport{report}); err != nil {
		return err
	}
	_, received, err := session.ReadMessage(ctx, time.Second)
	if err != nil {
		return err
	}
	if received {
		return conformance.Fail("authenticator responded to an unsolicited continuation report")
	}

	return nil
}

func hid1P3(ctx context.Context, _ *conformance.TestContext, _ Config, session HIDSession) error {
	nonce := hidDeterministicBytes(8, 3)
	response, err := hidExchange(ctx, session, ctaphid.BROADCAST_CID, ctaphid.CTAPHID_INIT, nonce)
	if err != nil {
		return err
	}
	_, err = validateHIDInit(response, ctaphid.BROADCAST_CID, nonce)

	return err
}

func hid1P4(ctx context.Context, _ *conformance.TestContext, _ Config, session HIDSession) error {
	seen := make(map[ctaphid.ChannelID]struct{}, 3)
	for index := 0; index < 3; index++ {
		nonce := hidDeterministicBytes(8, byte(index+11))
		response, err := hidExchange(ctx, session, ctaphid.BROADCAST_CID, ctaphid.CTAPHID_INIT, nonce)
		if err != nil {
			return err
		}
		cid, err := validateHIDInit(response, ctaphid.BROADCAST_CID, nonce)
		if err != nil {
			return err
		}
		if _, duplicate := seen[cid]; duplicate {
			return conformance.Fail("CTAPHID_INIT allocated a duplicate channel")
		}
		seen[cid] = struct{}{}
	}

	return nil
}

func hid1P5(ctx context.Context, _ *conformance.TestContext, _ Config, session HIDSession) error {
	return hidPing(ctx, session, 50, false)
}

func hid1P6(ctx context.Context, _ *conformance.TestContext, _ Config, session HIDSession) error {
	return hidPing(ctx, session, 1024, false)
}

func hid1P7(ctx context.Context, _ *conformance.TestContext, _ Config, session HIDSession) error {
	cid, err := hidAllocateChannel(ctx, session, 21)
	if err != nil {
		return err
	}
	reports, err := encodeHIDReports(cid, ctaphid.CTAPHID_PING, hidDeterministicBytes(512, 22))
	if err != nil {
		return err
	}
	reports = reports[:len(reports)-1]
	nonce := hidDeterministicBytes(8, 23)
	initReports, err := encodeHIDReports(cid, ctaphid.CTAPHID_INIT, nonce)
	if err != nil {
		return err
	}
	reports = append(reports, initReports[0])
	if err := session.WriteReports(ctx, reports); err != nil {
		return err
	}
	response, received, err := session.ReadMessage(ctx, time.Second)
	if err != nil {
		return err
	}
	if !received {
		return conformance.Fail("CTAPHID_INIT did not abort the incomplete PING")
	}
	_, err = validateHIDInit(response, cid, nonce)

	return err
}

func hid1P8(ctx context.Context, _ *conformance.TestContext, _ Config, session HIDSession) error {
	return hidPing(ctx, session, 1024, true)
}

func hid1P9(ctx context.Context, session HIDSession, payload []byte) error {
	cid, err := hidAllocateChannel(ctx, session, 31)
	if err != nil {
		return err
	}
	if err := hidWriteMessage(ctx, session, cid, ctaphid.CTAPHID_CBOR, payload); err != nil {
		return err
	}
	if err := hidReadKeepalive(ctx, session, cid); err != nil {
		return err
	}
	if err := hidWriteMessage(ctx, session, cid, ctaphid.CTAPHID_CANCEL, nil); err != nil {
		return err
	}

	return hidReadCancelled(ctx, session, cid)
}

func hid1P10(ctx context.Context, session HIDSession, payload []byte) error {
	cid, err := hidAllocateChannel(ctx, session, 41)
	if err != nil {
		return err
	}
	if err := hidWriteMessage(ctx, session, cid, ctaphid.CTAPHID_CBOR, payload); err != nil {
		return err
	}
	if err := hidReadKeepalive(ctx, session, cid); err != nil {
		return err
	}
	if err := hidWriteMessage(ctx, session, cid, ctaphid.CTAPHID_CANCEL, nil); err != nil {
		return err
	}
	if err := hidReadCancelled(ctx, session, cid); err != nil {
		return err
	}
	if err := hidWriteMessage(ctx, session, cid, ctaphid.CTAPHID_CANCEL, nil); err != nil {
		return err
	}
	_, received, err := session.ReadMessage(ctx, 400*time.Millisecond)
	if err != nil {
		return err
	}
	if received {
		return conformance.Fail("a second CTAPHID_CANCEL received a response")
	}

	return nil
}

func runHIDMakeCredentialTransportCase(
	ctx context.Context,
	test *conformance.TestContext,
	config Config,
	cancel bool,
) error {
	if config.PowerCycler == nil {
		return errors.New("ctap23: authenticator power cycler is required for HID MakeCredential transport cases")
	}
	test.Cleanup(residentKeyCleanupStep(test, config))
	if err := residentKeyResetAndRebind(ctx, test, config); err != nil {
		return err
	}
	payload, err := hidMakeCredentialPayload(ctx, test, config)
	if err != nil {
		return err
	}
	defer clear(payload)

	return config.HIDSessionProvider(ctx, func(sessionCtx context.Context, session HIDSession) error {
		if cancel {
			return hid1P10(sessionCtx, session, payload)
		}

		return hid1P9(sessionCtx, session, payload)
	})
}

func hid1P12(ctx context.Context, _ *conformance.TestContext, _ Config, session HIDSession) error {
	cid, capabilities, err := hidAllocateChannelWithCapabilities(ctx, session, 51)
	if err != nil {
		return err
	}
	if capabilities&byte(ctaphid.CAPABILITY_WINK) == 0 {
		return conformance.Skip("CTAPHID_WINK is not advertised")
	}
	response, err := hidExchange(ctx, session, cid, ctaphid.CTAPHID_WINK, nil)
	if err != nil {
		return err
	}
	return requireHIDResponse(response, cid, ctaphid.CTAPHID_WINK, nil)
}

func hid1P13(ctx context.Context, _ *conformance.TestContext, _ Config, session HIDSession) error {
	cid, err := hidAllocateChannel(ctx, session, 61)
	if err != nil {
		return err
	}
	response, err := hidExchange(ctx, session, cid, ctaphid.CTAPHID_LOCK, []byte{0})
	if err != nil {
		return err
	}
	if hidIsError(response, cid, ctaphid.ERR_INVALID_CMD) {
		return conformance.Skip("CTAPHID_LOCK is not implemented")
	}
	return requireHIDResponse(response, cid, ctaphid.CTAPHID_LOCK, nil)
}

func hid1P14(ctx context.Context, _ *conformance.TestContext, _ Config, session HIDSession) (resultErr error) {
	cid, err := hidAllocateChannel(ctx, session, 71)
	if err != nil {
		return err
	}
	lock, err := hidExchange(ctx, session, cid, ctaphid.CTAPHID_LOCK, []byte{8})
	if err != nil {
		return err
	}
	if hidIsError(lock, cid, ctaphid.ERR_INVALID_CMD) {
		return conformance.Skip("CTAPHID_LOCK is not implemented")
	}
	if err := requireHIDResponse(lock, cid, ctaphid.CTAPHID_LOCK, nil); err != nil {
		return err
	}
	locked := true
	defer func() {
		if !locked {
			return
		}
		unlock, err := hidExchange(ctx, session, cid, ctaphid.CTAPHID_LOCK, []byte{0})
		if err == nil {
			err = requireHIDResponse(unlock, cid, ctaphid.CTAPHID_LOCK, nil)
		}
		if resultErr == nil {
			resultErr = err
		}
	}()
	other := cid
	other[0]++
	nonce := hidDeterministicBytes(8, 72)
	busy, err := hidExchange(ctx, session, other, ctaphid.CTAPHID_INIT, nonce)
	if err != nil {
		return err
	}
	if !hidIsError(busy, other, ctaphid.ERR_CHANNEL_BUSY) {
		return conformance.Fail("locked channel did not reject another channel with ERR_CHANNEL_BUSY")
	}
	unlock, err := hidExchange(ctx, session, cid, ctaphid.CTAPHID_LOCK, []byte{0})
	if err != nil {
		return err
	}
	if err := requireHIDResponse(unlock, cid, ctaphid.CTAPHID_LOCK, nil); err != nil {
		return err
	}
	locked = false
	after, err := hidExchange(ctx, session, other, ctaphid.CTAPHID_INIT, nonce)
	if err != nil {
		return err
	}
	_, err = validateHIDInit(after, other, nonce)

	return err
}

func hid1P15(ctx context.Context, _ *conformance.TestContext, _ Config, session HIDSession) error {
	cid, err := hidAllocateChannel(ctx, session, 81)
	if err != nil {
		return err
	}
	if err := hidWriteMessage(ctx, session, cid, ctaphid.CTAPHID_CBOR, []byte{byte(protocol.AuthenticatorSelection)}); err != nil {
		return err
	}
	if err := hidReadKeepalive(ctx, session, cid); err != nil {
		return err
	}
	if err := hidWriteMessage(ctx, session, cid, ctaphid.CTAPHID_CANCEL, nil); err != nil {
		return err
	}
	if err := hidReadCancelled(ctx, session, cid); err != nil {
		return err
	}
	if err := hidWriteMessage(ctx, session, cid, ctaphid.CTAPHID_CANCEL, nil); err != nil {
		return err
	}
	_, received, err := session.ReadMessage(ctx, 400*time.Millisecond)
	if err != nil {
		return err
	}
	if received {
		return conformance.Fail("a second CTAPHID_CANCEL received a response")
	}

	return nil
}

func hid1F1(ctx context.Context, _ *conformance.TestContext, _ Config, session HIDSession) error {
	cid, err := hidAllocateChannel(ctx, session, 91)
	if err != nil {
		return err
	}
	response, err := hidExchange(ctx, session, cid, ctaphid.Command(0x20), nil)
	if err != nil {
		return err
	}
	return requireHIDError(response, cid, ctaphid.ERR_INVALID_CMD)
}

func hid1F2(ctx context.Context, _ *conformance.TestContext, _ Config, session HIDSession) error {
	response, err := hidExchange(ctx, session, hidCIDZero, ctaphid.CTAPHID_INIT, hidDeterministicBytes(8, 101))
	if err != nil {
		return err
	}
	return requireHIDError(response, hidCIDZero, ctaphid.ERR_INVALID_CHANNEL)
}

func hid1F3(ctx context.Context, _ *conformance.TestContext, _ Config, session HIDSession) error {
	response, err := hidExchange(ctx, session, ctaphid.BROADCAST_CID, ctaphid.CTAPHID_PING, nil)
	if err != nil {
		return err
	}
	return requireHIDError(response, ctaphid.BROADCAST_CID, ctaphid.ERR_INVALID_CHANNEL)
}

func hid1F4(ctx context.Context, _ *conformance.TestContext, _ Config, session HIDSession) error {
	cid, err := hidAllocateChannel(ctx, session, 111)
	if err != nil {
		return err
	}
	reports, err := encodeHIDReports(cid, ctaphid.CTAPHID_PING, hidDeterministicBytes(1024, 112))
	if err != nil {
		return err
	}
	reports[2][5]++
	if err := session.WriteReports(ctx, reports); err != nil {
		return err
	}
	response, received, err := session.ReadMessage(ctx, time.Second)
	if err != nil {
		return err
	}
	if !received {
		return conformance.Fail("out-of-order continuation received no CTAPHID_ERROR")
	}
	return requireHIDError(response, cid, ctaphid.ERR_INVALID_SEQ)
}

func hidPing(ctx context.Context, session HIDSession, size int, leadingZero bool) error {
	cid, err := hidAllocateChannel(ctx, session, byte(size))
	if err != nil {
		return err
	}
	payload := hidDeterministicBytes(size, byte(size>>2))
	if leadingZero {
		payload[0] = 0
	}
	response, err := hidExchange(ctx, session, cid, ctaphid.CTAPHID_PING, payload)
	if err != nil {
		return err
	}
	return requireHIDResponse(response, cid, ctaphid.CTAPHID_PING, payload)
}

func hidAllocateChannel(ctx context.Context, session HIDSession, seed byte) (ctaphid.ChannelID, error) {
	cid, _, err := hidAllocateChannelWithCapabilities(ctx, session, seed)
	return cid, err
}

func hidAllocateChannelWithCapabilities(
	ctx context.Context,
	session HIDSession,
	seed byte,
) (ctaphid.ChannelID, byte, error) {
	nonce := hidDeterministicBytes(8, seed)
	response, err := hidExchange(ctx, session, ctaphid.BROADCAST_CID, ctaphid.CTAPHID_INIT, nonce)
	if err != nil {
		return ctaphid.ChannelID{}, 0, err
	}
	cid, err := validateHIDInit(response, ctaphid.BROADCAST_CID, nonce)
	if err != nil {
		return ctaphid.ChannelID{}, 0, err
	}

	return cid, response.Payload[16], nil
}

func validateHIDInit(
	response HIDMessage,
	requestCID ctaphid.ChannelID,
	nonce []byte,
) (ctaphid.ChannelID, error) {
	if response.CID != requestCID || response.Command != ctaphid.CTAPHID_INIT || response.DeclaredLength != uint16(len(response.Payload)) || len(response.Payload) < 17 {
		return ctaphid.ChannelID{}, conformance.Fail("CTAPHID_INIT response has invalid CID, command, or length")
	}
	if !slices.Equal(response.Payload[:8], nonce) {
		return ctaphid.ChannelID{}, conformance.Fail("CTAPHID_INIT response nonce does not match")
	}
	var cid ctaphid.ChannelID
	copy(cid[:], response.Payload[8:12])
	if cid == hidCIDZero || cid == ctaphid.BROADCAST_CID {
		return ctaphid.ChannelID{}, conformance.Fail("CTAPHID_INIT allocated a reserved channel")
	}
	if response.Payload[12] != hidInitVersion {
		return ctaphid.ChannelID{}, conformance.Failf("CTAPHID protocol version = %d, want %d", response.Payload[12], hidInitVersion)
	}
	capabilities := response.Payload[16]
	allowed := byte(ctaphid.CAPABILITY_WINK | ctaphid.CAPABILITY_CBOR | ctaphid.CAPABILITY_NMSG)
	if capabilities&^allowed != 0 || capabilities&byte(ctaphid.CAPABILITY_CBOR) == 0 {
		return ctaphid.ChannelID{}, conformance.Failf("CTAPHID capabilities = 0x%02x", capabilities)
	}

	return cid, nil
}

func hidExchange(
	ctx context.Context,
	session HIDSession,
	cid ctaphid.ChannelID,
	command ctaphid.Command,
	payload []byte,
) (HIDMessage, error) {
	if err := hidWriteMessage(ctx, session, cid, command, payload); err != nil {
		return HIDMessage{}, err
	}
	response, received, err := session.ReadMessage(ctx, time.Second)
	if err != nil {
		return HIDMessage{}, err
	}
	if !received {
		return HIDMessage{}, conformance.Fail("CTAPHID command received no response")
	}

	return response, nil
}

func hidWriteMessage(
	ctx context.Context,
	session HIDSession,
	cid ctaphid.ChannelID,
	command ctaphid.Command,
	payload []byte,
) error {
	reports, err := encodeHIDReports(cid, command, payload)
	if err != nil {
		return err
	}

	return session.WriteReports(ctx, reports)
}

func encodeHIDReports(cid ctaphid.ChannelID, command ctaphid.Command, payload []byte) ([]HIDReport, error) {
	if len(payload) > 7609 {
		return nil, errors.New("ctap23: CTAPHID payload exceeds 7609 bytes")
	}
	reportCount := 1
	if len(payload) > 57 {
		reportCount += (len(payload) - 57 + 58) / 59
	}
	reports := make([]HIDReport, reportCount)
	copy(reports[0][1:5], cid[:])
	reports[0][5] = byte(command) | 0x80
	binary.BigEndian.PutUint16(reports[0][6:8], uint16(len(payload)))
	offset := copy(reports[0][8:], payload)
	for index := 1; index < len(reports); index++ {
		copy(reports[index][1:5], cid[:])
		reports[index][5] = byte(index - 1)
		offset += copy(reports[index][6:], payload[offset:])
	}

	return reports, nil
}

func requireHIDResponse(
	response HIDMessage,
	cid ctaphid.ChannelID,
	command ctaphid.Command,
	payload []byte,
) error {
	if response.CID != cid || response.Command != command || int(response.DeclaredLength) != len(payload) || !slices.Equal(response.Payload, payload) {
		return conformance.Fail("CTAPHID response does not match its request")
	}

	return nil
}

func requireHIDError(response HIDMessage, cid ctaphid.ChannelID, code ctaphid.Error) error {
	if response.CID != cid || response.Command != ctaphid.CTAPHID_ERROR || response.DeclaredLength != 1 || len(response.Payload) != 1 || response.Payload[0] != byte(code) {
		return conformance.Failf("CTAPHID error response = %#v, want %s", response, code)
	}

	return nil
}

func hidIsError(response HIDMessage, cid ctaphid.ChannelID, code ctaphid.Error) bool {
	return response.CID == cid && response.Command == ctaphid.CTAPHID_ERROR && response.DeclaredLength == 1 && len(response.Payload) == 1 && response.Payload[0] == byte(code)
}

func hidReadKeepalive(ctx context.Context, session HIDSession, cid ctaphid.ChannelID) error {
	response, received, err := session.ReadMessage(ctx, time.Second)
	if err != nil {
		return err
	}
	if !received || response.CID != cid || response.Command != ctaphid.CTAPHID_KEEPALIVE || response.DeclaredLength != 1 || len(response.Payload) != 1 {
		return conformance.Fail("pending command did not return a one-byte CTAPHID_KEEPALIVE")
	}
	status := ctaphid.KeepaliveStatusCode(response.Payload[0])
	if status != ctaphid.STATUS_PROCESSING && status != ctaphid.STATUS_UPNEEDED {
		return conformance.Failf("CTAPHID_KEEPALIVE status = 0x%02x", response.Payload[0])
	}

	return nil
}

func hidReadCancelled(ctx context.Context, session HIDSession, cid ctaphid.ChannelID) error {
	for attempts := 0; attempts < 20; attempts++ {
		response, received, err := session.ReadMessage(ctx, 400*time.Millisecond)
		if err != nil {
			return err
		}
		if !received {
			continue
		}
		if response.Command == ctaphid.CTAPHID_KEEPALIVE {
			if err := hidValidateKeepaliveMessage(response, cid); err != nil {
				return err
			}
			continue
		}
		if response.CID != cid || response.Command != ctaphid.CTAPHID_CBOR || response.DeclaredLength != 1 || len(response.Payload) != 1 || ctaptransport.StatusCode(response.Payload[0]) != ctaptransport.CTAP2_ERR_KEEPALIVE_CANCEL {
			return conformance.Fail("CTAPHID_CANCEL did not complete with CTAP2_ERR_KEEPALIVE_CANCEL")
		}

		return nil
	}

	return conformance.Fail("CTAPHID_CANCEL received no final response")
}

func hidValidateKeepaliveMessage(response HIDMessage, cid ctaphid.ChannelID) error {
	if response.CID != cid || response.DeclaredLength != 1 || len(response.Payload) != 1 {
		return conformance.Fail("CTAPHID_KEEPALIVE has invalid CID or length")
	}
	status := ctaphid.KeepaliveStatusCode(response.Payload[0])
	if status != ctaphid.STATUS_PROCESSING && status != ctaphid.STATUS_UPNEEDED {
		return conformance.Fail("CTAPHID_KEEPALIVE has an invalid status")
	}

	return nil
}

func hidMakeCredentialPayload(
	ctx context.Context,
	test *conformance.TestContext,
	config Config,
) ([]byte, error) {
	request, err := prepareAuthorizedMakeCredentialRequest(ctx, test, config, "hid-1.ctap23-conformance.example")
	if err != nil {
		return nil, err
	}
	defer clearAuthorizedMakeCredentialRequest(&request)
	body, err := ctap2EncMode.Marshal(request)
	if err != nil {
		return nil, err
	}

	return append([]byte{byte(protocol.AuthenticatorMakeCredential)}, body...), nil
}

func hidDeterministicBytes(length int, seed byte) []byte {
	value := make([]byte, length)
	for index := range value {
		value[index] = byte(int(seed) + index*31)
	}

	return value
}

func hid1Reference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "ctap-2.3-ps-20260226:11.2:usb-hid",
		Specification: "CTAP 2.3 Proposed Standard (2026-02-26)",
		URL:           "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#usb-hid",
		Section:       "11.2",
		Clause:        "usb-hid",
		Level:         conformance.RequirementMust,
	}
}
