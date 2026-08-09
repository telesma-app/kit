package ctap23

import (
	"context"
	"encoding/binary"
	"errors"
	"slices"
	"testing"
	"time"

	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/ctap/transport/ctaphid"
	"github.com/telesma-app/kit/conformance"
)

type hid1TestSession struct {
	queue          []HIDMessage
	nextCID        byte
	pendingCID     ctaphid.ChannelID
	lockedCID      ctaphid.ChannelID
	malformedBusy  bool
	providerWrites int
}

func newHID1TestSession() *hid1TestSession {
	return &hid1TestSession{nextCID: 1}
}

func (s *hid1TestSession) WriteReports(_ context.Context, reports []HIDReport) error {
	s.providerWrites++
	if len(reports) == 0 {
		return errors.New("empty report sequence")
	}
	if reports[0][5]&0x80 == 0 {
		return nil
	}
	if len(reports) > 1 && reports[len(reports)-1][5]&0x80 != 0 {
		message, _ := decodeHID1TestReports(reports[len(reports)-1:])
		s.handle(message)
		return nil
	}
	message, invalidSequence := decodeHID1TestReports(reports)
	if invalidSequence {
		s.queue = append(s.queue, hid1Error(message.CID, ctaphid.ERR_INVALID_SEQ))
		return nil
	}
	s.handle(message)
	return nil
}

func (s *hid1TestSession) ReadMessage(context.Context, time.Duration) (HIDMessage, bool, error) {
	if len(s.queue) == 0 {
		return HIDMessage{}, false, nil
	}
	message := s.queue[0]
	s.queue = s.queue[1:]
	return message, true, nil
}

func (s *hid1TestSession) handle(message HIDMessage) {
	switch message.Command {
	case ctaphid.CTAPHID_INIT:
		if message.CID == hidCIDZero {
			s.queue = append(s.queue, hid1Error(message.CID, ctaphid.ERR_INVALID_CHANNEL))
			return
		}
		if s.lockedCID != hidCIDZero && message.CID != s.lockedCID {
			response := hid1Error(message.CID, ctaphid.ERR_CHANNEL_BUSY)
			if s.malformedBusy {
				response.DeclaredLength = 2
			}
			s.queue = append(s.queue, response)
			return
		}
		cid := message.CID
		if message.CID == ctaphid.BROADCAST_CID {
			cid = ctaphid.ChannelID{s.nextCID, 2, 3, 4}
			s.nextCID++
		}
		payload := make([]byte, 17)
		copy(payload, message.Payload)
		copy(payload[8:12], cid[:])
		payload[12] = hidInitVersion
		payload[16] = byte(ctaphid.CAPABILITY_WINK | ctaphid.CAPABILITY_CBOR)
		s.queue = append(s.queue, HIDMessage{CID: message.CID, Command: ctaphid.CTAPHID_INIT, DeclaredLength: 17, Payload: payload})
	case ctaphid.CTAPHID_PING:
		if message.CID == hidCIDZero || message.CID == ctaphid.BROADCAST_CID {
			s.queue = append(s.queue, hid1Error(message.CID, ctaphid.ERR_INVALID_CHANNEL))
			return
		}
		s.queue = append(s.queue, HIDMessage{CID: message.CID, Command: message.Command, DeclaredLength: uint16(len(message.Payload)), Payload: slices.Clone(message.Payload)})
	case ctaphid.CTAPHID_WINK:
		s.queue = append(s.queue, HIDMessage{CID: message.CID, Command: message.Command})
	case ctaphid.CTAPHID_LOCK:
		if len(message.Payload) != 1 {
			s.queue = append(s.queue, hid1Error(message.CID, ctaphid.ERR_INVALID_LEN))
			return
		}
		if message.Payload[0] == 0 {
			s.lockedCID = hidCIDZero
		} else {
			s.lockedCID = message.CID
		}
		s.queue = append(s.queue, HIDMessage{CID: message.CID, Command: message.Command})
	case ctaphid.CTAPHID_CBOR:
		s.pendingCID = message.CID
		s.queue = append(s.queue, HIDMessage{CID: message.CID, Command: ctaphid.CTAPHID_KEEPALIVE, DeclaredLength: 1, Payload: []byte{byte(ctaphid.STATUS_UPNEEDED)}})
	case ctaphid.CTAPHID_CANCEL:
		if s.pendingCID == message.CID {
			s.queue = append(s.queue, HIDMessage{CID: message.CID, Command: ctaphid.CTAPHID_CBOR, DeclaredLength: 1, Payload: []byte{byte(ctaptransport.CTAP2_ERR_KEEPALIVE_CANCEL)}})
			s.pendingCID = hidCIDZero
		}
	default:
		s.queue = append(s.queue, hid1Error(message.CID, ctaphid.ERR_INVALID_CMD))
	}
}

func decodeHID1TestReports(reports []HIDReport) (HIDMessage, bool) {
	var cid ctaphid.ChannelID
	copy(cid[:], reports[0][1:5])
	message := HIDMessage{
		CID:            cid,
		Command:        ctaphid.Command(reports[0][5] & 0x7f),
		DeclaredLength: binary.BigEndian.Uint16(reports[0][6:8]),
	}
	remaining := int(message.DeclaredLength)
	first := min(remaining, 57)
	message.Payload = append(message.Payload, reports[0][8:8+first]...)
	remaining -= first
	for index, report := range reports[1:] {
		if report[5] != byte(index) {
			return message, true
		}
		count := min(remaining, 59)
		message.Payload = append(message.Payload, report[6:6+count]...)
		remaining -= count
		if remaining == 0 {
			break
		}
	}

	return message, false
}

func hid1Error(cid ctaphid.ChannelID, code ctaphid.Error) HIDMessage {
	return HIDMessage{CID: cid, Command: ctaphid.CTAPHID_ERROR, DeclaredLength: 1, Payload: []byte{byte(code)}}
}

func TestHID1Definitions(t *testing.T) {
	tests := hid1Tests(Config{})
	want := []conformance.TestID{
		TestIDHID1P1, TestIDHID1P2, TestIDHID1P3, TestIDHID1P4, TestIDHID1P5,
		TestIDHID1P6, TestIDHID1P7, TestIDHID1P8, TestIDHID1P9, TestIDHID1P10,
		TestIDHID1P11, TestIDHID1P12, TestIDHID1P13, TestIDHID1P14, TestIDHID1P15,
		TestIDHID1F1, TestIDHID1F2, TestIDHID1F3, TestIDHID1F4,
	}
	if len(tests) != len(want) {
		t.Fatalf("tests = %d, want %d", len(tests), len(want))
	}
	for index, test := range tests {
		if test.ID != want[index] || test.Source.Path != hid1SourcePath || test.Source.Case == "" || len(test.References) != 1 || test.References[0].Section != "11.2" {
			t.Fatalf("test %d = %#v", index, test)
		}
	}
}

func TestHID1ActualCases(t *testing.T) {
	for index := range hid1Tests(Config{}) {
		device := newEnterpriseAttestationTestDevice(t, SecurityProfileConsumer)
		session := newHID1TestSession()
		config := device.config()
		config.Transport = AuthenticatorTransportHID
		config.HIDSessionProvider = func(ctx context.Context, run func(context.Context, HIDSession) error) error {
			return run(ctx, session)
		}
		result := runHID1Test(t, device, hid1Tests(config)[index])
		want := conformance.StatusPassed
		if index == 10 {
			want = conformance.StatusSkipped
		}
		if result.Status != want {
			t.Fatalf("test %d = %#v, want %s", index, result, want)
		}
		device.assertWiped(t)
	}
}

func TestHID1ApplicabilityStopsBeforeRawProvider(t *testing.T) {
	calls := 0
	config := Config{
		Transport: AuthenticatorTransportNFC,
		HIDSessionProvider: func(ctx context.Context, run func(context.Context, HIDSession) error) error {
			calls++
			return run(ctx, newHID1TestSession())
		},
	}
	device := newEnterpriseAttestationTestDevice(t, SecurityProfileConsumer)
	result := runHID1Test(t, device, hid1Tests(config)[0])
	if result.Status != conformance.StatusSkipped || calls != 0 {
		t.Fatalf("wrong transport = %#v, calls %d", result, calls)
	}
	config.Transport = AuthenticatorTransportHID
	config.HIDSessionProvider = nil
	result = runHID1Test(t, device, hid1Tests(config)[0])
	if result.Status != conformance.StatusSkipped {
		t.Fatalf("missing provider = %#v", result)
	}
}

func TestHIDReportEncodingBoundariesAndSnapshots(t *testing.T) {
	cid := ctaphid.ChannelID{1, 2, 3, 4}
	for _, length := range []int{0, 57, 58, 1024, 7609} {
		payload := hidDeterministicBytes(length, byte(length))
		reports, err := encodeHIDReports(cid, ctaphid.CTAPHID_PING, payload)
		if err != nil {
			t.Fatalf("length %d: %v", length, err)
		}
		decoded, invalid := decodeHID1TestReports(reports)
		if invalid || decoded.CID != cid || decoded.Command != ctaphid.CTAPHID_PING || !slices.Equal(decoded.Payload, payload) {
			t.Fatalf("length %d decoded = %#v invalid %t", length, decoded, invalid)
		}
		if len(reports) > 1 {
			copyOfFirst := reports[0]
			reports[1][6] ^= 0xff
			if reports[0] != copyOfFirst {
				t.Fatal("report mutation aliased another report")
			}
		}
	}
	if _, err := encodeHIDReports(cid, ctaphid.CTAPHID_PING, make([]byte, 7610)); err == nil {
		t.Fatal("oversized HID payload accepted")
	}
}

func TestHID1ClassifiesRawProviderErrors(t *testing.T) {
	providerErr := errors.New("raw HID lease failed")
	device := newEnterpriseAttestationTestDevice(t, SecurityProfileConsumer)
	config := device.config()
	config.Transport = AuthenticatorTransportHID
	config.HIDSessionProvider = func(context.Context, func(context.Context, HIDSession) error) error { return providerErr }
	result := runHID1Test(t, device, hid1Tests(config)[0])
	if result.Status != conformance.StatusError || result.Tests[0].Steps[0].Message != providerErr.Error() {
		t.Fatalf("provider error = %#v", result)
	}
}

func TestValidateHIDInitAcceptsFutureExtensionBytes(t *testing.T) {
	nonce := hidDeterministicBytes(8, 91)
	cid := ctaphid.ChannelID{1, 2, 3, 4}
	payload := make([]byte, 18)
	copy(payload, nonce)
	copy(payload[8:12], cid[:])
	payload[12] = hidInitVersion
	payload[16] = byte(ctaphid.CAPABILITY_CBOR)
	payload[17] = 0xa5

	got, err := validateHIDInit(HIDMessage{
		CID:            ctaphid.BROADCAST_CID,
		Command:        ctaphid.CTAPHID_INIT,
		DeclaredLength: uint16(len(payload)),
		Payload:        payload,
	}, ctaphid.BROADCAST_CID, nonce)
	if err != nil || got != cid {
		t.Fatalf("validateHIDInit() = %v, %v", got, err)
	}
}

func TestHID1P14UnlocksAfterAssertionFailure(t *testing.T) {
	session := newHID1TestSession()
	session.malformedBusy = true
	err := hid1P14(t.Context(), nil, Config{}, session)
	if err == nil {
		t.Fatal("malformed channel-busy response accepted")
	}
	if session.lockedCID != hidCIDZero {
		t.Fatalf("locked CID after failure = %v", session.lockedCID)
	}
}

func TestHIDIsErrorRequiresExactChannelAndLength(t *testing.T) {
	cid := ctaphid.ChannelID{1, 2, 3, 4}
	response := hid1Error(cid, ctaphid.ERR_CHANNEL_BUSY)
	if !hidIsError(response, cid, ctaphid.ERR_CHANNEL_BUSY) {
		t.Fatal("canonical CTAPHID_ERROR rejected")
	}
	response.CID[0]++
	if hidIsError(response, cid, ctaphid.ERR_CHANNEL_BUSY) {
		t.Fatal("wrong-channel CTAPHID_ERROR accepted")
	}
	response = hid1Error(cid, ctaphid.ERR_CHANNEL_BUSY)
	response.DeclaredLength = 2
	if hidIsError(response, cid, ctaphid.ERR_CHANNEL_BUSY) {
		t.Fatal("wrong-length CTAPHID_ERROR accepted")
	}
}

func runHID1Test(
	t *testing.T,
	device *enterpriseAttestationTestDevice,
	test conformance.Test,
) conformance.SuiteResult {
	t.Helper()
	runner, err := conformance.NewRunner(device)
	if err != nil {
		t.Fatal(err)
	}
	result, err := runner.Run(t.Context(), conformance.Suite{ID: "hid-1-test", Tests: []conformance.Test{test}})
	if err != nil {
		t.Fatal(err)
	}

	return result
}
