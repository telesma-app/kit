package ctapkit

import (
	"errors"
	"testing"

	"github.com/telesma-app/kit/model/report"
	"github.com/telesma-app/token2"
)

func TestToken2PIVATRIsAvailableWithoutVendorIdentity(t *testing.T) {
	raw := []byte{0x3b, 0x8f, 0x80, 0x01, 0x54, 0x4b, 0x00, 0x50, 0x49, 0x56, 0x04, 0x02, 0x38, 0x38, 0x38, 0x38, 0x38, 0x38, 0x38, 0x60}
	atr, err := token2.ParseATR(raw)

	info := token2.DeviceInfo{
		SerialNumber: token2.Descriptor[string]{Value: new("66103930925563")},
		ATR:          token2.Descriptor[token2.ATR]{Value: &atr, Err: err},
	}
	for _, cleanup := range []error{nil, errors.New("close failed")} {
		source := token2Source(info, errors.Join(err, cleanup))

		reading := source.Data.ATR
		if reading.Value == nil || reading.Value.Identity != nil || reading.Error != nil || string(reading.Value.Raw) != string(raw) {
			t.Fatalf("ATR = %#v", reading)
		}

		if cleanup == nil && (source.State != report.SourceAvailable || source.Error != nil) {
			t.Fatalf("unexpected failure = %#v", source.Outcome)
		}

		if cleanup != nil && (source.State != report.SourcePartial || source.Error == nil) {
			t.Fatalf("cleanup error lost = %#v", source.Outcome)
		}
	}
}

func TestToken2MalformedATRRemainsFailed(t *testing.T) {
	_, err := token2.ParseATR([]byte{0x3b, 0xff})

	source := token2Source(token2.DeviceInfo{ATR: token2.Descriptor[token2.ATR]{Err: err}}, err)
	if source.State != report.SourceFailed || source.Data.ATR.Value != nil || source.Data.ATR.Error == nil {
		t.Fatalf("malformed ATR = %#v", source)
	}
}
