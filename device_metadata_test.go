package ctapkit

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/iso7816"
	rtauthenticator "github.com/telesma-app/kit/internal/authenticator"
	"github.com/telesma-app/kit/model/report"
	"github.com/telesma-app/kit/transport"
	"github.com/telesma-app/pcsc"
	"github.com/telesma-app/token2"
	token2pcsc "github.com/telesma-app/token2/transport/pcsc"
	yubicopcsc "github.com/telesma-app/yubico/transport/pcsc"
)

func TestToken2SerialSurvivesConfigurationFailure(t *testing.T) {
	info := token2.DeviceInfo{SerialNumber: token2.Descriptor[string]{Value: new("1234")}, Configuration: token2.Descriptor[token2.Configuration]{Err: token2.ErrInvalidConfiguration}}

	source := token2Source(info, token2.ErrInvalidConfiguration)
	if source.State != report.SourcePartial || source.Error == nil || source.Data.SerialNumber.Value != info.SerialNumber.Value || source.Data.Configuration.Error == nil || source.Data.Configuration.Error.Message != token2.ErrInvalidConfiguration.Error() {
		t.Fatalf("source = %#v", source)
	}
}

func TestJoinedSourceErrorsDoNotHideFailures(t *testing.T) {
	for _, err := range []error{
		errors.Join(errors.New("identity unavailable"), errors.New("enumeration failed")),
		errors.Join(token2pcsc.ErrOTPApplicationNotAvailable, &ctaptransport.IOError{Operation: ctaptransport.IOTransmit, Err: errors.New("card removed")}),
	} {
		if outcome := sourceOutcome(err); outcome.State != report.SourceFailed || outcome.Error == nil {
			t.Fatalf("outcome = %#v", outcome)
		}
	}
}

type borrowedCard struct {
	active       bool
	events       []string
	closes       int
	selectStatus byte
	ctapStatus   byte
	endStatus    byte
	endErr       error
}

func (c *borrowedCard) Close() error {
	c.closes++
	return nil
}

func (c *borrowedCard) BeginTransaction(context.Context) error {
	c.active = true
	c.events = append(c.events, "begin")

	return nil
}
func (c *borrowedCard) EndTransaction(pcsc.Disposition) error {
	c.active = false
	c.events = append(c.events, "end")

	return c.endErr
}
func (c *borrowedCard) Status() (*pcsc.CardStatus, error) {
	return &pcsc.CardStatus{ATR: []byte{0x3b, 0xff, 0x18, 0, 0, 0x10, 0x80, 0x86, 0x8e, 0, 0x16, 0x60, 0, 0x60, '1', '2', '3', '4', '5', '6', '7', '8'}}, nil
}
func (c *borrowedCard) Transmit(_ context.Context, apdu []byte) ([]byte, error) {
	if !c.active {
		return nil, errors.New("APDU outside transaction")
	}

	c.events = append(c.events, "command")

	switch apdu[1] {
	case 0xa4:
		if bytes.Contains(apdu, []byte{0xa0, 0, 0, 6, 0x47, 0x2f, 0, 1}) {
			c.events[len(c.events)-1] = "select-fido"
			if c.selectStatus != 0 {
				return []byte{c.selectStatus, 0x82}, nil
			}

			return append([]byte("FIDO_2_0"), 0x90, 0), nil
		}

		return []byte{0x90, 0}, nil
	case 0x10:
		c.events[len(c.events)-1] = fmt.Sprintf("ctap:%02x", apdu[5])
		return []byte{c.ctapStatus, 0x90, 0}, nil
	case 0x12:
		c.events[len(c.events)-1] = "end-fido"
		if c.endStatus != 0 {
			return []byte{c.endStatus, 0}, nil
		}

		return []byte{0x90, 0}, nil
	case 0x1d:
		return append(yubicoInfoPayload(), 0x90, 0), nil
	case 0x33:
		return []byte{0xd1, 4, '1', '2', '3', '4', 0x90, 0}, nil
	default:
		return []byte{0x6d, 0}, nil
	}
}

func TestSmartCardReadsBorrowOneManagementTransaction(t *testing.T) {
	card := &borrowedCard{}
	owner := &rtauthenticator.SmartCard{Card: card}

	t.Cleanup(func() { _ = owner.Close() })

	opened := &rtauthenticator.Opened{Card: owner}

	sources, err := readSmartCardSources(t.Context(), newAttachment(smartCardCandidate("reader", 1)), opened)
	if err != nil {
		t.Fatal(err)
	}

	if card.active || card.events[0] != "begin" || card.events[len(card.events)-1] != "end" || slices.Contains(card.events, "select-fido") || card.closes != 0 {
		t.Fatalf("transaction order = %v, closes = %d", card.events, card.closes)
	}

	if sources.yubico.Data == nil || sources.token2.State != report.SourceUnsupported {
		t.Fatalf("partial management = %#v", sources)
	}
}

func TestSmartCardToken2ReportRetainsReadErrorsAfterCleanupFailure(t *testing.T) {
	cleanupErr := errors.New("end transaction failed")
	card := &borrowedCard{endErr: cleanupErr}
	owner := &rtauthenticator.SmartCard{Card: card}

	t.Cleanup(func() { _ = owner.Close() })

	target := newAttachment(smartCardCandidate("reader", 1))
	target.report.Sources.Token2 = identitySources(report.DeviceIdentity{Vendor: report.VendorToken2, SerialNumber: "1234"}).token2

	sources, err := readSmartCardSources(t.Context(), target, &rtauthenticator.Opened{Card: owner})

	if !errors.Is(err, cleanupErr) {
		t.Fatalf("management error = %v, want cleanup failure", err)
	}

	if sources.token2.State != report.SourcePartial || sources.token2.Error == nil {
		t.Fatalf("Token2 outcome = %#v, want partial failure", sources.token2.Outcome)
	}

	data := sources.token2.Data
	if data.SerialNumber.Value == nil || *data.SerialNumber.Value != "1234" || data.SerialNumber.Error != nil {
		t.Fatalf("serial reading = %#v, want successful value", data.SerialNumber)
	}

	if data.Configuration.Error == nil || !strings.Contains(data.Configuration.Error.Message, "read Token2 configuration") {
		t.Fatalf("configuration failure was replaced: %#v", data.Configuration)
	}

	if card.active || card.closes != 1 {
		t.Fatalf("card active = %v, closes = %d", card.active, card.closes)
	}
}

func TestUnsupportedGetInfoSource(t *testing.T) {
	outcome := sourceOutcome(&ctaptransport.CTAPError{StatusCode: ctaptransport.CTAP1_ERR_INVALID_COMMAND})
	if outcome.State != report.SourceUnsupported {
		t.Fatalf("GetInfo outcome = %#v", outcome)
	}
}

func TestToken2PartialValuesRetainLibraryData(t *testing.T) {
	cleanupErr := errors.New("transaction cleanup failed")

	config, err := token2.ParseConfiguration([]byte{0, 0x04, 0, 0, 0, 0, 2, 1, 0, 0x11})
	if err != nil {
		t.Fatal(err)
	}

	model := &token2.Model{Release: "R3.2", FormFactor: "Bio3 Dual A+C PIN+", Branding: "Token2"}
	info := token2.DeviceInfo{SerialNumber: token2.Descriptor[string]{Value: new("72103654095303"), Err: cleanupErr}, Configuration: token2.Descriptor[token2.Configuration]{Value: &config, Err: cleanupErr}, Model: model}

	source := token2Source(info, cleanupErr)
	if source.State != report.SourcePartial || source.Data.SerialNumber.Value != info.SerialNumber.Value || source.Data.Configuration.Value != &config || source.Data.Model != model || source.Data.Configuration.Error == nil || source.Data.Configuration.Error.Message != cleanupErr.Error() {
		t.Fatal("library values or failure were replaced")
	}
}

func TestMissingManagementApplicationWithUnsupportedSelect(t *testing.T) {
	err := fmt.Errorf("%w: %w", yubicopcsc.ErrManagementApplicationNotAvailable, &iso7816.APDUError{SW1: 0x6d})
	if got := sourceOutcome(err); got.State != report.SourceAbsent {
		t.Fatalf("missing management applet = %#v", got)
	}

	if got := sourceOutcome(errors.Join(err, errors.New("end transaction failed"))); got.State != report.SourceFailed {
		t.Fatalf("cleanup error was hidden: %#v", got)
	}
}

func TestSmartCardInterface(t *testing.T) {
	tests := []struct {
		name  string
		value pcsc.CardInterface
		want  transport.SmartCardInterface
	}{
		{
			name:  "contact",
			value: pcsc.CardInterfaceContact,
			want:  transport.SmartCardInterfaceContact,
		},
		{
			name:  "contactless",
			value: pcsc.CardInterfaceContactless,
			want:  transport.SmartCardInterfaceContactless,
		},
		{
			name:  "unknown",
			value: pcsc.CardInterfaceUnknown,
			want:  transport.SmartCardInterfaceUnknown,
		},
		{
			name:  "future",
			value: pcsc.CardInterface("future"),
			want:  transport.SmartCardInterfaceUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := smartCardInterface(tt.value); got != tt.want {
				t.Fatalf("interface = %q, want %q", got, tt.want)
			}
		})
	}
}
