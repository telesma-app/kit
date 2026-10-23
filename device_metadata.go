package ctapkit

import (
	"context"
	"errors"

	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/ctap/transport/ctaphid"
	"github.com/telesma-app/iso7816"
	rtauthenticator "github.com/telesma-app/kit/internal/authenticator"
	"github.com/telesma-app/kit/model/failure"
	"github.com/telesma-app/kit/model/report"
	"github.com/telesma-app/kit/transport"
	"github.com/telesma-app/pcsc"
	"github.com/telesma-app/token2"
	token2hid "github.com/telesma-app/token2/transport/hid"
	token2pcsc "github.com/telesma-app/token2/transport/pcsc"
	"github.com/telesma-app/yubico"
	yubicoctaphid "github.com/telesma-app/yubico/transport/ctaphid"
	yubicopcsc "github.com/telesma-app/yubico/transport/pcsc"
)

const (
	yubicoVendorID uint16 = 0x1050
	token2VendorID uint16 = 0x349e
)

type vendorSources struct {
	yubico report.YubicoSource
	token2 report.Token2Source
}

type sourceReadFunc func(context.Context, attachment, *rtauthenticator.Opened) (vendorSources, error)

func initialSources(mode transport.Mode) report.Sources {
	pending := report.Outcome{State: report.SourceNotRequested}

	sources := report.Sources{
		HIDInit: report.HIDInitSource{Outcome: pending}, GetInfo: report.GetInfoSource{Outcome: pending},
		MDS: report.MDSSource{Outcome: pending}, Yubico: report.YubicoSource{Outcome: pending}, Token2: report.Token2Source{Outcome: pending},
	}
	if mode == transport.ModeSmartCard {
		sources.HIDInit.Outcome = report.Outcome{State: report.SourceUnsupported, Reason: report.ReasonTransport}
	}

	return sources
}

func readVendorSources(ctx context.Context, target attachment, opened *rtauthenticator.Opened) (vendorSources, error) {
	if err := ctx.Err(); err != nil {
		return vendorSources{yubico: report.YubicoSource{Outcome: sourceOutcome(err)}, token2: report.Token2Source{Outcome: sourceOutcome(err)}}, err
	}

	if target.mode == transport.ModeSmartCard {
		return readSmartCardSources(ctx, target, opened)
	}

	unknown := report.Outcome{State: report.SourceUnavailable, Reason: report.ReasonVendorUnknown}
	mismatch := report.Outcome{State: report.SourceUnsupported, Reason: report.ReasonVendorMismatch}
	result := vendorSources{yubico: report.YubicoSource{Outcome: unknown}, token2: report.Token2Source{Outcome: unknown}}

	usb := target.report.Attachment.USB
	if usb.VendorID.State != report.DescriptorRead {
		return result, nil
	}

	switch usb.VendorID.Value {
	case yubicoVendorID:
		result.token2.Outcome = mismatch
		if opened == nil || opened.Vendor == nil {
			result.yubico.Outcome = report.Outcome{State: report.SourceUnavailable, Reason: report.ReasonTransport}
			return result, nil
		}

		info, err := yubicoctaphid.ReadDeviceInfo(ctx, opened.Vendor)

		result.yubico = report.YubicoSource{Outcome: sourceOutcome(err)}
		if info.RawFields != nil {
			result.yubico.Data = &info
			result.yubico.ModelName, _ = info.ModelName()
		}

		return result, lifecycleError(err)
	case token2VendorID:
		result.yubico.Outcome = mismatch

		var vendor rtauthenticator.VendorProvider
		if opened != nil {
			vendor = opened.Vendor
		}

		info, err := token2hid.ReadDeviceInfo(ctx, target.path, vendor)
		result.token2 = token2Source(info, err)

		return result, lifecycleError(err)
	default:
		result.yubico.Outcome = mismatch
		result.token2.Outcome = mismatch

		return result, nil
	}
}

func readSmartCardSources(ctx context.Context, target attachment, opened *rtauthenticator.Opened) (result vendorSources, err error) {
	unavailable := report.Outcome{State: report.SourceUnavailable, Reason: report.ReasonTransport}
	mismatch := report.Outcome{State: report.SourceUnsupported, Reason: report.ReasonVendorMismatch}

	result = vendorSources{yubico: report.YubicoSource{Outcome: unavailable}, token2: report.Token2Source{Outcome: unavailable}}
	if opened == nil || opened.Card == nil {
		return result, nil
	}

	if beginErr := opened.Card.BeginTransaction(ctx); beginErr != nil {
		result.yubico.Outcome = sourceOutcome(beginErr)
		result.token2.Outcome = sourceOutcome(beginErr)

		return result, lifecycleError(beginErr)
	}

	defer func() {
		cleanupErr := opened.Card.EndTransaction(pcsc.DispositionLeaveCard)
		if cleanupErr != nil {
			if result.yubico.Data != nil {
				result.yubico.Outcome = sourceOutcome(cleanupErr)
				result.yubico.State = report.SourcePartial
			}

			if result.token2.Data != nil {
				result.token2.Outcome = sourceOutcome(cleanupErr)

				data := result.token2.Data
				if data.SerialNumber.Value != nil || data.ATR.Value != nil || data.Configuration.Value != nil {
					result.token2.State = report.SourcePartial
				}
			}

			err = errors.Join(err, cleanupErr)
		}
	}()

	identity := identityFromSources(target.report.Sources)
	if identity.Vendor != report.VendorToken2 {
		info, readErr := yubicopcsc.ReadDeviceInfo(ctx, opened.Card)

		result.yubico = report.YubicoSource{Outcome: sourceOutcome(readErr)}
		if info.RawFields != nil {
			result.yubico.Data = &info
			result.yubico.ModelName, _ = info.ModelName()
			result.token2.Outcome = mismatch

			return result, lifecycleError(readErr)
		}

		if fatal := lifecycleError(readErr); fatal != nil {
			return result, fatal
		}

		if identity.Vendor == report.VendorYubico {
			result.token2.Outcome = mismatch
			return result, nil
		}
	} else {
		result.yubico.Outcome = mismatch
	}

	info, readErr := token2pcsc.ReadDeviceInfo(ctx, opened.Card)

	result.token2 = token2Source(info, readErr)
	if info.SerialNumber.Value != nil {
		result.yubico.Outcome = mismatch
	}

	return result, lifecycleError(readErr)
}

func token2Source(info token2.DeviceInfo, err error) report.Token2Source {
	outcome := sourceOutcome(err)
	if err != nil && info.HasData() {
		outcome.State = report.SourcePartial
	}

	return report.Token2Source{
		Outcome: outcome,
		Data: &report.Token2Report{
			SerialNumber:  token2Reading(info.SerialNumber),
			ATR:           token2Reading(info.ATR),
			Configuration: token2Reading(info.Configuration),
			Model:         info.Model,
		},
	}
}

func token2Reading[T any](descriptor token2.Descriptor[T]) report.SourceReading[T] {
	reading := report.SourceReading[T]{Value: descriptor.Value}
	if descriptor.Err != nil {
		reading.Error = &report.SourceReadError{Message: descriptor.Err.Error()}
	}

	return reading
}

func sourceOutcome(err error) report.Outcome {
	if err == nil {
		return report.Outcome{State: report.SourceAvailable}
	}

	return report.Outcome{State: sourceState(err), Error: failure.Snapshot(NormalizeError(err, failure.PhaseAuthenticator))}
}

func sourceState(err error) report.SourceState {
	switch err {
	case yubicopcsc.ErrManagementApplicationNotAvailable, token2pcsc.ErrOTPApplicationNotAvailable:
		return report.SourceAbsent
	case yubico.ErrDeviceInfoNotSupported:
		return report.SourceUnsupported
	}

	switch value := err.(type) {
	case *ctaptransport.DeviceInvalidatedError, *ctaptransport.IOError:
		return report.SourceFailed
	case *ctaptransport.CTAPError:
		if value.StatusCode == ctaptransport.CTAP1_ERR_INVALID_COMMAND {
			return report.SourceUnsupported
		}
	case *ctaphid.ErrorResponse:
		if value.ErrorCode == ctaphid.ERR_INVALID_CMD {
			return report.SourceUnsupported
		}
	case *iso7816.APDUError:
		switch value.StatusWord() {
		case 0x6a82, 0x6999, 0x6b00:
			return report.SourceAbsent
		case 0x6d00:
			return report.SourceUnsupported
		}
	case interface{ Unwrap() []error }:
		var state report.SourceState

		for _, child := range value.Unwrap() {
			childState := sourceState(child)
			if state != "" && state != childState {
				// A missing applet can wrap an unsupported SELECT status.
				// Independent I/O or cleanup failures must still win.
				if state == report.SourceAbsent && childState == report.SourceUnsupported ||
					state == report.SourceUnsupported && childState == report.SourceAbsent {
					state = report.SourceAbsent
					continue
				}

				return report.SourceFailed
			}

			state = childState
		}

		if state != "" {
			return state
		}
	case interface{ Unwrap() error }:
		return sourceState(value.Unwrap())
	}

	return report.SourceFailed
}

func lifecycleError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}

	if _, invalid := errors.AsType[*ctaptransport.DeviceInvalidatedError](err); invalid {
		return err
	}

	return nil
}
