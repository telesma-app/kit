package ctapkit

import (
	"context"
	"errors"
	"strconv"

	rtauthenticator "github.com/telesma-app/kit/internal/authenticator"
	"github.com/telesma-app/kit/model/report"
	"github.com/telesma-app/kit/transport"
	"github.com/telesma-app/token2"
	token2resolver "github.com/telesma-app/token2/resolver"
	token2ctaphid "github.com/telesma-app/token2/transport/ctaphid"
	yubicoresolver "github.com/telesma-app/yubico/resolver"
	yubicoctaphid "github.com/telesma-app/yubico/transport/ctaphid"
)

const (
	yubicoVendorID uint16 = 0x1050
	token2VendorID uint16 = 0x349e
)

type deviceMetadata = report.DeviceVendorMetadata

type deviceMetadataResolveFunc func(
	context.Context,
	attachment,
	rtauthenticator.VendorProvider,
) (deviceMetadata, error)

func resolveDeviceMetadata(
	ctx context.Context,
	target attachment,
	vendor rtauthenticator.VendorProvider,
) (deviceMetadata, error) {
	if target.mode == transport.ModeSmartCard {
		return resolveSmartCardMetadata(ctx, target)
	}

	usb := target.report.Attachment.USB
	switch usb.VendorID {
	case yubicoVendorID:
		info, err := yubicoctaphid.GetDeviceInfo(ctx, vendor)
		if err != nil {
			return optionalMetadataError(err)
		}

		return deviceMetadata{Yubico: &info}, nil
	case token2VendorID:
		var atr *token2.ATR
		if value, err := token2ctaphid.ReadATR(ctx, vendor); err == nil {
			atr = &value
		} else if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return deviceMetadata{}, err
		}

		info, err := token2resolver.NewLocal().ResolveHID(ctx, token2resolver.HIDTarget{
			ReportedSerial: usb.ReportedSerial,
			ProductID:      usb.ProductID,
			InstanceID:     target.hidInstanceID,
			ParentDeviceID: target.hidParentID,
			ATR:            atr,
		})
		if err != nil {
			return optionalMetadataError(err)
		}

		return deviceMetadata{Token2: &info}, nil
	default:
		return deviceMetadata{}, nil
	}
}

func resolveSmartCardMetadata(
	ctx context.Context,
	target attachment,
) (deviceMetadata, error) {
	result, err := token2resolver.NewLocal().ResolveSmartCard(ctx, target.path)
	if err == nil {
		return deviceMetadata{Token2: &result}, nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return deviceMetadata{}, err
	}
	if !errors.Is(err, token2resolver.ErrNotApplicable) {
		return deviceMetadata{}, nil
	}

	info, err := yubicoresolver.NewLocal().ResolveSmartCard(ctx, target.path)
	if err != nil {
		return optionalMetadataError(err)
	}

	return deviceMetadata{Yubico: &info}, nil
}

func optionalMetadataError(err error) (deviceMetadata, error) {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return deviceMetadata{}, err
	}

	return deviceMetadata{}, nil
}

func deviceMetadataEmpty(m deviceMetadata) bool {
	return m.Yubico == nil && m.Token2 == nil
}

func deviceMetadataIdentity(
	m deviceMetadata,
	fallback string,
) *report.DeviceIdentityReport {
	switch {
	case m.Yubico != nil:
		serial := ""
		if m.Yubico.Serial != nil {
			serial = strconv.FormatUint(uint64(*m.Yubico.Serial), 10)
		}

		return &report.DeviceIdentityReport{
			Vendor:       report.DeviceVendorYubico,
			Name:         m.Yubico.ModelName(fallback),
			SerialNumber: serial,
		}
	case m.Token2 != nil:
		return &report.DeviceIdentityReport{
			Vendor:       report.DeviceVendorToken2,
			Name:         m.Token2.ModelName(fallback),
			SerialNumber: m.Token2.SerialNumber,
		}
	default:
		return nil
	}
}

func applyDeviceMetadata(device *report.DeviceReport, metadata deviceMetadata) {
	fallback := ""
	if usb := device.Attachment.USB; usb != nil {
		fallback = usb.Product
	}
	device.Identity = deviceMetadataIdentity(metadata, fallback)
	device.VendorMetadata = &metadata
}
