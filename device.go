package ctapkit

import (
	"encoding/hex"

	"github.com/telesma-app/hid"
	"github.com/telesma-app/kit/internal/devicewatch"
	"github.com/telesma-app/kit/model/failure"
	"github.com/telesma-app/kit/model/report"
	"github.com/telesma-app/kit/transport"
	"github.com/telesma-app/pcsc"
)

type attachment struct {
	mode   transport.Mode
	path   string
	report report.EndpointReport
}

func newAttachment(candidate devicewatch.Candidate) attachment {
	attachmentReport := report.AttachmentReport{
		ID:        report.AttachmentID(string(candidate.Transport) + ":" + candidate.Path),
		Transport: candidate.Transport,
	}

	result := attachment{
		mode: candidate.Transport,
		path: candidate.Path,
	}
	if candidate.Transport == transport.ModeSmartCard {
		attachmentReport.SmartCard = &report.SmartCardReport{
			Reader:          candidate.Path,
			Interface:       transport.SmartCardInterfaceUnknown,
			FIDOApplication: report.Outcome{State: report.SourceNotRequested},
			ATR:             hex.EncodeToString(candidate.SmartCard.ATR),
		}
	} else {
		attachmentReport.USB = &report.USBReport{
			Manufacturer:   reportDescriptor(candidate.HID.MfrStr),
			Product:        reportDescriptor(candidate.HID.ProductStr),
			ReportedSerial: reportDescriptor(candidate.HID.SerialNbr),
			VendorID:       reportDescriptor(candidate.HID.VendorID),
			ProductID:      reportDescriptor(candidate.HID.ProductID),
			HIDName:        reportDescriptor(candidate.HID.HIDName),
			HIDUnique:      reportDescriptor(candidate.HID.HIDUnique),
			MetadataError:  failure.Snapshot(NormalizeError(candidate.HIDMetadataErr, failure.PhaseDiscovery)),
		}
	}

	result.report = report.EndpointReport{
		Attachment: attachmentReport,
		Sources:    initialSources(candidate.Transport),
	}

	return result
}

func smartCardInterface(value pcsc.CardInterface) transport.SmartCardInterface {
	switch value {
	case pcsc.CardInterfaceContact:
		return transport.SmartCardInterfaceContact
	case pcsc.CardInterfaceContactless:
		return transport.SmartCardInterfaceContactless
	default:
		return transport.SmartCardInterfaceUnknown
	}
}

// Only the report boundary turns a native descriptor error into display text.
func reportDescriptor[T any](value hid.Descriptor[T]) report.Descriptor[T] {
	var result report.Descriptor[T]
	if value.Err != nil {
		result.State = report.DescriptorFailed
		result.Error = &struct {
			Message string `json:"message"`
		}{Message: value.Err.Error()}
	} else if value.Value != nil {
		result.State = report.DescriptorRead
		result.Value = *value.Value
	}

	return result
}
