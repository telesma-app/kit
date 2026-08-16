package ctapkit

import (
	"encoding/hex"

	"github.com/telesma-app/kit/internal/devicewatch"
	"github.com/telesma-app/kit/model/report"
	"github.com/telesma-app/kit/transport"
)

type attachment struct {
	mode          transport.Mode
	path          string
	hidInstanceID string
	hidParentID   string
	report        report.DeviceReport
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
			Reader:    candidate.Path,
			Interface: candidate.SmartCardInterface,
			ATR:       hex.EncodeToString(candidate.SmartCard.ATR),
		}
	} else {
		attachmentReport.USB = &report.USBReport{
			Manufacturer:   candidate.HID.MfrStr,
			Product:        candidate.HID.ProductStr,
			ReportedSerial: candidate.HID.SerialNbr,
			VendorID:       candidate.HID.VendorID,
			ProductID:      candidate.HID.ProductID,
		}
		result.hidInstanceID = candidate.HID.InstanceID
		result.hidParentID = candidate.HID.ParentDeviceID
	}

	result.report = report.DeviceReport{
		Attachment: attachmentReport,
	}

	return result
}
