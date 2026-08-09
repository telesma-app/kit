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
	id := report.AttachmentID(string(candidate.Transport) + ":" + candidate.Path)
	attachmentReport := report.AttachmentReport{
		ID:        id,
		Transport: candidate.Transport,
	}
	if candidate.Transport == transport.ModeSmartCard {
		attachmentReport.SmartCard = &report.SmartCardReport{
			Reader:    candidate.Path,
			Interface: candidate.SmartCardInterface,
		}
		if candidate.SmartCard != nil {
			attachmentReport.SmartCard.ATR = hex.EncodeToString(
				candidate.SmartCard.ATR,
			)
		}
	} else if candidate.HID != nil {
		attachmentReport.USB = &report.USBReport{
			Manufacturer:   candidate.HID.MfrStr,
			Product:        candidate.HID.ProductStr,
			ReportedSerial: candidate.HID.SerialNbr,
			VendorID:       candidate.HID.VendorID,
			ProductID:      candidate.HID.ProductID,
		}
	}

	result := attachment{
		mode: candidate.Transport,
		path: candidate.Path,
		report: report.DeviceReport{
			Attachment: attachmentReport,
		},
	}
	if candidate.HID != nil {
		result.hidInstanceID = candidate.HID.InstanceID
		result.hidParentID = candidate.HID.ParentDeviceID
	}

	return result
}
