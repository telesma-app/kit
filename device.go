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

func powerCycleCandidateMatches(
	original attachment,
	originalReport report.DeviceReport,
	candidate attachment,
) bool {
	if original.mode != candidate.mode {
		return false
	}
	if original.mode == transport.ModeSmartCard {
		return original.path == candidate.path
	}
	if !sameUSBProduct(original.report, candidate.report) {
		return false
	}
	if canonicalSerial(originalReport) != "" {
		return true
	}

	originalUSB := original.report.Attachment.USB
	candidateUSB := candidate.report.Attachment.USB
	if originalUSB.ReportedSerial != "" {
		return originalUSB.ReportedSerial == candidateUSB.ReportedSerial
	}
	if original.hidInstanceID != "" && original.hidInstanceID == candidate.hidInstanceID {
		return true
	}
	if original.hidParentID != "" && original.hidParentID == candidate.hidParentID {
		return true
	}
	if original.hidInstanceID != "" || original.hidParentID != "" {
		return false
	}

	return original.path == candidate.path
}

func powerCycleIdentityMatches(
	original attachment,
	originalReport report.DeviceReport,
	candidate attachment,
	candidateReport report.DeviceReport,
) bool {
	if !powerCycleCandidateMatches(original, originalReport, candidate) {
		return false
	}
	serial := canonicalSerial(originalReport)
	if serial == "" {
		return true
	}

	return candidateReport.Identity != nil &&
		originalReport.Identity.Vendor == candidateReport.Identity.Vendor &&
		serial == candidateReport.Identity.SerialNumber
}

func sameUSBProduct(left, right report.DeviceReport) bool {
	leftUSB := left.Attachment.USB
	rightUSB := right.Attachment.USB
	return leftUSB != nil && rightUSB != nil &&
		leftUSB.VendorID == rightUSB.VendorID &&
		leftUSB.ProductID == rightUSB.ProductID
}

func canonicalSerial(device report.DeviceReport) string {
	if device.Identity == nil {
		return ""
	}

	return device.Identity.SerialNumber
}
