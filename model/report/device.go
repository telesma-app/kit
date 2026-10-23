package report

import (
	"github.com/telesma-app/kit/model/failure"
	"github.com/telesma-app/kit/transport"
)

// AttachmentID identifies a transport endpoint, not a physical device.
type AttachmentID string

// DescriptorState is the outcome exposed in application reports.
type DescriptorState string

const (
	DescriptorUnknown DescriptorState = ""
	DescriptorRead    DescriptorState = "read"
	DescriptorFailed  DescriptorState = "error"
)

// Descriptor is the JSON representation of one HID observation.
type Descriptor[T any] struct {
	Value T               `json:"value"`
	State DescriptorState `json:"state"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// USBReport contains USB/HID observations, independent of vendor commands.
type USBReport struct {
	Manufacturer   Descriptor[string] `json:"manufacturer"`
	Product        Descriptor[string] `json:"product"`
	ReportedSerial Descriptor[string] `json:"reportedSerial"`
	VendorID       Descriptor[uint16] `json:"vendorId"`
	ProductID      Descriptor[uint16] `json:"productId"`
	// Linux kernel observations, which may differ from USB strings.
	HIDName       Descriptor[string] `json:"hidName"`
	HIDUnique     Descriptor[string] `json:"hidUnique"`
	MetadataError *failure.Failure   `json:"metadataError,omitempty"`
}

// SmartCardReport describes a PC/SC attachment separately from card identity.
type SmartCardReport struct {
	Reader          string                       `json:"reader"`
	ATR             string                       `json:"atr,omitempty"`
	Interface       transport.SmartCardInterface `json:"interface"`
	FIDOApplication Outcome                      `json:"fidoApplication"`
}

// AttachmentReport is the transport-layer view of one present endpoint.
type AttachmentReport struct {
	ID        AttachmentID     `json:"id"`
	Transport transport.Mode   `json:"transport"`
	USB       *USBReport       `json:"usb,omitempty"`
	SmartCard *SmartCardReport `json:"smartCard,omitempty"`
}

// EndpointReport contains observations obtained through one transport endpoint.
type EndpointReport struct {
	Attachment AttachmentReport `json:"attachment"`
	Sources    Sources          `json:"sources"`
}

// DeviceID identifies a physical token independently of its selected endpoint.
type DeviceID string

type Vendor string

const (
	VendorYubico Vendor = "yubico"
	VendorToken2 Vendor = "token2"
)

// DeviceIdentity is verified by a manufacturer's full serial-number command.
type DeviceIdentity struct {
	Vendor       Vendor `json:"vendor"`
	SerialNumber string `json:"serialNumber"`
}

// DeviceReport owns endpoint membership. Endpoint data and the active endpoint
// are stored once in DeviceSnapshot, not copied into the physical device.
type DeviceReport struct {
	ID          DeviceID        `json:"id"`
	Identity    *DeviceIdentity `json:"identity,omitempty"`
	EndpointIDs []AttachmentID  `json:"endpointIds"`
}
