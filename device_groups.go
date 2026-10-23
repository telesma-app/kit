package ctapkit

import (
	"cmp"
	"context"
	"errors"
	"slices"

	"github.com/telesma-app/kit/model/failure"
	"github.com/telesma-app/kit/model/report"
	"github.com/telesma-app/kit/transport"
)

type physicalDevice struct {
	id        report.DeviceID
	identity  *report.DeviceIdentity
	endpoints []*deviceRecord
}

func (device *physicalDevice) snapshot() report.DeviceReport {
	result := report.DeviceReport{ID: device.id, Identity: device.identity, EndpointIDs: make([]report.AttachmentID, 0, len(device.endpoints))}
	for _, endpoint := range device.endpoints {
		result.EndpointIDs = append(result.EndpointIDs, endpoint.attachment.report.Attachment.ID)
	}

	return result
}

// Membership is a projection of the current endpoints and their last known identity.
// Matching vendor serials pair one HID and one PCSC endpoint; ambiguous serials
// and unknown identities retain independent endpoint-backed device identities.
func (m *DeviceManager) reconcileDevices() {
	ordered := sortedRecords(m.records)
	identities := make(map[report.DeviceIdentity][]*deviceRecord)

	for _, endpoint := range ordered {
		if endpoint.identity.SerialNumber != "" {
			identities[endpoint.identity] = append(identities[endpoint.identity], endpoint)
		}
	}

	current := make(map[report.DeviceID]*physicalDevice)

	for _, endpoint := range ordered {
		identity := endpoint.identity
		matches := identities[identity]
		known := identity.SerialNumber != "" && (len(matches) == 1 || len(matches) == 2 && (matches[0].attachment.mode == transport.ModeSmartCard) != (matches[1].attachment.mode == transport.ModeSmartCard))

		id := report.DeviceID("endpoint:" + string(endpoint.attachment.report.Attachment.ID))
		if known {
			id = report.DeviceID(string(identity.Vendor) + ":" + identity.SerialNumber)
		}

		device := current[id]
		if device == nil {
			device = &physicalDevice{id: id}
			if known {
				device.identity = &identity
			}

			current[id] = device
		}

		device.endpoints = append(device.endpoints, endpoint)
	}

	m.devices = current
}

func (device *physicalDevice) contains(id report.AttachmentID) bool {
	for _, endpoint := range device.endpoints {
		if endpoint.attachment.report.Attachment.ID == id {
			return true
		}
	}

	return false
}

func (m *DeviceManager) deviceFor(id report.AttachmentID) *physicalDevice {
	for _, device := range m.devices {
		if device.contains(id) {
			return device
		}
	}

	return nil
}

func (m *DeviceManager) sameDevice(left, right report.AttachmentID) bool {
	device := m.deviceFor(left)
	return device != nil && device.contains(right)
}

func sortedDevices(devices map[report.DeviceID]*physicalDevice) []*physicalDevice {
	result := make([]*physicalDevice, 0, len(devices))
	for _, device := range devices {
		result = append(result, device)
	}

	slices.SortFunc(result, func(a, b *physicalDevice) int {
		left, right := a.endpoints[0].attachment, b.endpoints[0].attachment
		if order := cmp.Compare(transportOrder(left.mode), transportOrder(right.mode)); order != 0 {
			return order
		}

		return cmp.Compare(left.path, right.path)
	})

	return result
}

func preferredEndpoint(endpoints []*deviceRecord, selected report.AttachmentID) *deviceRecord {
	for _, endpoint := range endpoints {
		if endpoint.attachment.report.Attachment.ID == selected && endpoint.openErr == nil {
			return endpoint
		}
	}

	for _, endpoint := range endpoints {
		if endpoint.openErr == nil {
			return endpoint
		}
	}

	return endpoints[0]
}

func groupOpenError(endpoints []*deviceRecord) error {
	var err error

	for _, endpoint := range endpoints {
		if endpoint.openErr == nil {
			return nil
		}

		err = errors.Join(err, endpoint.openErr)
	}

	return err
}

// Select chooses a physical device; the runtime retains its current channel or
// opens its preferred working endpoint. SelectEndpoint explicitly chooses a channel.
func (m *DeviceManager) Select(ctx context.Context, id report.DeviceID) error {
	reply := make(chan error, 1)
	if err := m.send(ctx, selectDevice{ctx: ctx, deviceID: id, reply: reply}); err != nil {
		return err
	}

	select {
	case err := <-reply:
		return err
	case <-ctx.Done():
		return NormalizeError(ctx.Err(), failure.PhaseAuthenticator)
	case <-m.done:
		return managerClosedError()
	}
}

// RefreshSources reads each endpoint of a physical device exactly once. Results
// are published in snapshots; per-command failures remain in the endpoint report.
func (m *DeviceManager) RefreshSources(ctx context.Context, id report.DeviceID) error {
	state := m.State()
	for _, device := range state.Snapshot.Devices {
		if device.ID != id {
			continue
		}

		for _, endpointID := range device.EndpointIDs {
			if _, err := m.ReadEndpointSources(ctx, endpointID); err != nil {
				return err
			}
		}

		return nil
	}

	return attachmentNotFound()
}
