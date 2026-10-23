package ctapkit

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	rtauthenticator "github.com/telesma-app/kit/internal/authenticator"
	"github.com/telesma-app/kit/internal/devicewatch"
	"github.com/telesma-app/kit/model/report"
	"github.com/telesma-app/kit/transport"
	"github.com/telesma-app/yubico"
)

func identitySources(identity report.DeviceIdentity) vendorSources {
	sources := vendorSources{yubico: report.YubicoSource{Outcome: sourceOutcome(nil)}, token2: report.Token2Source{Outcome: sourceOutcome(nil)}}

	switch identity.Vendor {
	case report.VendorToken2:
		sources.token2.Data = &report.Token2Report{SerialNumber: report.SourceReading[string]{Value: &identity.SerialNumber}}
	case report.VendorYubico:
		sources.yubico.Data = &yubico.DeviceInfo{SerialNumber: new(uint32(42))}
	}

	return sources
}

func TestPhysicalMembershipRequiresUnambiguousVendorSerial(t *testing.T) {
	for _, tc := range []struct {
		name       string
		identities []report.DeviceIdentity
		modes      []transport.Mode
		want       int
	}{
		{"same key", []report.DeviceIdentity{{Vendor: report.VendorToken2, SerialNumber: "42"}, {Vendor: report.VendorToken2, SerialNumber: "42"}}, []transport.Mode{transport.ModeHID, transport.ModeSmartCard}, 1},
		{"different serial", []report.DeviceIdentity{{Vendor: report.VendorToken2, SerialNumber: "42"}, {Vendor: report.VendorToken2, SerialNumber: "43"}}, []transport.Mode{transport.ModeHID, transport.ModeSmartCard}, 2},
		{"different vendor", []report.DeviceIdentity{{Vendor: report.VendorToken2, SerialNumber: "42"}, {Vendor: report.VendorYubico, SerialNumber: "42"}}, []transport.Mode{transport.ModeHID, transport.ModeSmartCard}, 2},
		{"unknown", []report.DeviceIdentity{{}, {}}, []transport.Mode{transport.ModeHID, transport.ModeSmartCard}, 2},
		{"ambiguous", []report.DeviceIdentity{{Vendor: report.VendorToken2, SerialNumber: "42"}, {Vendor: report.VendorToken2, SerialNumber: "42"}, {Vendor: report.VendorToken2, SerialNumber: "42"}}, []transport.Mode{transport.ModeHID, transport.ModeHID, transport.ModeSmartCard}, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			records := make(map[report.AttachmentID]*deviceRecord)

			for i, identity := range tc.identities {
				candidate := hidCandidate(string(rune('a' + i)))
				if tc.modes[i] == transport.ModeSmartCard {
					candidate = smartCardCandidate(candidate.Path, 1)
				}

				record := &deviceRecord{attachment: newAttachment(candidate), identity: identity}
				sources := identitySources(identity)
				record.attachment.report.Sources.Yubico = sources.yubico
				record.attachment.report.Sources.Token2 = sources.token2
				records[record.attachment.report.Attachment.ID] = record
			}

			manager := &DeviceManager{records: records}
			manager.reconcileDevices()

			if len(manager.devices) != tc.want {
				t.Fatalf("devices=%d want %d", len(manager.devices), tc.want)
			}
		})
	}
}

func physicalManager(t *testing.T, watcher *fakeDeviceWatcher, unsupportedPCSC bool, calls *atomic.Int32) *DeviceManager {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	manager := newDeviceManager(ctx, cancel, watcher, func(_ context.Context, mode transport.Mode, _ string) (*rtauthenticator.Opened, error) {
		if unsupportedPCSC && mode == transport.ModeSmartCard {
			return openedDevice(nil), errors.New("FIDO unavailable")
		}

		return openedDevice(nil), nil
	}, func(_ context.Context, target attachment, _ *rtauthenticator.Opened) (vendorSources, error) {
		calls.Add(1)
		return identitySources(report.DeviceIdentity{Vendor: report.VendorToken2, SerialNumber: target.path[len(target.path)-1:]}), nil
	}, nil)
	<-manager.ready
	t.Cleanup(func() {
		if err := manager.Close(); err != nil {
			t.Error(err)
		}
	})

	return manager
}

func TestPhysicalDevicesRetainEveryEndpointAndReadIdentityOnlyOnce(t *testing.T) {
	watcher := &fakeDeviceWatcher{snapshot: devicewatch.Snapshot{Candidates: []devicewatch.Candidate{hidCandidate("hid-a"), hidCandidate("hid-b"), smartCardCandidate("reader-a", 1), smartCardCandidate("reader-b", 2)}}, events: make(chan devicewatch.Event, 2)}

	var calls atomic.Int32

	manager := physicalManager(t, watcher, true, &calls)

	state := manager.State()
	if len(state.Snapshot.Devices) != 2 || len(state.Snapshot.Endpoints) != 4 || state.Error != nil || calls.Load() != 4 {
		t.Fatalf("state=%#v calls=%d", state.Snapshot, calls.Load())
	}

	for _, device := range state.Snapshot.Devices {
		if len(device.EndpointIDs) != 2 || device.Identity == nil {
			t.Fatalf("device=%#v", device)
		}
	}

	selected := state.Selected

	id := state.Snapshot.Selected
	if err := manager.Select(t.Context(), id); err != nil {
		t.Fatal(err)
	}

	if calls.Load() != 4 || manager.State().Selected != selected {
		t.Fatal("selection repeated vendor reads or reopened current channel")
	}

	if err := manager.RefreshSources(t.Context(), id); err != nil {
		t.Fatal(err)
	}

	if calls.Load() != 6 {
		t.Fatalf("refresh reads=%d want 6", calls.Load())
	}

	watcher.events <- devicewatch.Event{Type: devicewatch.EventDisconnected, Candidate: smartCardCandidate("reader-a", 1)}

	waitForDeviceManager(t, func() bool { return len(manager.State().Snapshot.Endpoints) == 3 })

	if manager.State().Snapshot.Selected != id || manager.State().Selected != selected || selected.Closed() {
		t.Fatal("auxiliary removal changed physical selection")
	}

	watcher.events <- devicewatch.Event{Type: devicewatch.EventConnected, Candidate: smartCardCandidate("reader-a", 1)}

	waitForDeviceManager(t, func() bool { return len(manager.State().Snapshot.Endpoints) == 4 })

	if len(manager.State().Snapshot.Devices) != 2 || manager.State().Error != nil || manager.State().Snapshot.Selected != id {
		t.Fatal("auxiliary reconnect changed physical device")
	}
}

func TestPhysicalSelectionSurvivesChannelArrivalAndFallback(t *testing.T) {
	watcher := &fakeDeviceWatcher{snapshot: devicewatch.Snapshot{Candidates: []devicewatch.Candidate{smartCardCandidate("reader-b", 1)}}, events: make(chan devicewatch.Event, 2)}

	var calls atomic.Int32

	manager := physicalManager(t, watcher, false, &calls)
	selected := manager.State().Selected
	deviceID := manager.State().Snapshot.Selected

	watcher.events <- devicewatch.Event{Type: devicewatch.EventConnected, Candidate: hidCandidate("hid-b")}

	waitForDeviceManager(t, func() bool { return len(manager.State().Snapshot.Endpoints) == 2 })

	if manager.State().Selected != selected || manager.State().Snapshot.Selected != deviceID {
		t.Fatal("interface arrival changed selection")
	}

	watcher.events <- devicewatch.Event{Type: devicewatch.EventConnected, Candidate: hidCandidate("hid-a")}

	waitForDeviceManager(t, func() bool { return len(manager.State().Snapshot.Devices) == 2 })

	watcher.events <- devicewatch.Event{Type: devicewatch.EventDisconnected, Candidate: smartCardCandidate("reader-b", 1)}

	waitForSelected(t, manager, attachmentID(transport.ModeHID, "hid-b"))

	if !selected.Closed() || manager.State().Snapshot.Selected != deviceID {
		t.Fatal("fallback lost physical identity or old channel")
	}
}

func TestFailedRefreshRetainsPhysicalIdentity(t *testing.T) {
	watcher := &fakeDeviceWatcher{snapshot: devicewatch.Snapshot{Candidates: []devicewatch.Candidate{hidCandidate("hid-a"), smartCardCandidate("reader-a", 1)}}, events: make(chan devicewatch.Event)}

	var calls atomic.Int32

	manager := physicalManager(t, watcher, true, &calls)
	id := manager.State().Snapshot.Selected

	manager.readSources = func(context.Context, attachment, *rtauthenticator.Opened) (vendorSources, error) {
		outcome := sourceOutcome(errors.New("temporary read failure"))
		return vendorSources{yubico: report.YubicoSource{Outcome: outcome}, token2: report.Token2Source{Outcome: outcome}}, nil
	}
	if err := manager.RefreshSources(t.Context(), id); err != nil {
		t.Fatal(err)
	}

	state := manager.State()
	if len(state.Snapshot.Devices) != 1 || state.Snapshot.Devices[0].ID != id || len(state.Snapshot.Devices[0].EndpointIDs) != 2 {
		t.Fatal("failed read erased confirmed identity")
	}
}

func TestSiblingSourceReadUsesPhysicalOperationGate(t *testing.T) {
	watcher := &fakeDeviceWatcher{snapshot: devicewatch.Snapshot{Candidates: []devicewatch.Candidate{hidCandidate("hid-a"), smartCardCandidate("reader-a", 1)}}, events: make(chan devicewatch.Event)}

	var calls atomic.Int32

	manager := physicalManager(t, watcher, false, &calls)
	selected := manager.State().Selected
	entered := make(chan struct{}, 1)
	manager.readSources = func(ctx context.Context, target attachment, opened *rtauthenticator.Opened) (vendorSources, error) {
		entered <- struct{}{}
		return noSourceReader(ctx, target, opened)
	}

	selected.runGate <- struct{}{}

	released := false
	defer func() {
		if !released {
			<-selected.runGate
		}
	}()

	done := make(chan error, 1)

	go func() {
		_, err := manager.ReadEndpointSources(t.Context(), attachmentID(transport.ModeSmartCard, "reader-a"))
		done <- err
	}()

	waitForDeviceManager(t, func() bool { return manager.State().Snapshot.Endpoints[1].Sources.Token2.State == report.SourceLoading })

	select {
	case <-entered:
		t.Fatal("sibling read bypassed active physical operation")
	case <-time.After(30 * time.Millisecond):
	}

	<-selected.runGate

	released = true

	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("source read did not resume")
	}

	select {
	case <-entered:
	default:
		t.Fatal("source was not read")
	}
}

func TestPhysicalSelectionRemainsWhenOnlyManagementEndpointSurvives(t *testing.T) {
	watcher := &fakeDeviceWatcher{snapshot: devicewatch.Snapshot{Candidates: []devicewatch.Candidate{hidCandidate("hid-a"), smartCardCandidate("reader-a", 1), hidCandidate("hid-b")}}, events: make(chan devicewatch.Event, 2)}

	var calls atomic.Int32

	manager := physicalManager(t, watcher, true, &calls)
	id := manager.State().Snapshot.Selected
	old := manager.State().Selected

	watcher.events <- devicewatch.Event{Type: devicewatch.EventDisconnected, Candidate: hidCandidate("hid-a")}

	waitForSelected(t, manager, attachmentID(transport.ModeSmartCard, "reader-a"))

	if manager.State().Snapshot.Selected != id || manager.State().Selected != nil || !old.Closed() {
		t.Fatal("loss of FIDO channel changed physical selection")
	}

	watcher.events <- devicewatch.Event{Type: devicewatch.EventConnected, Candidate: hidCandidate("hid-a")}

	waitForSelected(t, manager, attachmentID(transport.ModeHID, "hid-a"))

	if manager.State().Snapshot.Selected != id || manager.State().Selected == nil {
		t.Fatal("returning FIDO endpoint did not restore the selected physical device")
	}
}
