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
)

func TestDevicePublicationWaitsForFirstInspection(t *testing.T) {
	for _, tc := range []struct {
		name    string
		serial  string
		openErr error
		wantID  report.DeviceID
	}{
		{name: "identified", serial: "a", wantID: "token2:a"},
		{name: "unknown", wantID: "endpoint:hid:hid-new"},
		{name: "failed", openErr: errors.New("cannot open new device"), wantID: "endpoint:hid:hid-new"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			watcher := &fakeDeviceWatcher{events: make(chan devicewatch.Event, 1)}
			started := make(chan struct{})
			release := make(chan struct{})

			manager := newTestDeviceManager(t, watcher, func(ctx context.Context, _ transport.Mode, _ string) (*rtauthenticator.Opened, error) {
				close(started)

				select {
				case <-release:
				case <-ctx.Done():
					return nil, ctx.Err()
				}

				if tc.openErr != nil {
					return nil, tc.openErr
				}

				return openedDevice(nil), nil
			})
			manager.readSources = func(context.Context, attachment, *rtauthenticator.Opened) (vendorSources, error) {
				return identitySources(report.DeviceIdentity{Vendor: report.VendorToken2, SerialNumber: tc.serial}), nil
			}

			watcher.events <- devicewatch.Event{Type: devicewatch.EventConnected, Candidate: hidCandidate("hid-new")}

			select {
			case <-started:
			case <-time.After(time.Second):
				t.Fatal("initial inspection did not start")
			}

			pending := manager.State()
			if len(pending.Snapshot.Devices) != 0 || len(pending.Snapshot.Endpoints) != 1 || pending.Snapshot.Selected != "" {
				t.Fatalf("uninspected endpoint was published as a physical device: %#v", pending.Snapshot)
			}

			close(release)

			state := waitForGroupingState(t, manager, func(update DeviceUpdate) bool {
				return len(update.Snapshot.Devices) == 1
			})
			if state.Snapshot.Devices[0].ID != tc.wantID || state.Snapshot.Selected != tc.wantID {
				t.Fatalf("inspected device = %#v, want %q", state.Snapshot, tc.wantID)
			}
			if tc.openErr != nil && (state.Error == nil || state.Selected != nil) {
				t.Fatal("failed inspection must publish the device and its error without a ready authenticator")
			}
			if tc.openErr == nil && state.Selected == nil {
				t.Fatal("first usable device was not automatically selected")
			}
		})
	}
}

func TestDevicePublicationResolvesPendingEndpointBeforeAddingPhysicalDevice(t *testing.T) {
	for _, tc := range []struct {
		name        string
		serial      string
		readErr     error
		wantDevices int
	}{
		{name: "sibling", serial: "a", wantDevices: 1},
		{name: "other device", serial: "b", wantDevices: 2},
		{name: "unknown identity", wantDevices: 2},
		{name: "failed identity", readErr: errors.New("vendor read failed"), wantDevices: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			watcher := &fakeDeviceWatcher{
				snapshot: devicewatch.Snapshot{Candidates: []devicewatch.Candidate{hidCandidate("hid-a")}},
				events:   make(chan devicewatch.Event, 1),
			}

			var calls atomic.Int32

			manager := physicalManager(t, watcher, false, &calls)
			selected := manager.State().Selected
			deviceID := manager.State().Snapshot.Selected
			cancel, workflowDone := holdWorkflow(t, selected)
			manager.readSources = func(context.Context, attachment, *rtauthenticator.Opened) (vendorSources, error) {
				return identitySources(report.DeviceIdentity{Vendor: report.VendorToken2, SerialNumber: tc.serial}), tc.readErr
			}

			watcher.events <- devicewatch.Event{Type: devicewatch.EventConnected, Candidate: smartCardCandidate("reader-new", 1)}

			pending := waitForGroupingState(t, manager, func(update DeviceUpdate) bool {
				return len(update.Snapshot.Endpoints) == 2
			})
			if len(pending.Snapshot.Devices) != 1 || len(pending.Snapshot.Devices[0].EndpointIDs) != 1 {
				t.Fatalf("pending arrival changed physical topology: %#v", pending.Snapshot.Devices)
			}
			if pending.Selected != selected || pending.Snapshot.Selected != deviceID {
				t.Fatal("pending arrival changed the selected authenticator")
			}

			cancel()
			waitForCanceledGroupingWorkflow(t, workflowDone)

			state := waitForGroupingState(t, manager, func(update DeviceUpdate) bool {
				return update.Snapshot.Endpoints[1].Sources.GetInfo.State != report.SourceNotRequested
			})
			if len(state.Snapshot.Devices) != tc.wantDevices {
				t.Fatalf("physical devices = %#v, want %d", state.Snapshot.Devices, tc.wantDevices)
			}
			if state.Selected != selected || selected.Closed() || state.Snapshot.Selected != deviceID {
				t.Fatal("initial inspection replaced the selected authenticator")
			}
			if tc.wantDevices == 1 && len(state.Snapshot.Devices[0].EndpointIDs) != 2 {
				t.Fatal("confirmed sibling was not attached to the existing physical device")
			}
		})
	}
}

func TestDevicePublicationDropsRemovedPendingEndpointWithoutInspectingIt(t *testing.T) {
	watcher := &fakeDeviceWatcher{
		snapshot: devicewatch.Snapshot{Candidates: []devicewatch.Candidate{hidCandidate("hid-a")}},
		events:   make(chan devicewatch.Event, 1),
	}

	var calls atomic.Int32

	manager := physicalManager(t, watcher, false, &calls)
	selected := manager.State().Selected
	cancel, workflowDone := holdWorkflow(t, selected)
	candidate := smartCardCandidate("reader-a", 1)

	watcher.events <- devicewatch.Event{Type: devicewatch.EventConnected, Candidate: candidate}

	waitForGroupingState(t, manager, func(update DeviceUpdate) bool {
		return len(update.Snapshot.Endpoints) == 2
	})
	watcher.events <- devicewatch.Event{Type: devicewatch.EventDisconnected, Candidate: candidate}

	state := waitForGroupingState(t, manager, func(update DeviceUpdate) bool {
		return len(update.Snapshot.Endpoints) == 1
	})
	if len(state.Snapshot.Devices) != 1 || state.Selected != selected || calls.Load() != 1 {
		t.Fatalf("removed pending endpoint affected selected device: %#v", state.Snapshot)
	}

	cancel()
	waitForCanceledGroupingWorkflow(t, workflowDone)
}
