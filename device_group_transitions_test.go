package ctapkit

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	rtauthenticator "github.com/telesma-app/kit/internal/authenticator"
	"github.com/telesma-app/kit/internal/devicewatch"
	"github.com/telesma-app/kit/model/failure"
	"github.com/telesma-app/kit/model/report"
	"github.com/telesma-app/kit/transport"
)

func TestSelectPendingEndpointReconcilesPhysicalIdentity(t *testing.T) {
	watcher := &fakeDeviceWatcher{
		snapshot: devicewatch.Snapshot{Candidates: []devicewatch.Candidate{hidCandidate("hid-a")}},
		events:   make(chan devicewatch.Event, 1),
	}

	var calls atomic.Int32

	manager := physicalManager(t, watcher, false, &calls)
	previous := manager.State().Selected
	deviceID := manager.State().Snapshot.Selected
	_, workflowDone := holdWorkflow(t, previous)

	watcher.events <- devicewatch.Event{Type: devicewatch.EventConnected, Candidate: smartCardCandidate("reader-a", 1)}

	pending := waitForGroupingState(t, manager, func(update DeviceUpdate) bool {
		return len(update.Snapshot.Endpoints) == 2
	})
	if pending.Snapshot.Endpoints[1].Sources.Token2.Data != nil {
		t.Fatal("pending endpoint was inspected during the active workflow")
	}

	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()

	endpointID := attachmentID(transport.ModeSmartCard, "reader-a")
	if err := manager.SelectEndpoint(ctx, endpointID); err != nil {
		t.Fatal(err)
	}

	waitForCanceledGroupingWorkflow(t, workflowDone)

	state := manager.State()
	if state.Snapshot.Selected != deviceID || len(state.Snapshot.Devices) != 1 {
		t.Fatalf("selection did not reconcile physical identity: %#v", state.Snapshot)
	}
	if state.Selected == nil || state.Selected == previous || !previous.Closed() {
		t.Fatal("selection did not replace the previous authenticator")
	}

	wantEndpoints := []report.AttachmentID{attachmentID(transport.ModeHID, "hid-a"), endpointID}
	if !slices.Equal(state.Snapshot.Devices[0].EndpointIDs, wantEndpoints) {
		t.Fatalf("group endpoints = %v, want %v", state.Snapshot.Devices[0].EndpointIDs, wantEndpoints)
	}
	if calls.Load() != 2 {
		t.Fatalf("vendor reads = %d, want 2", calls.Load())
	}

	selected := state.Selected
	if err := manager.Select(ctx, deviceID); err != nil {
		t.Fatal(err)
	}
	if manager.State().Selected != selected {
		t.Fatal("physical selection reopened the current endpoint")
	}
}

func TestFallbackPhysicalIdentityDoesNotDependOnArrivalTiming(t *testing.T) {
	for _, pending := range []bool{false, true} {
		name := "inspected-before-removal"
		if pending {
			name = "pending-until-removal"
		}

		t.Run(name, func(t *testing.T) {
			watcher := &fakeDeviceWatcher{
				snapshot: devicewatch.Snapshot{Candidates: []devicewatch.Candidate{hidCandidate("hid-old")}},
				events:   make(chan devicewatch.Event, 2),
			}

			var calls atomic.Int32

			manager := physicalManager(t, watcher, false, &calls)
			var workflowDone <-chan error
			if pending {
				_, workflowDone = holdWorkflow(t, manager.State().Selected)
			}

			watcher.events <- devicewatch.Event{Type: devicewatch.EventConnected, Candidate: smartCardCandidate("reader-a", 1)}

			waitForGroupingState(t, manager, func(update DeviceUpdate) bool {
				if len(update.Snapshot.Endpoints) != 2 {
					return false
				}

				return pending || update.Snapshot.Endpoints[1].Sources.Token2.Data != nil
			})

			watcher.events <- devicewatch.Event{Type: devicewatch.EventDisconnected, Candidate: hidCandidate("hid-old")}

			state := waitForGroupingState(t, manager, func(update DeviceUpdate) bool {
				return len(update.Snapshot.Endpoints) == 1 && update.Selected != nil
			})
			if pending {
				waitForCanceledGroupingWorkflow(t, workflowDone)
			}

			wantIdentity := report.DeviceIdentity{Vendor: report.VendorToken2, SerialNumber: "a"}
			want := []report.DeviceReport{{
				ID:          "token2:a",
				Identity:    &wantIdentity,
				EndpointIDs: []report.AttachmentID{attachmentID(transport.ModeSmartCard, "reader-a")},
			}}
			if !reflect.DeepEqual(state.Snapshot.Devices, want) {
				t.Fatalf("fallback groups = %#v, want %#v", state.Snapshot.Devices, want)
			}
			if state.Snapshot.Selected != "token2:a" || state.Snapshot.SelectedEndpoint != want[0].EndpointIDs[0] {
				t.Fatalf("fallback selection = %q/%q, want token2:a/%q", state.Snapshot.Selected, state.Snapshot.SelectedEndpoint, want[0].EndpointIDs[0])
			}
			if calls.Load() != 2 {
				t.Fatalf("vendor reads = %d, want 2", calls.Load())
			}
		})
	}
}

func TestPhysicalGroupingIgnoresEndpointInsertionOrder(t *testing.T) {
	for _, tc := range []struct {
		name       string
		candidates []devicewatch.Candidate
		serials    []string
		want       []report.DeviceReport
	}{
		{
			name:       "paired-and-unknown",
			candidates: []devicewatch.Candidate{hidCandidate("hid-a"), smartCardCandidate("reader-a", 1), hidCandidate("hid-b"), smartCardCandidate("reader-b", 1), hidCandidate("hid-unknown")},
			serials:    []string{"a", "a", "b", "b", ""},
			want: []report.DeviceReport{
				{ID: "token2:a", Identity: &report.DeviceIdentity{Vendor: report.VendorToken2, SerialNumber: "a"}, EndpointIDs: []report.AttachmentID{attachmentID(transport.ModeHID, "hid-a"), attachmentID(transport.ModeSmartCard, "reader-a")}},
				{ID: "token2:b", Identity: &report.DeviceIdentity{Vendor: report.VendorToken2, SerialNumber: "b"}, EndpointIDs: []report.AttachmentID{attachmentID(transport.ModeHID, "hid-b"), attachmentID(transport.ModeSmartCard, "reader-b")}},
				{ID: "endpoint:hid:hid-unknown", EndpointIDs: []report.AttachmentID{attachmentID(transport.ModeHID, "hid-unknown")}},
			},
		},
		{
			name:       "ambiguous-serial",
			candidates: []devicewatch.Candidate{hidCandidate("hid-a"), smartCardCandidate("reader-a", 1), hidCandidate("hid-b")},
			serials:    []string{"a", "a", "a"},
			want: []report.DeviceReport{
				{ID: "endpoint:hid:hid-a", EndpointIDs: []report.AttachmentID{attachmentID(transport.ModeHID, "hid-a")}},
				{ID: "endpoint:hid:hid-b", EndpointIDs: []report.AttachmentID{attachmentID(transport.ModeHID, "hid-b")}},
				{ID: "endpoint:smart-card:reader-a", EndpointIDs: []report.AttachmentID{attachmentID(transport.ModeSmartCard, "reader-a")}},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, order := range groupingPermutations(len(tc.candidates)) {
				records := make(map[report.AttachmentID]*deviceRecord)
				manager := &DeviceManager{records: records, devices: make(map[report.DeviceID]*physicalDevice)}

				for _, index := range order {
					record := &deviceRecord{attachment: newAttachment(tc.candidates[index])}
					sources := identitySources(report.DeviceIdentity{Vendor: report.VendorToken2, SerialNumber: tc.serials[index]})
					record.attachment.report.Sources.Yubico = sources.yubico
					record.attachment.report.Sources.Token2 = sources.token2
					record.identity = identityFromSources(record.attachment.report.Sources)
					records[record.attachment.report.Attachment.ID] = record

					manager.reconcileDevices()
				}

				var got []report.DeviceReport
				for _, device := range sortedDevices(manager.devices) {
					got = append(got, device.snapshot())
				}
				if !reflect.DeepEqual(got, tc.want) {
					t.Fatalf("insertion order %v: groups = %#v, want %#v", order, got, tc.want)
				}
			}
		})
	}
}

func TestInitialPhysicalGroupsIgnoreSnapshotOrder(t *testing.T) {
	candidates := []devicewatch.Candidate{hidCandidate("hid-a"), smartCardCandidate("reader-a", 1), hidCandidate("hid-b"), smartCardCandidate("reader-b", 1)}
	want := []report.DeviceReport{
		{ID: "token2:a", Identity: &report.DeviceIdentity{Vendor: report.VendorToken2, SerialNumber: "a"}, EndpointIDs: []report.AttachmentID{attachmentID(transport.ModeHID, "hid-a"), attachmentID(transport.ModeSmartCard, "reader-a")}},
		{ID: "token2:b", Identity: &report.DeviceIdentity{Vendor: report.VendorToken2, SerialNumber: "b"}, EndpointIDs: []report.AttachmentID{attachmentID(transport.ModeHID, "hid-b"), attachmentID(transport.ModeSmartCard, "reader-b")}},
	}

	for trial, order := range groupingPermutations(len(candidates)) {
		t.Run(strconv.Itoa(trial), func(t *testing.T) {
			watcher := &fakeDeviceWatcher{events: make(chan devicewatch.Event)}
			for _, index := range order {
				watcher.snapshot.Candidates = append(watcher.snapshot.Candidates, candidates[index])
			}

			var calls atomic.Int32

			manager := physicalManager(t, watcher, false, &calls)
			state := manager.State()
			if !reflect.DeepEqual(state.Snapshot.Devices, want) {
				t.Fatalf("snapshot order %v: groups = %#v, want %#v", order, state.Snapshot.Devices, want)
			}
			if state.Snapshot.Selected != "token2:a" || state.Snapshot.SelectedEndpoint != attachmentID(transport.ModeHID, "hid-a") {
				t.Fatalf("snapshot order %v: selection = %q/%q", order, state.Snapshot.Selected, state.Snapshot.SelectedEndpoint)
			}
			if calls.Load() != 4 {
				t.Fatalf("vendor reads = %d, want 4", calls.Load())
			}
		})
	}
}

func TestInitialDeviceErrorUsesSortedEndpointOrder(t *testing.T) {
	codes := make(map[failure.Code]int)

	for trial := range 100 {
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		candidates := []devicewatch.Candidate{hidCandidate("a"), hidCandidate("b")}
		if trial%2 != 0 {
			slices.Reverse(candidates)
		}

		watcher := &fakeDeviceWatcher{snapshot: devicewatch.Snapshot{Candidates: candidates}, events: make(chan devicewatch.Event)}
		manager := newDeviceManager(ctx, cancel, watcher, func(_ context.Context, _ transport.Mode, path string) (*rtauthenticator.Opened, error) {
			code := failure.CodeTransportPermissionDenied
			if path == "b" {
				code = failure.CodeTransportFailure
			}

			return nil, failure.New(code)
		}, noSourceReader, nil)
		t.Cleanup(func() {
			if err := manager.Close(); err != nil {
				t.Error(err)
			}
		})

		select {
		case <-manager.ready:
		case <-ctx.Done():
			t.Fatal("initial device inspection did not finish")
		}

		state := manager.State()
		if state.Error == nil {
			t.Fatal("failed endpoints did not produce a startup error")
		}
		codes[state.Error.Code]++

		if err := manager.Close(); err != nil {
			t.Fatal(err)
		}
	}

	if len(codes) != 1 || codes[failure.CodeTransportPermissionDenied] != 100 {
		t.Fatalf("startup errors = %v, want TRANSPORT_PERMISSION_DENIED for every snapshot order", codes)
	}
}

func waitForGroupingState(t *testing.T, manager *DeviceManager, condition func(DeviceUpdate) bool) DeviceUpdate {
	t.Helper()

	if state := *manager.State(); condition(state) {
		return state
	}

	timer := time.NewTimer(time.Second)
	defer timer.Stop()

	for {
		select {
		case update, ok := <-manager.Updates():
			if !ok {
				t.Fatal("device manager stopped before the expected grouping update")
			}
			if condition(update) {
				return update
			}
		case <-timer.C:
			t.Fatal("expected device grouping update was not published")
		}
	}
}

func waitForCanceledGroupingWorkflow(t *testing.T, done <-chan error) {
	t.Helper()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("previous workflow error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("previous workflow was not canceled")
	}
}

func groupingPermutations(count int) [][]int {
	order := make([]int, count)
	for i := range order {
		order[i] = i
	}

	var result [][]int
	var visit func(int)
	visit = func(index int) {
		if index == len(order) {
			result = append(result, slices.Clone(order))
			return
		}

		for i := index; i < len(order); i++ {
			order[index], order[i] = order[i], order[index]
			visit(index + 1)
			order[index], order[i] = order[i], order[index]
		}
	}
	visit(0)

	return result
}
