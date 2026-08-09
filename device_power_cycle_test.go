package ctapkit

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	ghid "github.com/telesma-app/hid"
	rtauthenticator "github.com/telesma-app/kit/internal/authenticator"
	"github.com/telesma-app/kit/internal/devicewatch"
	"github.com/telesma-app/kit/model/failure"
	"github.com/telesma-app/kit/model/report"
	"github.com/telesma-app/kit/transport"
	"github.com/telesma-app/token2"
)

func TestDeviceManagerPowerCycleRebindsStableReportedSerial(t *testing.T) {
	for _, mode := range []transport.Mode{transport.ModeHID, transport.ModeWindowsProxy} {
		t.Run(string(mode), func(t *testing.T) {
			first := powerCycleHIDCandidate(mode, "hid-a", "reported-serial")
			second := powerCycleHIDCandidate(mode, "hid-b", "reported-serial")
			watcher := &fakeDeviceWatcher{
				snapshot: devicewatch.Snapshot{Candidates: []devicewatch.Candidate{first}},
				events:   make(chan devicewatch.Event, 2),
			}
			var firstCloses atomic.Int32
			manager := newTestDeviceManager(t, watcher, func(
				_ context.Context,
				_ transport.Mode,
				path string,
			) (*rtauthenticator.Opened, error) {
				if path == first.Path {
					return openedDevice(func() { firstCloses.Add(1) }), nil
				}

				return openedDevice(nil), nil
			})
			selected := manager.State().Selected
			cycle := selected.conformancePowerCycler()

			err := cycle(t.Context(), func(ctx context.Context) error {
				if err := manager.Select(ctx, selected.Device().Attachment.ID); !failure.IsCode(
					err,
					failure.CodeAuthenticatorOperationPending,
				) {
					t.Fatalf("Select() while armed = %v, want operation pending", err)
				}
				watcher.events <- devicewatch.Event{Candidate: first}
				waitForNoPowerCycleSelection(t, manager)
				watcher.events <- devicewatch.Event{Connected: true, Candidate: second}

				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if manager.State().Selected != selected {
				t.Fatal("power cycle replaced the stable authenticator handle")
			}
			if got := selected.Device().Attachment.ID; got != attachmentID(mode, second.Path) {
				t.Fatalf("selected attachment = %q, want %q", got, attachmentID(mode, second.Path))
			}
			if firstCloses.Load() != 1 {
				t.Fatalf("original close calls = %d, want 1", firstCloses.Load())
			}
		})
	}
}

func TestDeviceManagerPowerCycleIgnoresWrongCanonicalIdentityThenInstallsTarget(t *testing.T) {
	first := powerCycleHIDCandidate(transport.ModeHID, "hid-a", "")
	wrong := powerCycleHIDCandidate(transport.ModeHID, "hid-wrong", "")
	right := powerCycleHIDCandidate(transport.ModeHID, "hid-right", "")
	watcher := &fakeDeviceWatcher{
		snapshot: devicewatch.Snapshot{Candidates: []devicewatch.Candidate{first}},
		events:   make(chan devicewatch.Event, 3),
	}
	var wrongCloses atomic.Int32
	manager := newTestDeviceManagerWithResolver(t, watcher, func(
		_ context.Context,
		_ transport.Mode,
		path string,
	) (*rtauthenticator.Opened, error) {
		if path == wrong.Path {
			return openedDevice(func() { wrongCloses.Add(1) }), nil
		}

		return openedDevice(nil), nil
	}, func(
		_ context.Context,
		target attachment,
		_ rtauthenticator.VendorProvider,
	) (deviceMetadata, error) {
		serial := "target"
		if target.path == wrong.Path {
			serial = "other"
		}

		return deviceMetadata{Token2: &token2.DeviceInfo{SerialNumber: serial}}, nil
	})
	selected := manager.State().Selected

	err := selected.conformancePowerCycler()(t.Context(), func(context.Context) error {
		watcher.events <- devicewatch.Event{Candidate: first}
		waitForNoPowerCycleSelection(t, manager)
		watcher.events <- devicewatch.Event{Connected: true, Candidate: wrong}
		watcher.events <- devicewatch.Event{Connected: true, Candidate: right}

		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := selected.Device().Attachment.ID; got != attachmentID(transport.ModeHID, right.Path) {
		t.Fatalf("selected attachment = %q, want right target", got)
	}
	if wrongCloses.Load() != 1 {
		t.Fatalf("wrong candidate close calls = %d, want 1", wrongCloses.Load())
	}
	waitForDevices(t, manager, 2)
	devices := manager.State().Snapshot.Devices
	if devices[0].Attachment.ID != attachmentID(transport.ModeHID, right.Path) ||
		devices[1].Attachment.ID != attachmentID(transport.ModeHID, wrong.Path) {
		t.Fatalf("remaining candidates = %#v, want wrong record and installed target", devices)
	}
}

func TestDeviceManagerPowerCycleCancelBeforeDetachAbortsLease(t *testing.T) {
	first := powerCycleHIDCandidate(transport.ModeHID, "hid-a", "serial")
	watcher := &fakeDeviceWatcher{
		snapshot: devicewatch.Snapshot{Candidates: []devicewatch.Candidate{first}},
		events:   make(chan devicewatch.Event),
	}
	var closes atomic.Int32
	manager := newTestDeviceManager(t, watcher, func(
		context.Context,
		transport.Mode,
		string,
	) (*rtauthenticator.Opened, error) {
		return openedDevice(func() { closes.Add(1) }), nil
	})
	selected := manager.State().Selected
	ctx, cancel := context.WithCancel(t.Context())

	err := selected.conformancePowerCycler()(ctx, func(context.Context) error {
		cancel()

		return nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("PowerCycle() = %v, want context canceled", err)
	}
	if manager.cycle != nil {
		t.Fatal("lease remains armed after cancellation before detach")
	}
	if manager.State().Selected != selected || closes.Load() != 0 {
		t.Fatal("cancellation before detach changed the selected connection")
	}
}

func TestDeviceManagerPowerCycleDoesNotGuessChangedPathWithoutStableIdentity(t *testing.T) {
	first := powerCycleHIDCandidate(transport.ModeHID, "hid-a", "")
	second := powerCycleHIDCandidate(transport.ModeHID, "hid-b", "")
	watcher := &fakeDeviceWatcher{
		snapshot: devicewatch.Snapshot{Candidates: []devicewatch.Candidate{first}},
		events:   make(chan devicewatch.Event, 2),
	}
	var secondCloses atomic.Int32
	manager := newTestDeviceManager(t, watcher, func(
		_ context.Context,
		_ transport.Mode,
		path string,
	) (*rtauthenticator.Opened, error) {
		if path == second.Path {
			return openedDevice(func() { secondCloses.Add(1) }), nil
		}

		return openedDevice(nil), nil
	})
	selected := manager.State().Selected
	ctx, cancel := context.WithCancel(t.Context())

	err := selected.conformancePowerCycler()(ctx, func(context.Context) error {
		watcher.events <- devicewatch.Event{Candidate: first}
		waitForNoPowerCycleSelection(t, manager)
		watcher.events <- devicewatch.Event{Connected: true, Candidate: second}
		waitForDevices(t, manager, 1)
		cancel()

		return nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("PowerCycle() = %v, want context canceled", err)
	}
	if got := selected.Device().Attachment.ID; got != attachmentID(transport.ModeHID, first.Path) {
		t.Fatalf("detached target attachment = %q, want unchanged original", got)
	}
	if secondCloses.Load() != 1 {
		t.Fatalf("unmatched candidate close calls = %d, want 1", secondCloses.Load())
	}
	if manager.State().Selected != nil {
		t.Fatal("unverified changed-path candidate became selected")
	}
}

func TestDeviceManagerPowerCycleResumesDetachedLeaseWithoutRepeatingAction(t *testing.T) {
	first := powerCycleHIDCandidate(transport.ModeHID, "hid-a", "serial")
	second := powerCycleHIDCandidate(transport.ModeHID, "hid-b", "serial")
	watcher := &fakeDeviceWatcher{
		snapshot: devicewatch.Snapshot{Candidates: []devicewatch.Candidate{first}},
		events:   make(chan devicewatch.Event, 2),
	}
	manager := newTestDeviceManager(t, watcher, func(
		context.Context,
		transport.Mode,
		string,
	) (*rtauthenticator.Opened, error) {
		return openedDevice(nil), nil
	})
	selected := manager.State().Selected
	interactionErr := errors.New("interaction failed after detach")

	err := selected.conformancePowerCycler()(t.Context(), func(context.Context) error {
		watcher.events <- devicewatch.Event{Candidate: first}
		waitForNoPowerCycleSelection(t, manager)

		return interactionErr
	})
	if !errors.Is(err, interactionErr) {
		t.Fatalf("first PowerCycle() = %v, want interaction error", err)
	}
	watcher.events <- devicewatch.Event{Connected: true, Candidate: second}

	var repeatedAction atomic.Bool
	err = selected.conformancePowerCycler()(t.Context(), func(context.Context) error {
		repeatedAction.Store(true)

		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if repeatedAction.Load() {
		t.Fatal("resumed detached lease repeated the physical-cycle action")
	}
	if got := selected.Device().Attachment.ID; got != attachmentID(transport.ModeHID, second.Path) {
		t.Fatalf("selected attachment = %q, want resumed target", got)
	}
}

func TestDeviceManagerPowerCycleSmartCardResetsAndReopensWithoutAction(t *testing.T) {
	card := smartCardCandidate("reader-a", 1)
	watcher := &fakeDeviceWatcher{
		snapshot: devicewatch.Snapshot{Candidates: []devicewatch.Candidate{card}},
		events:   make(chan devicewatch.Event),
	}
	var opens atomic.Int32
	var closes atomic.Int32
	manager := newTestDeviceManager(t, watcher, func(
		context.Context,
		transport.Mode,
		string,
	) (*rtauthenticator.Opened, error) {
		opens.Add(1)

		return openedDevice(func() { closes.Add(1) }), nil
	})
	selected := manager.State().Selected
	var actionCalls atomic.Int32

	if err := selected.conformancePowerCycler()(t.Context(), func(context.Context) error {
		actionCalls.Add(1)

		return errors.New("NFC must not invoke physical-cycle interaction")
	}); err != nil {
		t.Fatal(err)
	}
	if actionCalls.Load() != 0 {
		t.Fatalf("action calls = %d, want 0", actionCalls.Load())
	}
	if opens.Load() != 2 {
		t.Fatalf("open calls = %d, want initial and reset reopen", opens.Load())
	}
	if closes.Load() != 1 {
		t.Fatalf("close calls before manager cleanup = %d, want 1", closes.Load())
	}
	if manager.State().Selected != selected {
		t.Fatal("NFC reset replaced the stable authenticator handle")
	}
}

func TestDeviceManagerPowerCycleSmartCardWaitsForTargetAfterWrongCard(t *testing.T) {
	card := smartCardCandidate("reader-a", 1)
	watcher := &fakeDeviceWatcher{
		snapshot: devicewatch.Snapshot{Candidates: []devicewatch.Candidate{card}},
		events:   make(chan devicewatch.Event, 2),
	}
	var resolves atomic.Int32
	var closes atomic.Int32
	manager := newTestDeviceManagerWithResolver(t, watcher, func(
		context.Context,
		transport.Mode,
		string,
	) (*rtauthenticator.Opened, error) {
		return openedDevice(func() { closes.Add(1) }), nil
	}, func(
		context.Context,
		attachment,
		rtauthenticator.VendorProvider,
	) (deviceMetadata, error) {
		serial := "target"
		if resolves.Add(1) == 2 {
			serial = "other"
		}

		return deviceMetadata{Token2: &token2.DeviceInfo{SerialNumber: serial}}, nil
	})
	selected := manager.State().Selected
	var actionCalls atomic.Int32
	cycleDone := make(chan error, 1)
	go func() {
		cycleDone <- selected.conformancePowerCycler()(t.Context(), func(context.Context) error {
			actionCalls.Add(1)

			return nil
		})
	}()
	waitForDeviceManager(t, func() bool { return closes.Load() == 2 })
	watcher.events <- devicewatch.Event{Candidate: card}
	watcher.events <- devicewatch.Event{Connected: true, Candidate: card}

	select {
	case err := <-cycleDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("NFC cycle did not resume when the target card returned")
	}
	if actionCalls.Load() != 0 {
		t.Fatalf("action calls = %d, want 0", actionCalls.Load())
	}
	if resolves.Load() != 3 {
		t.Fatalf("metadata resolutions = %d, want initial, wrong, target", resolves.Load())
	}
}

func TestDeviceManagerCloseUnblocksActivePowerCycle(t *testing.T) {
	first := powerCycleHIDCandidate(transport.ModeHID, "hid-a", "serial")
	watcher := &fakeDeviceWatcher{
		snapshot: devicewatch.Snapshot{Candidates: []devicewatch.Candidate{first}},
		events:   make(chan devicewatch.Event),
	}
	ctx, cancel := context.WithCancel(t.Context())
	manager := newDeviceManager(ctx, cancel, watcher, func(
		context.Context,
		transport.Mode,
		string,
	) (*rtauthenticator.Opened, error) {
		return openedDevice(nil), nil
	}, noDeviceMetadataResolver, nil)
	<-manager.ready
	selected := manager.State().Selected
	actionCalled := make(chan struct{})
	cycleDone := make(chan error, 1)
	go func() {
		selected.runMu.Lock()
		defer selected.runMu.Unlock()

		cycleDone <- selected.conformancePowerCycler()(context.Background(), func(context.Context) error {
			close(actionCalled)

			return nil
		})
	}()
	<-actionCalled
	closeDone := make(chan error, 1)
	go func() {
		closeDone <- manager.Close()
	}()

	select {
	case err := <-cycleDone:
		if err == nil {
			t.Fatal("active power cycle unexpectedly succeeded during manager close")
		}
	case <-time.After(time.Second):
		t.Fatal("manager close did not unblock active power cycle")
	}
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("manager close deadlocked behind active operation")
	}
}

func TestDeviceManagerCloseCancelsPowerCycleAction(t *testing.T) {
	first := powerCycleHIDCandidate(transport.ModeHID, "hid-a", "serial")
	watcher := &fakeDeviceWatcher{
		snapshot: devicewatch.Snapshot{Candidates: []devicewatch.Candidate{first}},
		events:   make(chan devicewatch.Event),
	}
	ctx, cancel := context.WithCancel(t.Context())
	manager := newDeviceManager(ctx, cancel, watcher, func(
		context.Context,
		transport.Mode,
		string,
	) (*rtauthenticator.Opened, error) {
		return openedDevice(nil), nil
	}, noDeviceMetadataResolver, nil)
	<-manager.ready
	selected := manager.State().Selected
	actionCalled := make(chan struct{})
	cycleDone := make(chan error, 1)
	go func() {
		selected.runMu.Lock()
		defer selected.runMu.Unlock()

		cycleDone <- selected.conformancePowerCycler()(context.Background(), func(ctx context.Context) error {
			close(actionCalled)
			<-ctx.Done()

			return ctx.Err()
		})
	}()
	<-actionCalled
	closeDone := make(chan error, 1)
	go func() {
		closeDone <- manager.Close()
	}()

	assertPowerCycleManagerCloseCompletes(t, cycleDone, closeDone)
}

func TestDeviceManagerCloseCancelsPowerCycleReopen(t *testing.T) {
	first := powerCycleHIDCandidate(transport.ModeHID, "hid-a", "serial")
	second := powerCycleHIDCandidate(transport.ModeHID, "hid-b", "serial")
	watcher := &fakeDeviceWatcher{
		snapshot: devicewatch.Snapshot{Candidates: []devicewatch.Candidate{first}},
		events:   make(chan devicewatch.Event, 2),
	}
	reopenStarted := make(chan struct{})
	ctx, cancel := context.WithCancel(t.Context())
	manager := newDeviceManager(ctx, cancel, watcher, func(
		ctx context.Context,
		_ transport.Mode,
		path string,
	) (*rtauthenticator.Opened, error) {
		if path == second.Path {
			close(reopenStarted)
			<-ctx.Done()

			return nil, ctx.Err()
		}

		return openedDevice(nil), nil
	}, noDeviceMetadataResolver, nil)
	<-manager.ready
	selected := manager.State().Selected
	cycleDone := make(chan error, 1)
	go func() {
		selected.runMu.Lock()
		defer selected.runMu.Unlock()

		cycleDone <- selected.conformancePowerCycler()(context.Background(), func(context.Context) error {
			watcher.events <- devicewatch.Event{Candidate: first}
			watcher.events <- devicewatch.Event{Connected: true, Candidate: second}

			return nil
		})
	}()
	<-reopenStarted
	closeDone := make(chan error, 1)
	go func() {
		closeDone <- manager.Close()
	}()

	assertPowerCycleManagerCloseCompletes(t, cycleDone, closeDone)
}

func TestDeviceManagerPowerCycleCommitsInstalledConnectionWhenDisplacedCloseFails(t *testing.T) {
	first := powerCycleHIDCandidate(transport.ModeHID, "hid-a", "serial")
	second := powerCycleHIDCandidate(transport.ModeHID, "hid-b", "serial")
	watcher := &fakeDeviceWatcher{
		snapshot: devicewatch.Snapshot{Candidates: []devicewatch.Candidate{first}},
		events:   make(chan devicewatch.Event, 2),
	}
	displacedCloseErr := errors.New("displaced close failed")
	var selected *Authenticator
	var installed *rtauthenticator.Opened
	ctx, cancel := context.WithCancel(t.Context())
	manager := newDeviceManager(ctx, cancel, watcher, func(
		_ context.Context,
		_ transport.Mode,
		path string,
	) (*rtauthenticator.Opened, error) {
		opened := openedDevice(nil)
		if path == second.Path {
			installed = opened
			selected.connection.mu.Lock()
			selected.connection.opened = &rtauthenticator.Opened{
				Lifecycle: &powerCycleErrorLifecycle{err: displacedCloseErr},
			}
			selected.connection.mu.Unlock()
		}

		return opened, nil
	}, noDeviceMetadataResolver, nil)
	<-manager.ready
	t.Cleanup(func() {
		if err := manager.Close(); !errors.Is(err, displacedCloseErr) {
			t.Errorf("Close() = %v, want displaced close error", err)
		}
	})
	selected = manager.State().Selected

	err := selected.conformancePowerCycler()(t.Context(), func(context.Context) error {
		watcher.events <- devicewatch.Event{Candidate: first}
		waitForNoPowerCycleSelection(t, manager)
		watcher.events <- devicewatch.Event{Connected: true, Candidate: second}

		return nil
	})
	if !errors.Is(err, displacedCloseErr) {
		t.Fatalf("PowerCycle() = %v, want displaced close error", err)
	}
	current, _, ok := selected.connection.Current()
	if !ok || current != installed {
		t.Fatal("successfully installed connection was not retained")
	}
	if manager.cycle != nil {
		t.Fatal("lease remained pending after successful install with close error")
	}
	if got := manager.State().Snapshot.Selected; got != attachmentID(transport.ModeHID, second.Path) {
		t.Fatalf("published selection = %q, want installed attachment", got)
	}
}

func TestPowerCycleCandidateIdentityPrecedence(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(*devicewatch.Candidate, *devicewatch.Candidate) report.DeviceReport
		matches bool
	}{
		{
			name: "canonical identity permits path change pending resolved verification",
			prepare: func(_, _ *devicewatch.Candidate) report.DeviceReport {
				return report.DeviceReport{Identity: &report.DeviceIdentityReport{
					Vendor:       report.DeviceVendorToken2,
					SerialNumber: "canonical",
				}}
			},
			matches: true,
		},
		{
			name: "reported serial",
			prepare: func(first, second *devicewatch.Candidate) report.DeviceReport {
				first.HID.SerialNbr = "reported"
				second.HID.SerialNbr = "reported"

				return report.DeviceReport{}
			},
			matches: true,
		},
		{
			name: "instance",
			prepare: func(first, second *devicewatch.Candidate) report.DeviceReport {
				first.HID.InstanceID = "instance"
				second.HID.InstanceID = "instance"

				return report.DeviceReport{}
			},
			matches: true,
		},
		{
			name: "parent",
			prepare: func(first, second *devicewatch.Candidate) report.DeviceReport {
				first.HID.ParentDeviceID = "parent"
				second.HID.ParentDeviceID = "parent"

				return report.DeviceReport{}
			},
			matches: true,
		},
		{
			name: "changed interface instance under same physical parent",
			prepare: func(first, second *devicewatch.Candidate) report.DeviceReport {
				first.HID.InstanceID = "old-interface"
				second.HID.InstanceID = "new-interface"
				first.HID.ParentDeviceID = "physical-parent"
				second.HID.ParentDeviceID = "physical-parent"

				return report.DeviceReport{}
			},
			matches: true,
		},
		{
			name: "different instance and parent",
			prepare: func(first, second *devicewatch.Candidate) report.DeviceReport {
				first.HID.InstanceID = "old-interface"
				second.HID.InstanceID = "new-interface"
				first.HID.ParentDeviceID = "old-parent"
				second.HID.ParentDeviceID = "new-parent"

				return report.DeviceReport{}
			},
			matches: false,
		},
		{
			name: "no stable identity",
			prepare: func(_, _ *devicewatch.Candidate) report.DeviceReport {
				return report.DeviceReport{}
			},
			matches: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			first := powerCycleHIDCandidate(transport.ModeHID, "hid-a", "")
			second := powerCycleHIDCandidate(transport.ModeHID, "hid-b", "")
			identity := test.prepare(&first, &second)
			got := powerCycleCandidateMatches(newAttachment(first), identity, newAttachment(second))
			if got != test.matches {
				t.Fatalf("powerCycleCandidateMatches() = %t, want %t", got, test.matches)
			}
		})
	}
}

type powerCycleErrorLifecycle struct {
	err error
}

func (l *powerCycleErrorLifecycle) Close() error {
	return l.err
}

func powerCycleHIDCandidate(mode transport.Mode, path, serial string) devicewatch.Candidate {
	return devicewatch.Candidate{
		Transport: mode,
		Path:      path,
		HID: &ghid.DeviceInfo{
			Path:      path,
			SerialNbr: serial,
			VendorID:  0x1234,
			ProductID: 0x5678,
		},
	}
}

func waitForNoPowerCycleSelection(t *testing.T, manager *DeviceManager) {
	t.Helper()

	waitForDeviceManager(t, func() bool {
		return manager.State().Snapshot.Selected == "" && manager.State().Selected == nil
	})
}

func assertPowerCycleManagerCloseCompletes(
	t *testing.T,
	cycleDone <-chan error,
	closeDone <-chan error,
) {
	t.Helper()

	select {
	case err := <-cycleDone:
		if err == nil {
			t.Fatal("active power cycle unexpectedly succeeded during manager close")
		}
	case <-time.After(time.Second):
		t.Fatal("manager close did not unblock active power cycle")
	}
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("manager close deadlocked behind active operation")
	}
}
