package ctapkit

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/telesma-app/ctap/transport/ctaphid"
	ghid "github.com/telesma-app/hid"
	rtauthenticator "github.com/telesma-app/kit/internal/authenticator"
	"github.com/telesma-app/kit/internal/devicewatch"
	"github.com/telesma-app/kit/model/failure"
	"github.com/telesma-app/kit/model/report"
	"github.com/telesma-app/kit/transport"
	"github.com/telesma-app/pcsc"
)

func TestNewDeviceManagerRejectsInvalidTransportMode(t *testing.T) {
	manager, err := NewDeviceManager(t.Context(), transport.Mode("invalid"))
	if manager != nil {
		t.Fatal("manager != nil")
	}

	if !failure.IsCode(err, failure.CodeTransportModeUnsupported) {
		t.Fatalf("error = %v, want %s", err, failure.CodeTransportModeUnsupported)
	}

	if got := failure.Snapshot(err).Phase; got != failure.PhaseValidation {
		t.Fatalf("phase = %q, want %q", got, failure.PhaseValidation)
	}
}

type fakeDeviceWatcher struct {
	snapshot devicewatch.Snapshot
	events   chan devicewatch.Event
	once     sync.Once
}

func (w *fakeDeviceWatcher) Snapshot() devicewatch.Snapshot {
	return w.snapshot
}

func (w *fakeDeviceWatcher) Listen() <-chan devicewatch.Event {
	return w.events
}

func (w *fakeDeviceWatcher) Close() error {
	w.once.Do(func() {
		close(w.events)
	})

	return nil
}

type fakeDeviceLifecycle struct {
	close func()
}

func (l *fakeDeviceLifecycle) Close() error {
	if l.close != nil {
		l.close()
	}

	return nil
}

func TestDeviceManagerSelectsFirstHIDAndStaysSticky(t *testing.T) {
	watcher := &fakeDeviceWatcher{
		snapshot: devicewatch.Snapshot{Candidates: []devicewatch.Candidate{
			smartCardCandidate("reader-a", 1),
			hidCandidate("hid-b"),
			hidCandidate("hid-a"),
		}},
		events: make(chan devicewatch.Event, 1),
	}
	opened := make(chan report.AttachmentID, 4)
	manager := newTestDeviceManager(t, watcher, func(
		_ context.Context,
		mode transport.Mode,
		path string,
	) (*rtauthenticator.Opened, error) {
		opened <- attachmentID(mode, path)

		return openedDevice(nil), nil
	})

	if got := <-opened; got != attachmentID(transport.ModeHID, "hid-a") {
		t.Fatalf("initial open = %q, want hid-a", got)
	}

	if got := <-opened; got != attachmentID(transport.ModeHID, "hid-b") {
		t.Fatalf("second inspected attachment = %q, want hid-b", got)
	}

	if got := <-opened; got != attachmentID(transport.ModeSmartCard, "reader-a") {
		t.Fatalf("third inspected attachment = %q, want reader-a", got)
	}

	selected := manager.State().Selected

	watcher.events <- devicewatch.Event{
		Type:      devicewatch.EventConnected,
		Candidate: hidCandidate("hid-0"),
	}

	waitForDevices(t, manager, 4)

	state := manager.State()
	if state.Selected != selected {
		t.Fatal("new candidate replaced the selected authenticator")
	}

	if state.Snapshot.SelectedEndpoint != selected.Endpoint().Attachment.ID {
		t.Fatalf(
			"snapshot selection = %q, runtime selection = %q",
			state.Snapshot.SelectedEndpoint,
			selected.Endpoint().Attachment.ID,
		)
	}

	update := <-manager.Updates()
	if update.Selected != selected || len(update.Snapshot.Endpoints) != 4 {
		t.Fatalf("topology update = %#v", update.Snapshot)
	}

	if got := <-opened; got != attachmentID(transport.ModeHID, "hid-0") {
		t.Fatalf("connected attachment inspection = %q, want hid-0", got)
	}
}

func TestDeviceManagerSkipsFailedCandidate(t *testing.T) {
	watcher := &fakeDeviceWatcher{
		snapshot: devicewatch.Snapshot{Candidates: []devicewatch.Candidate{
			hidCandidate("hid-a"),
			hidCandidate("hid-b"),
			smartCardCandidate("reader-a", 1),
		}},
		events: make(chan devicewatch.Event, 1),
	}

	var mu sync.Mutex

	attempts := make(map[report.AttachmentID]int)
	manager := newTestDeviceManager(t, watcher, func(
		_ context.Context,
		mode transport.Mode,
		path string,
	) (*rtauthenticator.Opened, error) {
		id := attachmentID(mode, path)

		mu.Lock()
		attempts[id]++
		mu.Unlock()

		if path == "hid-a" {
			return nil, errors.New("hid-a cannot be opened")
		}

		return openedDevice(nil), nil
	})

	if got := manager.State().Snapshot.SelectedEndpoint; got != attachmentID(transport.ModeHID, "hid-b") {
		t.Fatalf("selected = %q, want hid-b", got)
	}

	watcher.events <- devicewatch.Event{Type: devicewatch.EventDisconnected, Candidate: hidCandidate("hid-b")}

	waitForSelected(
		t,
		manager,
		attachmentID(transport.ModeSmartCard, "reader-a"),
	)
	mu.Lock()
	defer mu.Unlock()

	if attempts[attachmentID(transport.ModeHID, "hid-a")] != 1 {
		t.Fatalf("failed HID attempts = %d, want 1", attempts[attachmentID(transport.ModeHID, "hid-a")])
	}
}

func TestDeviceManagerClosesBeforeOpeningReplacement(t *testing.T) {
	watcher := &fakeDeviceWatcher{
		snapshot: devicewatch.Snapshot{Candidates: []devicewatch.Candidate{
			hidCandidate("hid-a"),
			hidCandidate("hid-b"),
		}},
		events: make(chan devicewatch.Event, 1),
	}
	order := make(chan string, 4)
	manager := newTestDeviceManager(t, watcher, func(
		_ context.Context,
		_ transport.Mode,
		path string,
	) (*rtauthenticator.Opened, error) {
		order <- "open-" + path

		return openedDevice(func() {
			order <- "close-" + path
		}), nil
	})

	if got := <-order; got != "open-hid-a" {
		t.Fatalf("initial action = %q", got)
	}

	if got := <-order; got != "open-hid-b" {
		t.Fatalf("second action = %q, want open-hid-b", got)
	}

	if got := <-order; got != "close-hid-b" {
		t.Fatalf("third action = %q, want close-hid-b", got)
	}

	watcher.events <- devicewatch.Event{Type: devicewatch.EventDisconnected, Candidate: hidCandidate("hid-a")}

	if got := <-order; got != "close-hid-a" {
		t.Fatalf("disconnect action = %q, want close-hid-a", got)
	}

	if got := <-order; got != "open-hid-b" {
		t.Fatalf("replacement action = %q, want open-hid-b", got)
	}

	waitForSelected(t, manager, attachmentID(transport.ModeHID, "hid-b"))
}

func TestDeviceManagerManualFailureRetainsAttachment(t *testing.T) {
	watcher := &fakeDeviceWatcher{
		snapshot: devicewatch.Snapshot{Candidates: []devicewatch.Candidate{
			hidCandidate("hid-a"),
			hidCandidate("hid-b"),
		}},
		events: make(chan devicewatch.Event),
	}
	opened := make(chan string, 4)

	manager := newTestDeviceManager(t, watcher, func(
		_ context.Context,
		_ transport.Mode,
		path string,
	) (*rtauthenticator.Opened, error) {
		opened <- path

		if path == "hid-b" {
			return nil, errors.New("hid-b cannot be opened")
		}

		return openedDevice(nil), nil
	})
	if got := <-opened; got != "hid-a" {
		t.Fatalf("initial open = %q", got)
	}

	if got := <-opened; got != "hid-b" {
		t.Fatalf("initial inspection = %q, want hid-b", got)
	}

	err := manager.SelectEndpoint(
		t.Context(),
		attachmentID(transport.ModeHID, "hid-b"),
	)
	if err == nil {
		t.Fatal("manual selection unexpectedly succeeded")
	}

	if got := <-opened; got != "hid-b" {
		t.Fatalf("manual open = %q", got)
	}

	if got := manager.State().Snapshot.SelectedEndpoint; got != attachmentID(transport.ModeHID, "hid-b") {
		t.Fatalf("selected after failure = %q", got)
	}

	if manager.State().Selected != nil {
		t.Fatal("failed attachment has runtime")
	}
}

func TestDeviceManagerRetriesReplacedCardOnly(t *testing.T) {
	first := smartCardCandidate("reader-a", 1)
	second := smartCardCandidate("reader-a", 2)
	watcher := &fakeDeviceWatcher{
		snapshot: devicewatch.Snapshot{Candidates: []devicewatch.Candidate{first}},
		events:   make(chan devicewatch.Event, 2),
	}

	var attemptCount atomic.Uint32

	attempts := make(chan byte, 2)
	manager := newTestDeviceManager(t, watcher, func(
		_ context.Context,
		_ transport.Mode,
		_ string,
	) (*rtauthenticator.Opened, error) {
		attempt := byte(attemptCount.Add(1))
		attempts <- attempt

		if attempt == 1 {
			return nil, errors.New("not a CTAP card")
		}

		return openedDevice(nil), nil
	})

	if got := <-attempts; got != 1 {
		t.Fatalf("initial attempt = %d", got)
	}

	if manager.State().Selected != nil {
		t.Fatal("unsupported card has runtime")
	}

	watcher.events <- devicewatch.Event{Type: devicewatch.EventDisconnected, Candidate: first}

	watcher.events <- devicewatch.Event{Type: devicewatch.EventConnected, Candidate: second}

	if got := <-attempts; got != 2 {
		t.Fatalf("replacement attempt = %d", got)
	}

	waitForSelected(
		t,
		manager,
		attachmentID(transport.ModeSmartCard, "reader-a"),
	)
}

func TestDeviceManagerCloseClosesSelection(t *testing.T) {
	watcher := &fakeDeviceWatcher{
		snapshot: devicewatch.Snapshot{Candidates: []devicewatch.Candidate{
			hidCandidate("hid-a"),
		}},
		events: make(chan devicewatch.Event),
	}
	closed := make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(t.Context())
	manager := newDeviceManager(
		ctx,
		cancel,
		watcher,
		func(
			context.Context,
			transport.Mode,
			string,
		) (*rtauthenticator.Opened, error) {
			return openedDevice(func() {
				closed <- struct{}{}
			}), nil
		},
		noSourceReader,
		nil,
	)
	<-manager.ready

	if err := manager.Close(); err != nil {
		t.Fatalf("close manager: %v", err)
	}

	select {
	case <-closed:
	default:
		t.Fatal("manager did not close its selected authenticator")
	}

	if manager.State().Selected != nil {
		t.Fatal("manager retained the closed authenticator")
	}
}

func newTestDeviceManager(
	t *testing.T,
	watcher devicewatch.Watcher,
	open authenticatorOpenFunc,
	options ...AuthenticatorOption,
) *DeviceManager {
	return newTestDeviceManagerWithResolver(
		t,
		watcher,
		open,
		noSourceReader,
		options...,
	)
}

func newTestDeviceManagerWithResolver(
	t *testing.T,
	watcher devicewatch.Watcher,
	open authenticatorOpenFunc,
	resolve sourceReadFunc,
	options ...AuthenticatorOption,
) *DeviceManager {
	t.Helper()

	ctx, cancel := context.WithCancel(t.Context())
	manager := newDeviceManager(ctx, cancel, watcher, open, noSourceReader, options)
	<-manager.ready
	manager.readSources = resolve

	t.Cleanup(func() {
		if err := manager.Close(); err != nil {
			t.Errorf("close device manager: %v", err)
		}
	})

	return manager
}

func noSourceReader(
	context.Context,
	attachment,
	*rtauthenticator.Opened,
) (vendorSources, error) {
	return vendorSources{yubico: report.YubicoSource{Outcome: sourceOutcome(nil)}, token2: report.Token2Source{Outcome: sourceOutcome(nil)}}, nil
}

func openedDevice(closed func()) *rtauthenticator.Opened {
	return &rtauthenticator.Opened{
		Lifecycle: &fakeDeviceLifecycle{close: closed},
		Info:      &contractAuthenticator{},
	}
}

func hidCandidate(path string) devicewatch.Candidate {
	return devicewatch.Candidate{
		Transport: transport.ModeHID,
		Path:      path,
		HID:       &ghid.DeviceInfo{Path: path},
	}
}

func smartCardCandidate(reader string, atr byte) devicewatch.Candidate {
	return devicewatch.Candidate{
		Transport: transport.ModeSmartCard,
		Path:      reader,
		SmartCard: &pcsc.ReaderInfo{
			Name:  reader,
			State: pcsc.ReaderStatePresent,
			ATR:   []byte{atr},
		},
	}
}

func attachmentID(
	mode transport.Mode,
	path string,
) report.AttachmentID {
	return report.AttachmentID(string(mode) + ":" + path)
}

func waitForDevices(
	t *testing.T,
	manager *DeviceManager,
	count int,
) {
	t.Helper()

	waitForDeviceManager(t, func() bool {
		return len(manager.State().Snapshot.Endpoints) == count
	})
}

func waitForSelected(
	t *testing.T,
	manager *DeviceManager,
	id report.AttachmentID,
) {
	t.Helper()

	waitForDeviceManager(t, func() bool {
		return manager.State().Snapshot.SelectedEndpoint == id
	})
}

func waitForDeviceManager(t *testing.T, condition func() bool) {
	t.Helper()

	deadline := time.Now().Add(time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("device manager state was not reached")
		}

		time.Sleep(time.Millisecond)
	}
}

func TestAttachmentPreservesIndependentHIDObservations(t *testing.T) {
	candidate := hidCandidate("bluetooth-hid")
	candidate.HID.HIDName = ghid.Descriptor[string]{Value: new("Kernel HID name")}
	candidate.HID.HIDUnique = ghid.Descriptor[string]{Value: new("transport-address")}
	candidate.HIDMetadataErr = errors.New("topology unavailable")

	usb := newAttachment(candidate).report.Attachment.USB
	if usb.HIDName.Value != *candidate.HID.HIDName.Value || usb.HIDName.State != report.DescriptorRead || usb.HIDUnique.Value != *candidate.HID.HIDUnique.Value || usb.HIDUnique.State != report.DescriptorRead || usb.MetadataError == nil {
		t.Fatalf("HID observations were lost: %#v", usb)
	}

	if usb.Product.State != report.DescriptorUnknown || usb.ReportedSerial.State != report.DescriptorUnknown {
		t.Fatalf("kernel strings were promoted to USB descriptors: %#v", usb)
	}
}

func TestHIDObservationUpdatePreservesSelectedRuntime(t *testing.T) {
	candidate := hidCandidate("one")
	candidate.HID.VendorID = ghid.Descriptor[uint16]{Err: errors.New("descriptor unavailable")}
	candidate.HIDMetadataErr = candidate.HID.VendorID.Err
	watcher := &fakeDeviceWatcher{
		snapshot: devicewatch.Snapshot{Candidates: []devicewatch.Candidate{candidate}},
		events:   make(chan devicewatch.Event, 1),
	}

	var opens, vendorReads atomic.Int32

	manager := newTestDeviceManagerWithResolver(t, watcher, func(context.Context, transport.Mode, string) (*rtauthenticator.Opened, error) {
		opens.Add(1)

		opened := openedDevice(nil)
		opened.Vendor = vendorReadFunc(func(context.Context, ctaphid.Command, []byte) (ctaphid.VendorResponse, error) {
			vendorReads.Add(1)
			return ctaphid.VendorResponse{Data: yubicoInfoPayload()}, nil
		})

		return opened, nil
	}, readVendorSources)
	previous := manager.State()
	selected := previous.Selected
	id := previous.Snapshot.SelectedEndpoint

	updated := hidCandidate("one")
	updated.HID.VendorID = ghid.Descriptor[uint16]{Value: new(yubicoVendorID)}

	updated.HID.ProductStr = ghid.Descriptor[string]{Value: new("YubiKey")}
	watcher.events <- devicewatch.Event{Type: devicewatch.EventUpdated, Candidate: updated}

	waitForDeviceManager(t, func() bool {
		return manager.State().Snapshot.Endpoints[0].Attachment.USB.VendorID.State == report.DescriptorRead
	})

	state := manager.State()

	usb := state.Snapshot.Endpoints[0].Attachment.USB
	if usb.Product.Value != "YubiKey" || usb.MetadataError != nil || usb.VendorID.Value != yubicoVendorID {
		t.Fatalf("updated USB observations = %#v", usb)
	}

	if state.Selected != selected || selected.Closed() || state.Snapshot.SelectedEndpoint != id || opens.Load() != 1 || vendorReads.Load() != 0 {
		t.Fatal("metadata update reopened the runtime or triggered a vendor probe")
	}

	if previous.Snapshot.Endpoints[0].Attachment.USB.VendorID.State != report.DescriptorFailed {
		t.Fatal("metadata update mutated the previous snapshot")
	}

	result, err := manager.ReadEndpointSources(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}

	if result.Sources.Yubico.Data == nil || result.Sources.Yubico.State != report.SourceAvailable || vendorReads.Load() != 1 {
		t.Fatalf("explicit vendor read after metadata update = %#v", result.Sources.Yubico)
	}

	if manager.State().Selected != selected || opens.Load() != 1 {
		t.Fatal("explicit source read replaced the selected runtime")
	}
}

func TestDiscoveryFailuresRemainInSnapshotsWithoutClosingSelection(t *testing.T) {
	initialErr := failure.Wrap(failure.CodeTransportFailure, errors.New("PC/SC unavailable"), failure.WithPhase(failure.PhaseDiscovery))
	watcher := &fakeDeviceWatcher{
		snapshot: devicewatch.Snapshot{Candidates: []devicewatch.Candidate{hidCandidate("a")}, Errors: map[transport.Mode]error{transport.ModeSmartCard: initialErr}},
		events:   make(chan devicewatch.Event, 1),
	}
	manager := newTestDeviceManager(t, watcher, func(context.Context, transport.Mode, string) (*rtauthenticator.Opened, error) {
		return openedDevice(nil), nil
	})
	previous := manager.State()

	selected := previous.Selected
	if got := previous.Snapshot.DiscoveryErrors[transport.ModeSmartCard]; got == nil || got.Phase != failure.PhaseDiscovery || got.Code != failure.CodeTransportFailure {
		t.Fatalf("initial discovery failure = %#v", got)
	}

	err := failure.Wrap(failure.CodeTransportFailure, errors.New("HID watcher failed"), failure.WithPhase(failure.PhaseDiscovery))
	watcher.events <- devicewatch.Event{Transport: transport.ModeHID, Err: err}

	waitForDeviceManager(t, func() bool { return manager.State().Snapshot.DiscoveryErrors[transport.ModeHID] != nil })

	if got := manager.State().Error; got == nil || got.Code != failure.CodeTransportFailure || got.Phase != failure.PhaseDiscovery {
		t.Fatalf("failure update = %#v", got)
	}

	if len(previous.Snapshot.DiscoveryErrors) != 1 {
		t.Fatal("new failure mutated the earlier snapshot")
	}

	if err := manager.SelectEndpoint(t.Context(), manager.State().Snapshot.SelectedEndpoint); err != nil {
		t.Fatal(err)
	}

	if len(manager.State().Snapshot.DiscoveryErrors) != 2 || manager.State().Selected != selected || selected.Closed() {
		t.Fatal("report update lost failures or closed a usable runtime")
	}
}
