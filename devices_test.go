package ctapkit

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ghid "github.com/telesma-app/hid"
	rtauthenticator "github.com/telesma-app/kit/internal/authenticator"
	"github.com/telesma-app/kit/internal/devicewatch"
	"github.com/telesma-app/kit/model/failure"
	"github.com/telesma-app/kit/model/report"
	"github.com/telesma-app/kit/transport"
	"github.com/telesma-app/pcsc"
	"github.com/telesma-app/token2"
	"github.com/telesma-app/yubico"
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
		Connected: true,
		Candidate: hidCandidate("hid-0"),
	}
	waitForDevices(t, manager, 4)
	state := manager.State()
	if state.Selected != selected {
		t.Fatal("new candidate replaced the selected authenticator")
	}
	if state.Snapshot.Selected != selected.Device().Attachment.ID {
		t.Fatalf(
			"snapshot selection = %q, runtime selection = %q",
			state.Snapshot.Selected,
			selected.Device().Attachment.ID,
		)
	}
	update := <-manager.Updates()
	if update.Selected != selected || len(update.Snapshot.Devices) != 4 {
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

	if got := manager.State().Snapshot.Selected; got != attachmentID(transport.ModeHID, "hid-b") {
		t.Fatalf("selected = %q, want hid-b", got)
	}
	watcher.events <- devicewatch.Event{Candidate: hidCandidate("hid-b")}
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
	watcher.events <- devicewatch.Event{Candidate: hidCandidate("hid-a")}
	if got := <-order; got != "close-hid-a" {
		t.Fatalf("disconnect action = %q, want close-hid-a", got)
	}
	if got := <-order; got != "open-hid-b" {
		t.Fatalf("replacement action = %q, want open-hid-b", got)
	}
	waitForSelected(t, manager, attachmentID(transport.ModeHID, "hid-b"))
}

func TestDeviceManagerManualFailureFallsBack(t *testing.T) {
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

	err := manager.Select(
		t.Context(),
		attachmentID(transport.ModeHID, "hid-b"),
	)
	if err == nil {
		t.Fatal("manual selection unexpectedly succeeded")
	}
	if got := <-opened; got != "hid-b" {
		t.Fatalf("manual open = %q", got)
	}
	if got := <-opened; got != "hid-a" {
		t.Fatalf("fallback open = %q", got)
	}
	if got := manager.State().Snapshot.Selected; got != attachmentID(transport.ModeHID, "hid-a") {
		t.Fatalf("selected after fallback = %q", got)
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
	if manager.State().Snapshot.Selected != "" {
		t.Fatal("unsupported card was selected")
	}
	watcher.events <- devicewatch.Event{Candidate: first}
	watcher.events <- devicewatch.Event{Connected: true, Candidate: second}
	if got := <-attempts; got != 2 {
		t.Fatalf("replacement attempt = %d", got)
	}
	waitForSelected(
		t,
		manager,
		attachmentID(transport.ModeSmartCard, "reader-a"),
	)
}

func TestDeviceManagerPublishesFullyEnrichedInitialSnapshot(t *testing.T) {
	card := smartCardCandidate("reader-a", 1)
	hid := hidCandidate("hid-a")
	hid.HID.VendorID = yubicoVendorID
	watcher := &fakeDeviceWatcher{
		snapshot: devicewatch.Snapshot{Candidates: []devicewatch.Candidate{
			hid,
			card,
		}},
		events: make(chan devicewatch.Event),
	}
	manager := newTestDeviceManagerWithResolver(
		t,
		watcher,
		func(context.Context, transport.Mode, string) (*rtauthenticator.Opened, error) {
			return openedDevice(nil), nil
		},
		func(
			_ context.Context,
			target attachment,
			_ rtauthenticator.VendorProvider,
		) (deviceMetadata, error) {
			if target.mode == transport.ModeSmartCard {
				return deviceMetadata{Token2: &token2.DeviceInfo{
					SerialNumber: "76202000000001",
					Branding:     "Token2",
					FormFactor:   "FIDO Card",
				}}, nil
			}

			serial := uint32(12345678)
			return deviceMetadata{Yubico: &yubico.DeviceInfo{
				Serial:          &serial,
				FirmwareVersion: yubico.FirmwareVersion{Major: 5, Minor: 7, Build: 1},
				FormFactor:      yubico.FormFactorUSBCKeychain,
			}}, nil
		},
	)

	update := <-manager.Updates()
	if update.Snapshot.Selected != attachmentID(transport.ModeHID, "hid-a") {
		t.Fatalf("selected = %q", update.Snapshot.Selected)
	}
	want := map[report.AttachmentID]string{
		attachmentID(transport.ModeHID, hid.Path):        "12345678",
		attachmentID(transport.ModeSmartCard, card.Path): "76202000000001",
	}
	for _, device := range update.Snapshot.Devices {
		if device.Attachment.Transport == transport.ModeSmartCard &&
			device.Attachment.SmartCard.Interface != transport.SmartCardInterfaceContactless {
			t.Fatalf(
				"smart-card interface = %q, want contactless",
				device.Attachment.SmartCard.Interface,
			)
		}
		serial, ok := want[device.Attachment.ID]
		if !ok {
			t.Fatalf("unexpected device %q", device.Attachment.ID)
		}
		if device.Identity == nil || device.Identity.SerialNumber != serial {
			t.Fatalf("device %q identity = %#v", device.Attachment.ID, device.Identity)
		}
		delete(want, device.Attachment.ID)
	}
	if len(want) != 0 {
		t.Fatalf("missing enriched devices: %v", want)
	}
	select {
	case extra := <-manager.Updates():
		t.Fatalf("unexpected intermediate update: %#v", extra.Snapshot)
	default:
	}
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
		noDeviceMetadataResolver,
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
		noDeviceMetadataResolver,
		options...,
	)
}

func newTestDeviceManagerWithResolver(
	t *testing.T,
	watcher devicewatch.Watcher,
	open authenticatorOpenFunc,
	resolve deviceMetadataResolveFunc,
	options ...AuthenticatorOption,
) *DeviceManager {
	t.Helper()

	ctx, cancel := context.WithCancel(t.Context())
	manager := newDeviceManager(ctx, cancel, watcher, open, resolve, options)
	<-manager.ready
	t.Cleanup(func() {
		if err := manager.Close(); err != nil {
			t.Errorf("close device manager: %v", err)
		}
	})

	return manager
}

func noDeviceMetadataResolver(
	context.Context,
	attachment,
	rtauthenticator.VendorProvider,
) (deviceMetadata, error) {
	return deviceMetadata{}, nil
}

func openedDevice(closed func()) *rtauthenticator.Opened {
	return &rtauthenticator.Opened{
		Lifecycle: &fakeDeviceLifecycle{close: closed},
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
		Transport:          transport.ModeSmartCard,
		Path:               reader,
		SmartCardInterface: transport.SmartCardInterfaceContactless,
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
		return len(manager.State().Snapshot.Devices) == count
	})
}

func waitForSelected(
	t *testing.T,
	manager *DeviceManager,
	id report.AttachmentID,
) {
	t.Helper()

	waitForDeviceManager(t, func() bool {
		return manager.State().Snapshot.Selected == id
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
