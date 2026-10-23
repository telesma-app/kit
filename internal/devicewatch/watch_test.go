package devicewatch

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/telesma-app/ctap/backend/hidproxy"
	ghid "github.com/telesma-app/hid"
	"github.com/telesma-app/kit/model/failure"
	"github.com/telesma-app/kit/transport"
	"github.com/telesma-app/pcsc"
)

func TestWatcherPublishesAttachmentsWithoutRequiringFIDO(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	pcscEvents := make(chan pcsc.DeviceEvent, 4)

	w := &watcher{
		ctx:         ctx,
		cancel:      cancel,
		events:      make(chan Event),
		done:        make(chan struct{}),
		pcscEvents:  pcscEvents,
		pcscCurrent: make(map[string]Candidate),
	}
	go w.run()

	ccid := &pcsc.ReaderInfo{Name: "ccid-reader", State: pcsc.ReaderStatePresent}
	fido := &pcsc.ReaderInfo{Name: "fido-reader", State: pcsc.ReaderStatePresent}

	pcscEvents <- pcsc.DeviceEvent{
		Type:       pcsc.DeviceEventCardInserted,
		ReaderInfo: ccid,
	}

	pcscEvents <- pcsc.DeviceEvent{
		Type:       pcsc.DeviceEventCardInserted,
		ReaderInfo: fido,
	}

	pcscEvents <- pcsc.DeviceEvent{
		Type:       pcsc.DeviceEventCardRemoved,
		ReaderInfo: ccid,
	}

	pcscEvents <- pcsc.DeviceEvent{
		Type:       pcsc.DeviceEventCardRemoved,
		ReaderInfo: fido,
	}

	close(pcscEvents)

	var got []Event
	for event := range w.events {
		got = append(got, event)
	}

	if len(got) != 5 {
		t.Fatalf("events = %#v, want every attachment", got)
	}

	if got[0].Candidate.Path != "ccid-reader" || got[0].Candidate.SmartCard != ccid {
		t.Fatalf("unknown attachment = %#v", got[0])
	}

	if got[1].Type != EventConnected || got[1].Candidate.SmartCard != fido {
		t.Fatalf("FIDO attachment = %#v", got[1])
	}

	if got[4].Transport != transport.ModeSmartCard || !failure.IsCode(got[4].Err, failure.CodeTransportFailure) {
		t.Fatalf("terminal failure = %#v", got[4])
	}

	if got[2].Type != EventDisconnected || got[3].Type != EventDisconnected {
		t.Fatal("missing disconnects")
	}
}

func TestProxyFailureLeavesSmartCardDiscoveryRunning(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	proxyEvents := make(chan hidproxy.DeviceEvent, 1)
	pcscEvents := make(chan pcsc.DeviceEvent, 1)

	w := &watcher{
		ctx: ctx, cancel: cancel,
		events: make(chan Event), done: make(chan struct{}),
		hidMode: transport.ModeWindowsProxy, proxyEvents: proxyEvents,
		pcscEvents: pcscEvents, pcscCurrent: make(map[string]Candidate),
	}
	go w.run()

	t.Cleanup(func() { _ = w.Close() })

	want := errors.New("proxy connection lost")
	proxyEvents <- hidproxy.DeviceEvent{Err: want}

	select {
	case event := <-w.Listen():
		if event.Transport != transport.ModeWindowsProxy || !errors.Is(event.Err, want) || !failure.IsCode(event.Err, failure.CodeTransportProxyUnavailable) {
			t.Fatalf("proxy failure = %#v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("proxy failure was not published")
	}

	reader := &pcsc.ReaderInfo{Name: "reader", State: pcsc.ReaderStatePresent}
	pcscEvents <- pcsc.DeviceEvent{Type: pcsc.DeviceEventCardInserted, ReaderInfo: reader}

	select {
	case event := <-w.Listen():
		if event.Type != EventConnected || event.Candidate.SmartCard != reader || event.Err != nil {
			t.Fatalf("smart-card arrival = %#v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("healthy source stopped after proxy failure")
	}

	if err := w.Close(); !errors.Is(err, want) {
		t.Fatalf("Close = %v, want proxy cause", err)
	}
}

func TestWatcherCancellationDoesNotReportDiscoveryFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())

	w := &watcher{ctx: ctx, cancel: cancel, events: make(chan Event), done: make(chan struct{}), pcscEvents: make(chan pcsc.DeviceEvent)}
	go w.run()

	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	if event, ok := <-w.Listen(); ok {
		t.Fatalf("shutdown emitted %#v", event)
	}
}

type failedHIDWatcher struct {
	events chan ghid.DeviceEvent
	err    error
}

func (w *failedHIDWatcher) Snapshot() ghid.Snapshot         { return ghid.Snapshot{} }
func (w *failedHIDWatcher) Listen() <-chan ghid.DeviceEvent { return w.events }
func (w *failedHIDWatcher) Close() error                    { return w.err }

func TestClosedHIDWatcherPublishesTerminalCause(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	want := errors.New("native HID monitoring failed")
	raw := &failedHIDWatcher{events: make(chan ghid.DeviceEvent), err: want}

	w := &watcher{ctx: ctx, cancel: cancel, events: make(chan Event), done: make(chan struct{}), hidMode: transport.ModeHID, hidWatcher: raw, hidEvents: raw.Listen()}
	go w.run()

	t.Cleanup(func() { _ = w.Close() })

	close(raw.events)

	select {
	case event := <-w.Listen():
		if event.Transport != transport.ModeHID || !errors.Is(event.Err, want) || !failure.IsCode(event.Err, failure.CodeTransportFailure) {
			t.Fatalf("HID failure = %#v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("terminal native error was not published")
	}

	if err := w.Close(); !errors.Is(err, want) {
		t.Fatalf("Close = %v, want native cause", err)
	}
}

func TestHIDReconciliationPublishesRecoveredMetadata(t *testing.T) {
	previous := &ghid.DeviceInfo{
		Path:      "token",
		UsagePage: 0xf1d0,
		Usage:     1,
		VendorID:  ghid.Descriptor[uint16]{Err: errors.New("descriptor not ready")},
	}
	current := &ghid.DeviceInfo{
		Path:       "token",
		UsagePage:  0xf1d0,
		Usage:      1,
		VendorID:   ghid.Descriptor[uint16]{Value: new(uint16(0x1050))},
		ProductStr: ghid.Descriptor[string]{Value: new("YubiKey")},
	}
	w := &watcher{
		ctx:    t.Context(),
		events: make(chan Event, 1),
		hidCurrent: map[string]Candidate{
			"token": {Transport: transport.ModeHID, Path: "token", HID: previous, HIDMetadataErr: previous.VendorID.Err},
		},
	}
	next := map[string]Candidate{"token": {Transport: transport.ModeHID, Path: "token", HID: current}}

	if err := w.reconcileHID(next); err != nil {
		t.Fatal(err)
	}

	select {
	case event := <-w.events:
		if event.Type != EventUpdated || event.Candidate.HID != current || event.Candidate.HIDMetadataErr != nil {
			t.Fatalf("recovered metadata = %#v", event)
		}
	default:
		t.Fatal("recovered metadata was not published")
	}

	if err := w.reconcileHID(next); err != nil {
		t.Fatal(err)
	}

	select {
	case event := <-w.events:
		t.Fatalf("unchanged metadata emitted another event: %#v", event)
	default:
	}
}

func TestHIDReconciliationComparesObservationValues(t *testing.T) {
	for _, test := range []struct {
		name    string
		update  func(*Candidate)
		changed bool
	}{
		{name: "equivalent values and allocated errors"},
		{name: "reported empty serial", update: func(candidate *Candidate) { candidate.HID.SerialNbr.Value = new("") }, changed: true},
		{name: "reported zero product ID", update: func(candidate *Candidate) { candidate.HID.ProductID.Value = new(uint16(0)) }, changed: true},
		{name: "descriptor error", update: func(candidate *Candidate) { candidate.HID.HIDUnique.Err = errors.New("identifier read failed") }, changed: true},
		{name: "metadata error", update: func(candidate *Candidate) { candidate.HIDMetadataErr = errors.New("metadata read failed") }, changed: true},
		{name: "recovered metadata error", update: func(candidate *Candidate) { candidate.HIDMetadataErr = nil }, changed: true},
		{name: "release number", update: func(candidate *Candidate) { candidate.HID.ReleaseNbr++ }, changed: true},
		{name: "interface number", update: func(candidate *Candidate) { candidate.HID.InterfaceNbr++ }, changed: true},
		{name: "parent device", update: func(candidate *Candidate) { candidate.HID.ParentDeviceID = "other-parent" }, changed: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			observation := func() Candidate {
				return Candidate{
					Transport:      transport.ModeHID,
					Path:           "token",
					HIDMetadataErr: errors.New("descriptor not ready"),
					HID: &ghid.DeviceInfo{
						Path:           "token",
						UsagePage:      0xf1d0,
						Usage:          1,
						VendorID:       ghid.Descriptor[uint16]{Value: new(uint16(0x1050))},
						ProductStr:     ghid.Descriptor[string]{Value: new("YubiKey")},
						HIDUnique:      ghid.Descriptor[string]{Err: errors.New("descriptor not ready")},
						ParentDeviceID: "parent",
					},
				}
			}

			previous, current := observation(), observation()
			if test.update != nil {
				test.update(&current)
			}

			w := &watcher{ctx: t.Context(), events: make(chan Event, 1), hidCurrent: map[string]Candidate{"token": previous}}
			if err := w.reconcileHID(map[string]Candidate{"token": current}); err != nil {
				t.Fatal(err)
			}

			select {
			case event := <-w.events:
				if !test.changed || event.Type != EventUpdated || event.Candidate.HID != current.HID {
					t.Fatalf("metadata update = %#v, changed = %v", event, test.changed)
				}
			default:
				if test.changed {
					t.Fatal("changed observation was not published")
				}
			}
		})
	}
}

func TestHIDReconciliationOrdersTopologyAndMetadataChanges(t *testing.T) {
	candidate := func(path, product string) Candidate {
		return Candidate{Transport: transport.ModeHID, Path: path, HID: &ghid.DeviceInfo{Path: path, ProductStr: ghid.Descriptor[string]{Value: new(product)}}}
	}
	w := &watcher{
		ctx:    t.Context(),
		events: make(chan Event, 8),
		hidCurrent: map[string]Candidate{
			"removed-z": candidate("removed-z", "removed"),
			"removed-a": candidate("removed-a", "removed"),
			"updated-b": candidate("updated-b", "old"),
			"unchanged": candidate("unchanged", "same"),
		},
	}
	next := map[string]Candidate{
		"updated-b": candidate("updated-b", "new"),
		"added-c":   candidate("added-c", "added"),
		"added-a":   candidate("added-a", "added"),
		"unchanged": candidate("unchanged", "same"),
	}

	if err := w.reconcileHID(next); err != nil {
		t.Fatal(err)
	}

	type change struct {
		typeName EventType
		path     string
	}

	var got []change

	for len(w.events) != 0 {
		event := <-w.events
		got = append(got, change{typeName: event.Type, path: event.Candidate.Path})
	}

	want := []change{
		{typeName: EventDisconnected, path: "removed-a"},
		{typeName: EventDisconnected, path: "removed-z"},
		{typeName: EventConnected, path: "added-a"},
		{typeName: EventConnected, path: "added-c"},
		{typeName: EventUpdated, path: "updated-b"},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("changes = %v, want %v", got, want)
	}

	if len(w.hidCurrent) != len(next) || w.hidCurrent["updated-b"].HID != next["updated-b"].HID {
		t.Fatalf("current HID snapshot = %#v", w.hidCurrent)
	}
}
