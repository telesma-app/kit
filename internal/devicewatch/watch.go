package devicewatch

import (
	"context"
	"errors"
	"iter"
	"maps"
	"slices"
	"sync"
	"time"

	directhid "github.com/telesma-app/ctap/backend/hid"
	"github.com/telesma-app/ctap/backend/hidproxy"
	ghid "github.com/telesma-app/hid"
	"github.com/telesma-app/kit/model/failure"
	"github.com/telesma-app/kit/transport"
	"github.com/telesma-app/pcsc"
)

const hidSettleDelay = 100 * time.Millisecond

type Candidate struct {
	Transport      transport.Mode
	Path           string
	HID            *ghid.DeviceInfo
	HIDMetadataErr error
	SmartCard      *pcsc.ReaderInfo
}

type EventType string

const (
	EventConnected    EventType = "connected"
	EventUpdated      EventType = "updated"
	EventDisconnected EventType = "disconnected"
)

// Type and Candidate describe topology changes. Transport and Err report a
// stopped discovery source independently of endpoint events.
type Event struct {
	Type      EventType
	Candidate Candidate
	Transport transport.Mode // Set with Err when a discovery source stops.
	Err       error
}

type Snapshot struct {
	Candidates []Candidate
	Errors     map[transport.Mode]error
}

type Watcher interface {
	Snapshot() Snapshot
	Listen() <-chan Event
	Close() error
}

type watcher struct {
	ctx      context.Context
	cancel   context.CancelFunc
	snapshot Snapshot
	events   chan Event
	done     chan struct{}

	hidMode       transport.Mode
	hidCurrent    map[string]Candidate
	hidEvents     <-chan ghid.DeviceEvent
	proxyEvents   <-chan hidproxy.DeviceEvent
	proxyCancel   context.CancelFunc
	pcscEvents    <-chan pcsc.DeviceEvent
	pcscCurrent   map[string]Candidate
	hidWatcher    ghid.Watcher
	pcscWatcher   pcsc.Watcher
	reconcileOnce bool

	closeOnce sync.Once
	runErr    error
	closeErr  error
}

func Watch(ctx context.Context, requested transport.Mode) (Watcher, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	modes, err := sourceModes(requested)
	if err != nil {
		return nil, err
	}

	watchCtx, cancel := context.WithCancel(ctx)
	result := &watcher{
		ctx:    watchCtx,
		cancel: cancel,
		events: make(chan Event),
		done:   make(chan struct{}),

		snapshot:    Snapshot{Errors: make(map[transport.Mode]error)},
		pcscCurrent: make(map[string]Candidate),
	}

	var sourceErr error

	for _, mode := range modes {
		switch mode {
		case transport.ModeHID, transport.ModeWindowsProxy:
			err = result.openHID(mode)
		case transport.ModeSmartCard:
			err = result.openSmartCards()
		}

		if err != nil {
			result.snapshot.Errors[mode] = discoveryFailure(mode, err)
			sourceErr = errors.Join(sourceErr, err)
		}
	}

	if result.hidEvents == nil &&
		result.proxyEvents == nil &&
		result.pcscEvents == nil {
		cancel()

		return nil, sourceErr
	}

	go result.run()

	return result, nil
}

func (w *watcher) Snapshot() Snapshot {
	return w.snapshot
}

func (w *watcher) Listen() <-chan Event {
	return w.events
}

func (w *watcher) Close() error {
	w.closeOnce.Do(func() {
		w.cancel()

		if w.hidWatcher != nil {
			w.closeErr = errors.Join(w.closeErr, w.hidWatcher.Close())
		}

		if w.pcscWatcher != nil {
			w.closeErr = errors.Join(w.closeErr, w.pcscWatcher.Close())
		}

		<-w.done
	})

	return errors.Join(w.runErr, w.closeErr)
}

func (w *watcher) run() {
	defer close(w.done)
	defer close(w.events)

	if w.reconcileOnce {
		if !w.waitHID() {
			return
		}

		if err := w.refreshHID(); err != nil {
			w.stopHID(err)
		}
	}

	for w.hidEvents != nil ||
		w.proxyEvents != nil ||
		w.pcscEvents != nil {
		select {
		case <-w.ctx.Done():
			return

		case event, ok := <-w.hidEvents:
			if !ok {
				w.stopHID(nil)
				continue
			}

			if event.Type == ghid.DeviceEventDisconnected &&
				event.DeviceInfo != nil &&
				event.DeviceInfo.Path != "" {
				if candidate, exists := w.hidCurrent[event.DeviceInfo.Path]; exists {
					delete(w.hidCurrent, candidate.Path)

					if !w.send(Event{Type: EventDisconnected, Candidate: candidate}) {
						return
					}

					continue
				}
			}

			if !w.waitHID() {
				return
			}

			if err := w.refreshHID(); err != nil {
				w.stopHID(err)
			}

		case event, ok := <-w.proxyEvents:
			if !ok {
				w.stopHID(nil)
				continue
			}

			if event.Err != nil {
				w.stopHID(event.Err)

				continue
			}

			if !w.waitHID() {
				return
			}

			if err := w.refreshHID(); err != nil {
				w.stopHID(err)
			}

		case event, ok := <-w.pcscEvents:
			if !ok {
				w.stopPCSC()
				continue
			}

			switch event.Type {
			case pcsc.DeviceEventCardInserted:
				candidate := w.connectSmartCard(event.ReaderInfo)
				if !w.send(Event{
					Type:      EventConnected,
					Candidate: candidate,
				}) {
					return
				}
			case pcsc.DeviceEventCardRemoved:
				candidate, ok := w.disconnectSmartCard(event.ReaderInfo.Name)
				if ok && !w.send(Event{Type: EventDisconnected, Candidate: candidate}) {
					return
				}
			}
		}
	}
}

func (w *watcher) openHID(mode transport.Mode) error {
	w.hidMode = mode
	if mode == transport.ModeWindowsProxy {
		proxyCtx, cancel := context.WithCancel(w.ctx)

		events, err := hidproxy.Events(proxyCtx)
		if err != nil {
			cancel()

			return err
		}

		w.proxyEvents = events
		w.proxyCancel = cancel
	} else {
		raw, err := ghid.Watch()
		if err != nil {
			return err
		}

		w.hidWatcher = raw

		w.hidEvents = raw.Listen()
		for _, device := range raw.Snapshot().Devices {
			w.reconcileOnce = w.reconcileOnce ||
				device.MetadataErr != nil ||
				incompleteHID(device.DeviceInfo)
		}
	}

	current, err := enumerateHID(w.ctx, mode)
	if err != nil {
		if w.hidWatcher != nil {
			err = errors.Join(err, w.hidWatcher.Close())
			w.hidWatcher = nil
			w.hidEvents = nil
		}

		if w.proxyCancel != nil {
			w.proxyCancel()
			w.proxyCancel = nil
		}

		w.proxyEvents = nil
		w.reconcileOnce = false

		return err
	}

	w.hidCurrent = current
	for _, path := range slices.Sorted(maps.Keys(current)) {
		w.snapshot.Candidates = append(w.snapshot.Candidates, current[path])
	}

	return nil
}

func (w *watcher) openSmartCards() error {
	raw, err := pcsc.Watch()
	if err != nil {
		return err
	}

	w.pcscWatcher = raw

	w.pcscEvents = raw.Listen()
	for _, reader := range raw.Snapshot().Readers {
		if reader.State&pcsc.ReaderStatePresent != 0 {
			w.snapshot.Candidates = append(w.snapshot.Candidates, w.connectSmartCard(reader))
		}
	}

	return nil
}

func (w *watcher) connectSmartCard(reader *pcsc.ReaderInfo) Candidate {
	candidate := Candidate{
		Transport: transport.ModeSmartCard,
		Path:      reader.Name,
		SmartCard: reader,
	}
	w.pcscCurrent[candidate.Path] = candidate

	return candidate
}

func (w *watcher) disconnectSmartCard(reader string) (Candidate, bool) {
	candidate, ok := w.pcscCurrent[reader]
	if ok {
		delete(w.pcscCurrent, reader)
	}

	return candidate, ok
}

func (w *watcher) refreshHID() error {
	next, err := enumerateHID(w.ctx, w.hidMode)
	if err != nil {
		return err
	}

	return w.reconcileHID(next)
}

func (w *watcher) reconcileHID(next map[string]Candidate) error {
	for _, path := range slices.Sorted(maps.Keys(w.hidCurrent)) {
		if _, present := next[path]; !present &&
			!w.send(Event{Type: EventDisconnected, Candidate: w.hidCurrent[path]}) {
			return w.ctx.Err()
		}
	}

	for _, path := range slices.Sorted(maps.Keys(next)) {
		previous, present := w.hidCurrent[path]
		kind := EventConnected

		if present {
			if equalHIDObservations(previous, next[path]) {
				continue
			}

			kind = EventUpdated
		}

		if !w.send(Event{Type: kind, Candidate: next[path]}) {
			return w.ctx.Err()
		}
	}

	w.hidCurrent = next

	return nil
}

func equalHIDObservations(left, right Candidate) bool {
	a, b := left.HID, right.HID

	return a.Path == b.Path &&
		a.ReleaseNbr == b.ReleaseNbr &&
		a.UsagePage == b.UsagePage &&
		a.Usage == b.Usage &&
		a.InterfaceNbr == b.InterfaceNbr &&
		a.InstanceID == b.InstanceID &&
		a.ParentDeviceID == b.ParentDeviceID &&
		equalDescriptor(a.VendorID, b.VendorID) &&
		equalDescriptor(a.ProductID, b.ProductID) &&
		equalDescriptor(a.SerialNbr, b.SerialNbr) &&
		equalDescriptor(a.MfrStr, b.MfrStr) &&
		equalDescriptor(a.ProductStr, b.ProductStr) &&
		equalDescriptor(a.HIDName, b.HIDName) &&
		equalDescriptor(a.HIDUnique, b.HIDUnique) &&
		equalMetadataError(left.HIDMetadataErr, right.HIDMetadataErr)
}

func equalDescriptor[T comparable](left, right ghid.Descriptor[T]) bool {
	if (left.Value == nil) != (right.Value == nil) {
		return false
	}

	return (left.Value == nil || *left.Value == *right.Value) && equalMetadataError(left.Err, right.Err)
}

// Repeated native reads may allocate equivalent errors independently.
func equalMetadataError(left, right error) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}

	return left.Error() == right.Error()
}

func (w *watcher) stopHID(err error) {
	if w.ctx.Err() == nil && w.hidWatcher != nil {
		err = errors.Join(err, w.hidWatcher.Close())
	}

	if w.proxyCancel != nil {
		w.proxyCancel()
		w.proxyCancel = nil
	}

	w.hidEvents = nil
	w.proxyEvents = nil
	w.reportFailure(w.hidMode, err)
}

func (w *watcher) stopPCSC() {
	var err error

	if w.ctx.Err() == nil && w.pcscWatcher != nil {
		err = w.pcscWatcher.Close()
	}

	w.pcscEvents = nil
	w.reportFailure(transport.ModeSmartCard, err)
}

func (w *watcher) reportFailure(mode transport.Mode, err error) {
	if w.ctx.Err() != nil {
		return
	}

	err = discoveryFailure(mode, err)
	w.runErr = errors.Join(w.runErr, err)
	w.send(Event{Transport: mode, Err: err})
}

func discoveryFailure(mode transport.Mode, err error) error {
	code := failure.CodeTransportFailure
	if mode == transport.ModeWindowsProxy {
		code = failure.CodeTransportProxyUnavailable
	}

	return failure.Wrap(code, err, failure.WithPhase(failure.PhaseDiscovery))
}

func (w *watcher) waitHID() bool {
	timer := time.NewTimer(hidSettleDelay)
	defer timer.Stop()

	select {
	case <-w.ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func (w *watcher) send(event Event) bool {
	select {
	case w.events <- event:
		return true
	case <-w.ctx.Done():
		return false
	}
}

func enumerateHID(
	ctx context.Context,
	mode transport.Mode,
) (map[string]Candidate, error) {
	var enumerate func(context.Context) iter.Seq2[*ghid.DeviceInfo, error]

	switch mode {
	case transport.ModeHID:
		enumerate = directhid.Devices
	case transport.ModeWindowsProxy:
		enumerate = hidproxy.Devices
	default:
		panic("devicewatch: invalid HID transport mode: " + string(mode))
	}

	candidates := make(map[string]Candidate)

	for info, err := range enumerate(ctx) {
		if info == nil {
			return nil, err
		}

		candidates[info.Path] = Candidate{
			Transport:      mode,
			Path:           info.Path,
			HID:            info,
			HIDMetadataErr: err,
		}
	}

	return candidates, nil
}

func incompleteHID(info *ghid.DeviceInfo) bool {
	return info == nil ||
		info.Path == "" ||
		info.UsagePage == 0 ||
		info.Usage == 0
}

func sourceModes(requested transport.Mode) ([]transport.Mode, error) {
	if requested == "" {
		requested = transport.ModeAuto
	}

	switch requested {
	case transport.ModeAuto:
		hidMode, err := resolveHIDMode(requested)
		if err != nil {
			return nil, err
		}

		return []transport.Mode{hidMode, transport.ModeSmartCard}, nil
	case transport.ModeHID, transport.ModeWindowsProxy:
		hidMode, err := resolveHIDMode(requested)
		if err != nil {
			return nil, err
		}

		return []transport.Mode{hidMode}, nil
	case transport.ModeSmartCard:
		return []transport.Mode{transport.ModeSmartCard}, nil
	default:
		return nil, failure.New(failure.CodeTransportModeUnsupported,
			failure.WithPhase(failure.PhaseValidation),
		)
	}
}
