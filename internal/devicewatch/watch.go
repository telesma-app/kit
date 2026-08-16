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
	ctapiso7816 "github.com/telesma-app/ctap/transport/iso7816"
	ghid "github.com/telesma-app/hid"
	"github.com/telesma-app/kit/model/failure"
	"github.com/telesma-app/kit/transport"
	"github.com/telesma-app/pcsc"
)

const hidSettleDelay = 100 * time.Millisecond

type Candidate struct {
	Transport          transport.Mode
	Path               string
	HID                *ghid.DeviceInfo
	SmartCard          *pcsc.ReaderInfo
	SmartCardInterface transport.SmartCardInterface
}

type Event struct {
	Connected bool
	Candidate Candidate
}

type Snapshot struct {
	Candidates []Candidate
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

	probeSmartCard func(
		context.Context,
		string,
	) (transport.SmartCardInterface, error)

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

		pcscCurrent:    make(map[string]Candidate),
		probeSmartCard: probeSmartCard,
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
		if !w.reconcileHID() {
			w.stopHID()
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
				w.stopHID()
				continue
			}
			if event.Type == ghid.DeviceEventDisconnected &&
				event.DeviceInfo != nil &&
				event.DeviceInfo.Path != "" {
				if candidate, exists := w.hidCurrent[event.DeviceInfo.Path]; exists {
					delete(w.hidCurrent, candidate.Path)
					if !w.send(Event{Candidate: candidate}) {
						return
					}

					continue
				}
			}
			if !w.waitHID() || !w.reconcileHID() {
				w.stopHID()
			}

		case event, ok := <-w.proxyEvents:
			if !ok {
				w.stopHID()
				continue
			}
			if event.Err != nil {
				w.runErr = errors.Join(w.runErr, event.Err)
				w.stopHID()
				continue
			}
			if !w.waitHID() || !w.reconcileHID() {
				w.stopHID()
			}

		case event, ok := <-w.pcscEvents:
			if !ok {
				w.stopPCSC()
				continue
			}
			switch event.Type {
			case pcsc.DeviceEventCardInserted:
				candidate, ok := w.connectSmartCard(event.ReaderInfo)
				if ok && !w.send(Event{
					Connected: true,
					Candidate: candidate,
				}) {
					return
				}
			case pcsc.DeviceEventCardRemoved:
				candidate, ok := w.disconnectSmartCard(event.ReaderInfo.Name)
				if ok && !w.send(Event{Candidate: candidate}) {
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
			candidate, ok := w.connectSmartCard(reader)
			if ok {
				w.snapshot.Candidates = append(
					w.snapshot.Candidates,
					candidate,
				)
			}
		}
	}

	return nil
}

func (w *watcher) connectSmartCard(reader *pcsc.ReaderInfo) (Candidate, bool) {
	cardInterface, err := w.probeSmartCard(w.ctx, reader.Name)
	if err != nil {
		return Candidate{}, false
	}

	candidate := smartCardCandidate(reader, cardInterface)
	w.pcscCurrent[candidate.Path] = candidate

	return candidate, true
}

func (w *watcher) disconnectSmartCard(reader string) (Candidate, bool) {
	candidate, ok := w.pcscCurrent[reader]
	if ok {
		delete(w.pcscCurrent, reader)
	}

	return candidate, ok
}

func (w *watcher) reconcileHID() bool {
	next, err := enumerateHID(w.ctx, w.hidMode)
	if err != nil {
		if w.ctx.Err() == nil {
			w.runErr = errors.Join(w.runErr, err)
		}

		return false
	}

	for _, path := range slices.Sorted(maps.Keys(w.hidCurrent)) {
		if next[path].Path == "" &&
			!w.send(Event{Candidate: w.hidCurrent[path]}) {
			return false
		}
	}
	for _, path := range slices.Sorted(maps.Keys(next)) {
		if w.hidCurrent[path].Path == "" &&
			!w.send(Event{Connected: true, Candidate: next[path]}) {
			return false
		}
	}
	w.hidCurrent = next

	return true
}

func (w *watcher) stopHID() {
	if w.ctx.Err() == nil && w.hidWatcher != nil {
		w.runErr = errors.Join(w.runErr, w.hidWatcher.Close())
	}
	if w.proxyCancel != nil {
		w.proxyCancel()
		w.proxyCancel = nil
	}
	w.hidEvents = nil
	w.proxyEvents = nil
}

func (w *watcher) stopPCSC() {
	if w.ctx.Err() == nil && w.pcscWatcher != nil {
		w.runErr = errors.Join(w.runErr, w.pcscWatcher.Close())
	}
	w.pcscEvents = nil
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
		if err != nil {
			return nil, err
		}
		candidates[info.Path] = Candidate{
			Transport: mode,
			Path:      info.Path,
			HID:       info,
		}
	}

	return candidates, nil
}

func smartCardCandidate(
	reader *pcsc.ReaderInfo,
	cardInterface transport.SmartCardInterface,
) Candidate {
	return Candidate{
		Transport:          transport.ModeSmartCard,
		Path:               reader.Name,
		SmartCard:          reader,
		SmartCardInterface: cardInterface,
	}
}

func probeSmartCard(
	ctx context.Context,
	reader string,
) (transport.SmartCardInterface, error) {
	card, err := pcsc.Open(
		reader,
		pcsc.WithShareMode(pcsc.ShareModeExclusive),
		pcsc.WithDisconnectDisposition(pcsc.DispositionResetCard),
	)
	if err != nil {
		return "", err
	}

	cardInterface := smartCardInterface(card.Interface())
	ctapTransport, err := ctapiso7816.New(ctx, card)
	if err != nil {
		return "", errors.Join(err, card.Close())
	}

	// Successful applet selection proves that this is a CTAP attachment.
	// Cleanup errors do not change that fact.
	_ = ctapTransport.Close()

	return cardInterface, nil
}

func smartCardInterface(value pcsc.CardInterface) transport.SmartCardInterface {
	switch value {
	case pcsc.CardInterfaceContact:
		return transport.SmartCardInterfaceContact
	case pcsc.CardInterfaceContactless:
		return transport.SmartCardInterfaceContactless
	default:
		return transport.SmartCardInterfaceUnknown
	}
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
