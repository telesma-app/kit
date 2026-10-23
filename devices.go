package ctapkit

import (
	"cmp"
	"context"
	"errors"
	"maps"
	"slices"
	"sync"
	"sync/atomic"

	rtauthenticator "github.com/telesma-app/kit/internal/authenticator"
	"github.com/telesma-app/kit/internal/devicewatch"
	rtinspect "github.com/telesma-app/kit/internal/inspect"
	"github.com/telesma-app/kit/model/failure"
	"github.com/telesma-app/kit/model/report"
	"github.com/telesma-app/kit/transport"
)

// DeviceSnapshot separates physical topology, endpoint observations and selection.
// Devices excludes endpoints awaiting their first inspection; Endpoints includes
// those pending arrivals as raw observations.
type DeviceSnapshot struct {
	Devices          []report.DeviceReport   `json:"devices"`
	Endpoints        []report.EndpointReport `json:"endpoints"`
	Selected         report.DeviceID         `json:"selected,omitempty"`
	SelectedEndpoint report.AttachmentID     `json:"selectedEndpoint,omitempty"`
	// DiscoveryErrors persist until the manager is recreated; other transports
	// and the selected authenticator can remain usable.
	DiscoveryErrors map[transport.Mode]*failure.Failure `json:"discoveryErrors,omitempty"`
}

// DeviceUpdate is an atomic topology/report update. Selected is non-nil only
// when the selected attachment is ready for authenticator operations.
type DeviceUpdate struct {
	Snapshot DeviceSnapshot   `json:"snapshot"`
	Selected *Authenticator   `json:"-"`
	Error    *failure.Failure `json:"error,omitempty"`
}

// DeviceManager owns physical devices, their endpoints and the selected runtime.
type DeviceManager struct {
	ctx             context.Context
	cancel          context.CancelFunc
	watcher         devicewatch.Watcher
	open            authenticatorOpenFunc
	readSources     sourceReadFunc
	records         map[report.AttachmentID]*deviceRecord
	devices         map[report.DeviceID]*physicalDevice
	discoveryErrors map[transport.Mode]*failure.Failure
	options         []AuthenticatorOption

	commands chan any
	sources  chan readSources
	updates  chan DeviceUpdate
	ready    chan struct{}
	done     chan struct{}

	state           atomic.Pointer[DeviceUpdate]
	selected        *Authenticator
	selectedID      report.AttachmentID
	retainSelection bool

	closeOnce sync.Once
	closeErr  error
}

type deviceRecord struct {
	attachment       attachment
	identity         report.DeviceIdentity
	openErr          error
	metadataRevision uint64
}

type selectDevice struct {
	ctx      context.Context
	id       report.AttachmentID
	deviceID report.DeviceID
	reply    chan error
}

// NewDeviceManager starts monitoring and automatically selects the first
// endpoint which opens successfully. Vendor observations establish device identity;
// MDS lookup and later source refreshes are explicit.
func NewDeviceManager(ctx context.Context, mode transport.Mode, options ...AuthenticatorOption) (*DeviceManager, error) {
	lifetime, cancel := context.WithCancel(ctx)

	watcher, err := devicewatch.Watch(lifetime, mode)
	if err != nil {
		cancel()

		return nil, NormalizeError(err, failure.PhaseDiscovery)
	}

	manager := newDeviceManager(lifetime, cancel, watcher, rtauthenticator.Open, readVendorSources, options)
	<-manager.ready

	return manager, nil
}

func newDeviceManager(ctx context.Context, cancel context.CancelFunc, watcher devicewatch.Watcher, open authenticatorOpenFunc, read sourceReadFunc, options []AuthenticatorOption) *DeviceManager {
	manager := &DeviceManager{
		ctx:             ctx,
		cancel:          cancel,
		watcher:         watcher,
		open:            open,
		readSources:     read,
		records:         make(map[report.AttachmentID]*deviceRecord),
		devices:         make(map[report.DeviceID]*physicalDevice),
		discoveryErrors: make(map[transport.Mode]*failure.Failure),
		options:         options,
		commands:        make(chan any),
		sources:         make(chan readSources),
		updates:         make(chan DeviceUpdate, 1),
		ready:           make(chan struct{}),
		done:            make(chan struct{}),
	}

	go manager.run(watcher.Snapshot())

	return manager
}

func (m *DeviceManager) Updates() <-chan DeviceUpdate { return m.updates }
func (m *DeviceManager) State() *DeviceUpdate         { return m.state.Load() }

// SelectEndpoint opens id. A selection change cancels the active source read
// before opening the replacement. On failure, id stays selected in the report.
func (m *DeviceManager) SelectEndpoint(ctx context.Context, id report.AttachmentID) error {
	reply := make(chan error, 1)
	if err := m.send(ctx, selectDevice{ctx: ctx, id: id, reply: reply}); err != nil {
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

func (m *DeviceManager) Close() error {
	m.closeOnce.Do(func() {
		m.cancel()
		<-m.done
	})

	return NormalizeError(m.closeErr, failure.PhaseCleanup)
}

func (m *DeviceManager) send(ctx context.Context, command any) error {
	select {
	case m.commands <- command:
		return nil
	case <-ctx.Done():
		return NormalizeError(ctx.Err(), failure.PhaseAuthenticator)
	case <-m.done:
		return managerClosedError()
	}
}

func (m *DeviceManager) run(initial devicewatch.Snapshot) {
	defer close(m.done)
	defer close(m.updates)

	for mode, err := range initial.Errors {
		m.discoveryErrors[mode] = failure.Snapshot(err)
	}

	for _, candidate := range initial.Candidates {
		record := &deviceRecord{attachment: newAttachment(candidate)}
		m.records[record.attachment.report.Attachment.ID] = record
	}

	var initialErr error

	for _, record := range sortedRecords(m.records) {
		opened, err := m.inspectRecord(m.ctx, record)
		if err != nil {
			continue
		}

		if m.selected == nil {
			m.selected = opened
			m.selectedID = record.attachment.report.Attachment.ID
		} else {
			initialErr = errors.Join(initialErr, opened.Close())
		}
	}

	if m.selectedID == "" && len(m.records) != 0 {
		m.selectedID = sortedRecords(m.records)[0].attachment.report.Attachment.ID
	}

	for _, device := range sortedDevices(m.devices) {
		initialErr = errors.Join(initialErr, groupOpenError(device.endpoints))
	}

	m.publish(initialErr)
	close(m.ready)

	events := m.watcher.Listen()

	var (
		reading *sourceRead
		pending []*deviceRecord
	)

	for {
		// Manual selection or removal may have already consumed a pending arrival.
		for len(pending) != 0 {
			record := pending[0]
			if m.records[record.attachment.report.Attachment.ID] == record && record.attachment.report.Sources.GetInfo.State == report.SourceNotRequested {
				break
			}

			pending = pending[1:]
		}

		if len(pending) != 0 && m.selected == nil && reading == nil && m.ctx.Err() == nil {
			record := pending[0]
			pending = pending[1:]

			m.publish(m.connectRecord(record))

			continue
		}

		var discoveryGate chan struct{}
		if len(pending) != 0 && m.selected != nil && reading == nil {
			// Identity is not known yet: the arrival may be a sibling interface.
			discoveryGate = m.selected.runGate
		}

		sourceRequests := m.sources

		var sourceDone <-chan sourceReadResult

		if reading != nil || len(pending) != 0 {
			sourceRequests = nil
		}

		if reading != nil {
			sourceDone = reading.done
		}

		var selectedDone <-chan struct{}
		if m.selected != nil {
			selectedDone = m.selected.done
		}

		select {
		case <-m.ctx.Done():
			for _, record := range m.records {
				if record.attachment.report.Sources.MDS.State == report.SourceLoading {
					record.attachment.report.Sources.MDS.Outcome = sourceOutcome(m.ctx.Err())
				}
			}

			m.closeErr = m.closeSelected()
			if reading != nil {
				m.closeErr = errors.Join(m.closeErr, m.stopSourceRead(reading))
			}

			m.closeErr = errors.Join(m.closeErr, m.watcher.Close())
			m.publish(nil)

			return
		case <-selectedDone:
			m.selected = nil
			m.publish(nil)
		case discoveryGate <- struct{}{}:
			record := pending[0]
			pending = pending[1:]
			err := m.connectRecord(record)

			<-discoveryGate

			m.publish(err)
		case event, ok := <-events:
			if !ok {
				events = nil

				if err := m.watcher.Close(); err != nil {
					m.publish(NormalizeError(err, failure.PhaseDiscovery))
				}

				continue
			}

			if event.Err != nil {
				m.discoveryErrors[event.Transport] = failure.Snapshot(event.Err)
				m.publish(event.Err)

				continue
			}

			switch event.Type {
			case devicewatch.EventConnected:
				attached := newAttachment(event.Candidate)

				id := attached.report.Attachment.ID
				if m.records[id] != nil {
					continue
				}

				record := &deviceRecord{attachment: attached}
				m.records[id] = record
				pending = append(pending, record)

				m.reconcileDevices()
				m.publish(nil)

				continue
			case devicewatch.EventUpdated:
				m.updateAttachment(event.Candidate)
				m.publish(nil)

				continue
			case devicewatch.EventDisconnected:
				var readCloseErr error

				id := newAttachment(event.Candidate).report.Attachment.ID
				if reading != nil && (id == m.selectedID || id == reading.request.id) {
					readCloseErr = m.stopSourceRead(reading)
					reading = nil
				}

				m.publish(errors.Join(readCloseErr, m.removeRecord(id)))
			default:
				panic("ctapkit: invalid discovery event type: " + string(event.Type))
			}
		case command := <-sourceRequests:
			record := m.records[command.id]
			if record == nil {
				command.reply <- reportReply{err: attachmentNotFound()}
				continue
			}

			reading = m.startSourceRead(record, command)
		case result := <-sourceDone:
			m.finishSourceRead(reading, result)
			reading = nil
		case command := <-m.commands:
			switch command := command.(type) {
			case selectDevice:
				if command.deviceID != "" {
					device := m.devices[command.deviceID]
					if device == nil {
						command.reply <- attachmentNotFound()
						continue
					}

					command.id = preferredEndpoint(device.endpoints, m.selectedID).attachment.report.Attachment.ID
				}

				if err := command.ctx.Err(); err != nil {
					command.reply <- NormalizeError(err, failure.PhaseAuthenticator)
					continue
				}

				var readCloseErr error

				unchanged := m.selected != nil && m.selectedID == command.id && !m.selected.Closed()

				target := m.records[command.id]
				if !unchanged && target != nil && reading != nil {
					readCloseErr = m.stopSourceRead(reading)
					reading = nil
				}

				ctx, cancel := m.operationContext(command.ctx)
				err := errors.Join(readCloseErr, m.selectRecord(ctx, command.id))

				cancel()
				m.publish(err)

				command.reply <- err
			case beginMetadata:
				m.beginMetadata(command)
			case finishMetadata:
				m.finishMetadata(command)
			}
		}
	}
}

func (m *DeviceManager) operationContext(parent context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(parent)
	stop := context.AfterFunc(m.ctx, cancel)

	return ctx, func() {
		stop()
		cancel()
	}
}

func (m *DeviceManager) connectRecord(record *deviceRecord) error {
	if err := m.ctx.Err(); err != nil {
		return err
	}

	id := record.attachment.report.Attachment.ID

	opened, err := m.inspectRecord(m.ctx, record)
	if err != nil {
		if m.selectedID == "" {
			m.selectedID = id
		}

		return groupOpenError(m.deviceFor(id).endpoints)
	}

	if m.selected == nil && (!m.retainSelection || m.sameDevice(m.selectedID, id)) {
		m.selected, m.selectedID = opened, id
		return nil
	}

	return opened.Close()
}

func (m *DeviceManager) removeRecord(id report.AttachmentID) error {
	peers := m.deviceFor(id).endpoints

	var closeErr error
	if id == m.selectedID {
		closeErr = m.closeSelected()
		m.selectedID = ""
		m.retainSelection = false
	}

	delete(m.records, id)
	m.reconcileDevices()

	if m.selectedID == "" {
		for _, peer := range peers {
			peerID := peer.attachment.report.Attachment.ID
			if peerID == id || peer.openErr != nil {
				continue
			}

			opened, err := m.inspectRecord(m.ctx, peer)
			if err == nil {
				m.selected, m.selectedID = opened, peerID
				return closeErr
			}

			closeErr = errors.Join(closeErr, err)
		}
		// The physical device is still present even when its remaining interface
		// cannot run FIDO. Keep it selected for observations until it disappears.
		for _, peer := range peers {
			peerID := peer.attachment.report.Attachment.ID
			if peerID != id {
				m.selectedID = peerID
				m.retainSelection = true

				return errors.Join(closeErr, peer.openErr)
			}
		}

		return errors.Join(closeErr, m.selectFirst())
	}

	return closeErr
}

func (m *DeviceManager) selectRecord(ctx context.Context, id report.AttachmentID) error {
	if err := ctx.Err(); err != nil {
		return NormalizeError(err, failure.PhaseAuthenticator)
	}

	target := m.records[id]
	if target == nil {
		return attachmentNotFound()
	}

	m.retainSelection = true
	if m.selected != nil && m.selectedID == id && !m.selected.Closed() {
		return nil
	}

	closeErr := m.closeSelected()
	m.selectedID = id
	opened, err := m.inspectRecord(ctx, target)
	m.selected = opened

	return errors.Join(closeErr, err)
}

func (m *DeviceManager) selectFirst() error {
	var result error

	for _, record := range sortedRecords(m.records) {
		if record.openErr != nil {
			continue
		}

		opened, err := m.inspectRecord(m.ctx, record)
		if err != nil {
			result = errors.Join(result, err)
			continue
		}

		m.selected = opened
		m.selectedID = record.attachment.report.Attachment.ID

		return result
	}

	if len(m.records) != 0 {
		m.selectedID = sortedRecords(m.records)[0].attachment.report.Attachment.ID
	}

	return result
}

func (m *DeviceManager) inspectRecord(ctx context.Context, record *deviceRecord) (*Authenticator, error) {
	target := record.attachment
	opened, err := openDevice(ctx, target, m.open, m.options...)
	observeOpen(&target, opened, err)

	if target.report.Sources.Yubico.State == report.SourceNotRequested && lifecycleError(err) == nil {
		var stopClosing func()
		if opened != nil {
			stopClosing = closeOnCancellation(ctx, opened.Lifecycle.Close)
		}

		values, readErr := m.readSources(ctx, target, opened)
		target.report.Sources.Yubico = values.yubico
		target.report.Sources.Token2 = values.token2

		if stopClosing != nil {
			stopClosing()
		}

		err = errors.Join(err, readErr, ctx.Err())
	}

	if err != nil && opened != nil {
		err = errors.Join(err, opened.Lifecycle.Close())
	}

	m.observeRecord(record, target.report, err)

	if err != nil {
		return nil, err
	}

	return newAuthenticatorHandle(record.attachment.report, opened), nil
}

// Source readers return observations without mutating the catalog. Apply their
// result here so membership always reflects the data used by selection and reports.
func (m *DeviceManager) observeRecord(record *deviceRecord, observed report.EndpointReport, openErr error) {
	record.attachment.report.Attachment.SmartCard = observed.Attachment.SmartCard
	sources := &record.attachment.report.Sources
	sources.HIDInit = observed.Sources.HIDInit
	sources.GetInfo = observed.Sources.GetInfo
	sources.Yubico = observed.Sources.Yubico
	sources.Token2 = observed.Sources.Token2
	record.openErr = openErr

	if identity := identityFromSources(*sources); identity.SerialNumber != "" {
		record.identity = identity
	}

	m.reconcileDevices()
}

func (m *DeviceManager) updateAttachment(candidate devicewatch.Candidate) {
	observed := newAttachment(candidate)
	record := m.records[observed.report.Attachment.ID]
	record.attachment.report.Attachment.USB = observed.report.Attachment.USB
}

func observeOpen(target *attachment, opened *rtauthenticator.Opened, err error) {
	if target.mode == transport.ModeSmartCard {
		card := &report.SmartCardReport{
			Reader:          target.path,
			ATR:             target.report.Attachment.SmartCard.ATR,
			Interface:       transport.SmartCardInterfaceUnknown,
			FIDOApplication: sourceOutcome(err),
		}
		if opened != nil && opened.Card != nil {
			card.Interface = smartCardInterface(opened.Card.Interface)
			card.FIDOApplication = sourceOutcome(opened.Card.FIDOSelectErr)
		}

		target.report.Attachment.SmartCard = card
	}

	sources := &target.report.Sources
	sources.GetInfo.Outcome = sourceOutcome(err)

	if opened == nil {
		if target.mode != transport.ModeSmartCard {
			sources.HIDInit.Outcome = sourceOutcome(err)
		}

		return
	}

	if opened.HIDInit != nil {
		sources.HIDInit = report.HIDInitSource{Outcome: sourceOutcome(nil), Data: opened.HIDInit}
	} else if target.mode != transport.ModeSmartCard {
		sources.HIDInit.Outcome = report.Outcome{State: report.SourceUnavailable, Reason: report.ReasonAdapterMissing}
	}

	if opened.Info != nil {
		if info, valid := opened.Info.GetInfoCached(); valid {
			sources.GetInfo = report.GetInfoSource{Outcome: sourceOutcome(nil), Data: new(rtinspect.BuildInfo(info))}
		}
	}
}

func (m *DeviceManager) closeSelected() error {
	selected := m.selected

	m.selected = nil
	if selected == nil {
		return nil
	}

	return selected.Close()
}

func (m *DeviceManager) publish(err error) {
	update := DeviceUpdate{Snapshot: DeviceSnapshot{
		SelectedEndpoint: m.selectedID,
		DiscoveryErrors:  maps.Clone(m.discoveryErrors),
	}}
	if m.selectedID != "" {
		update.Snapshot.Selected = m.deviceFor(m.selectedID).id
	}

	for _, record := range sortedRecords(m.records) {
		update.Snapshot.Endpoints = append(update.Snapshot.Endpoints, record.attachment.report)
		if record.attachment.report.Attachment.ID == m.selectedID {
			if m.selected != nil {
				m.selected.setEndpoint(record.attachment.report)
				update.Selected = m.selected
			}
		}
	}

	for _, device := range sortedDevices(m.devices) {
		// An uninspected arrival has no identity and forms a singleton group.
		if device.endpoints[0].attachment.report.Sources.GetInfo.State == report.SourceNotRequested {
			continue
		}

		update.Snapshot.Devices = append(update.Snapshot.Devices, device.snapshot())
	}

	if err != nil {
		update.Error = failure.Snapshot(NormalizeError(err, failure.PhaseAuthenticator))
	}

	m.state.Store(&update)

	select {
	case m.updates <- update:
	default:
		select {
		case <-m.updates:
		default:
		}

		m.updates <- update
	}
}

func sortedRecords(records map[report.AttachmentID]*deviceRecord) []*deviceRecord {
	sorted := make([]*deviceRecord, 0, len(records))
	for _, record := range records {
		sorted = append(sorted, record)
	}

	slices.SortFunc(sorted, func(left, right *deviceRecord) int {
		if order := cmp.Compare(transportOrder(left.attachment.mode), transportOrder(right.attachment.mode)); order != 0 {
			return order
		}

		return cmp.Compare(left.attachment.path, right.attachment.path)
	})

	return sorted
}

func transportOrder(mode transport.Mode) int {
	if mode == transport.ModeSmartCard {
		return 1
	}

	return 0
}

func managerClosedError() error {
	return failure.New(failure.CodeOperationCanceled, failure.WithPhase(failure.PhaseAuthenticator))
}

func attachmentNotFound() error {
	return failure.New(failure.CodeDeviceNotFound, failure.WithPhase(failure.PhaseAuthenticator))
}

// The returned function waits for any running close callback to finish.
func closeOnCancellation(ctx context.Context, closeHandle func() error) func() {
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(done)

		_ = closeHandle()
	})

	return func() {
		if !stop() {
			<-done
		}
	}
}
