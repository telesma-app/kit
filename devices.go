package ctapkit

import (
	"cmp"
	"context"
	"errors"
	"slices"
	"sync"
	"sync/atomic"

	rtauthenticator "github.com/telesma-app/kit/internal/authenticator"
	"github.com/telesma-app/kit/internal/devicewatch"
	"github.com/telesma-app/kit/model/failure"
	"github.com/telesma-app/kit/model/report"
	"github.com/telesma-app/kit/transport"
)

// DeviceSnapshot is the complete current attachment and selection state.
type DeviceSnapshot struct {
	Devices  []report.DeviceReport `json:"devices"`
	Selected report.AttachmentID   `json:"selected,omitempty"`
}

// DeviceUpdate is one atomic view of device topology and selection.
type DeviceUpdate struct {
	Snapshot DeviceSnapshot   `json:"snapshot"`
	Selected *Authenticator   `json:"-"`
	Error    *failure.Failure `json:"error,omitempty"`
}

// DeviceManager owns live device topology and the selected Authenticator.
type DeviceManager struct {
	ctx     context.Context
	cancel  context.CancelFunc
	watcher devicewatch.Watcher
	open    authenticatorOpenFunc
	resolve deviceMetadataResolveFunc
	options []AuthenticatorOption

	commands chan any
	updates  chan DeviceUpdate
	ready    chan struct{}
	done     chan struct{}

	state    atomic.Pointer[DeviceUpdate]
	selected *Authenticator

	closeOnce sync.Once
	closeErr  error
}

type deviceRecord struct {
	attachment attachment
	openErr    error
}

type selectDevice struct {
	ctx   context.Context
	id    report.AttachmentID
	reply chan error
}

// NewDeviceManager starts device monitoring and selects the first attachment
// which opens successfully.
func NewDeviceManager(
	ctx context.Context,
	mode transport.Mode,
	options ...AuthenticatorOption,
) (*DeviceManager, error) {
	lifetime, cancel := context.WithCancel(ctx)
	watcher, err := devicewatch.Watch(lifetime, mode)
	if err != nil {
		cancel()

		return nil, NormalizeError(err, failure.PhaseDiscovery)
	}

	manager := newDeviceManager(
		lifetime,
		cancel,
		watcher,
		rtauthenticator.Open,
		resolveDeviceMetadata,
		options,
	)
	<-manager.ready

	return manager, nil
}

func newDeviceManager(
	ctx context.Context,
	cancel context.CancelFunc,
	watcher devicewatch.Watcher,
	open authenticatorOpenFunc,
	resolve deviceMetadataResolveFunc,
	options []AuthenticatorOption,
) *DeviceManager {
	manager := &DeviceManager{
		ctx:      ctx,
		cancel:   cancel,
		watcher:  watcher,
		open:     open,
		resolve:  resolve,
		options:  options,
		commands: make(chan any),
		updates:  make(chan DeviceUpdate, 1),
		ready:    make(chan struct{}),
		done:     make(chan struct{}),
	}

	go manager.run(watcher.Snapshot())

	return manager
}

// Updates returns coalescible complete device states.
func (m *DeviceManager) Updates() <-chan DeviceUpdate {
	return m.updates
}

// State returns the latest atomic topology and selection state.
func (m *DeviceManager) State() *DeviceUpdate {
	return m.state.Load()
}

// Select closes the current authenticator and selects id. If id cannot be
// opened, the manager falls back to the first remaining attachment.
func (m *DeviceManager) Select(
	ctx context.Context,
	id report.AttachmentID,
) error {
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

// Close stops monitoring and closes the selected authenticator.
func (m *DeviceManager) Close() error {
	m.closeOnce.Do(func() {
		m.cancel()
		<-m.done
	})

	return m.closeErr
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

	records := make(map[report.AttachmentID]*deviceRecord)
	for _, candidate := range initial.Candidates {
		record := &deviceRecord{attachment: newAttachment(candidate)}
		records[record.attachment.report.Attachment.ID] = record
	}

	var initialErr error
	for _, record := range sortedRecords(records) {
		authenticator, err := m.inspectRecord(m.ctx, record)
		if err != nil {
			record.openErr = err
			initialErr = errors.Join(initialErr, err)
			continue
		}
		if m.selected == nil {
			m.selected = authenticator
			continue
		}

		initialErr = errors.Join(initialErr, authenticator.Close())
	}
	m.publish(records, initialErr)
	close(m.ready)

	events := m.watcher.Listen()
	for {
		select {
		case <-m.ctx.Done():
			closeErr := m.closeSelected()
			m.publish(records, nil)
			m.closeErr = errors.Join(closeErr, m.watcher.Close())

			return

		case event, ok := <-events:
			if !ok {
				events = nil
				continue
			}

			m.publish(records, m.applyEvent(records, event))

		case command := <-m.commands:
			switch command := command.(type) {
			case selectDevice:
				if err := command.ctx.Err(); err != nil {
					command.reply <- NormalizeError(
						err,
						failure.PhaseAuthenticator,
					)
					continue
				}

				err := m.selectRecord(command.ctx, records, command.id)
				m.publish(records, err)
				command.reply <- err
			}
		}
	}
}

func (m *DeviceManager) applyEvent(
	records map[report.AttachmentID]*deviceRecord,
	event devicewatch.Event,
) error {
	attached := newAttachment(event.Candidate)
	id := attached.report.Attachment.ID
	if event.Connected {
		var record *deviceRecord
		if current := records[id]; current != nil {
			current.attachment = attached
			current.openErr = nil
			record = current
		} else {
			record = &deviceRecord{attachment: attached}
			records[id] = record
		}

		authenticator, err := m.inspectRecord(m.ctx, record)
		if err != nil {
			record.openErr = err
			return err
		}
		if m.selected == nil {
			m.selected = authenticator
			return nil
		}

		return authenticator.Close()
	}

	selected := m.selected
	var closeErr error
	if selected != nil && selected.Device().Attachment.ID == id {
		closeErr = m.closeSelected()
	}
	delete(records, id)
	if selected != nil {
		return errors.Join(closeErr, m.selectFirst(records))
	}

	return closeErr
}

func (m *DeviceManager) selectRecord(
	ctx context.Context,
	records map[report.AttachmentID]*deviceRecord,
	id report.AttachmentID,
) error {
	if selected := m.selected; selected != nil &&
		selected.Device().Attachment.ID == id {
		return nil
	}

	target := records[id]
	if target == nil {
		return failure.New(
			failure.CodeDeviceNotFound,
			failure.WithPhase(failure.PhaseAuthenticator),
		)
	}

	closeErr := m.closeSelected()
	target.openErr = nil
	openCtx, cancel := context.WithCancel(m.ctx)
	stop := context.AfterFunc(ctx, cancel)
	err := m.openRecord(openCtx, target)
	stop()
	cancel()
	if err != nil {
		target.openErr = err

		return errors.Join(closeErr, err, m.selectFirst(records))
	}

	return closeErr
}

func (m *DeviceManager) selectFirst(
	records map[report.AttachmentID]*deviceRecord,
) error {
	if m.selected != nil {
		return nil
	}

	var openErr error
	for _, record := range sortedRecords(records) {
		if record.openErr != nil {
			continue
		}
		if err := m.openRecord(m.ctx, record); err != nil {
			record.openErr = err
			openErr = errors.Join(openErr, err)
			continue
		}

		return openErr
	}

	return openErr
}

func (m *DeviceManager) openRecord(
	ctx context.Context,
	record *deviceRecord,
) error {
	var metadata deviceMetadata
	if current := record.attachment.report.VendorMetadata; current != nil {
		metadata = *current
	}

	authenticator, err := openAuthenticatorHandle(
		ctx,
		record.attachment,
		m.open,
		m.options...,
	)
	if err != nil {
		return err
	}
	if !deviceMetadataEmpty(metadata) {
		applyDeviceMetadata(&authenticator.selected, metadata)
	}
	record.attachment.report = authenticator.Device()

	m.selected = authenticator

	return nil
}

func (m *DeviceManager) inspectRecord(
	ctx context.Context,
	record *deviceRecord,
) (*Authenticator, error) {
	var metadata deviceMetadata
	var err error
	if record.attachment.mode == transport.ModeSmartCard {
		metadata, err = m.resolve(ctx, record.attachment, nil)
		if err != nil {
			return nil, NormalizeError(err, failure.PhaseAuthenticator)
		}
	}

	authenticator, err := openAuthenticatorHandle(
		ctx,
		record.attachment,
		m.open,
		m.options...,
	)
	if err != nil {
		return nil, err
	}
	if record.attachment.mode != transport.ModeSmartCard {
		metadata, err = m.resolve(ctx, record.attachment, authenticator.vendor)
		if err != nil {
			return nil, errors.Join(
				NormalizeError(err, failure.PhaseAuthenticator),
				authenticator.Close(),
			)
		}
	}
	if !deviceMetadataEmpty(metadata) {
		applyDeviceMetadata(&authenticator.selected, metadata)
	}
	record.attachment.report = authenticator.Device()

	return authenticator, nil
}

func (m *DeviceManager) closeSelected() error {
	selected := m.selected
	if selected == nil {
		return nil
	}
	m.selected = nil

	return selected.Close()
}

func (m *DeviceManager) publish(
	records map[report.AttachmentID]*deviceRecord,
	err error,
) {
	update := DeviceUpdate{}
	for _, record := range sortedRecords(records) {
		update.Snapshot.Devices = append(
			update.Snapshot.Devices,
			record.attachment.report,
		)
	}
	if m.selected != nil {
		update.Snapshot.Selected = m.selected.Device().Attachment.ID
		update.Selected = m.selected
	}

	if err != nil {
		update.Error = failure.Snapshot(
			NormalizeError(err, failure.PhaseAuthenticator),
		)
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

func sortedRecords(
	records map[report.AttachmentID]*deviceRecord,
) []*deviceRecord {
	sorted := make([]*deviceRecord, 0, len(records))
	for _, record := range records {
		sorted = append(sorted, record)
	}
	slices.SortFunc(sorted, func(left, right *deviceRecord) int {
		if order := cmp.Compare(
			transportOrder(left.attachment.mode),
			transportOrder(right.attachment.mode),
		); order != 0 {
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
	return failure.New(
		failure.CodeOperationCanceled,
		failure.WithPhase(failure.PhaseAuthenticator),
	)
}
