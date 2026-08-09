package ctapkit

import (
	"context"
	"errors"
	"sync"

	rtauthenticator "github.com/telesma-app/kit/internal/authenticator"
	"github.com/telesma-app/kit/internal/devicewatch"
	"github.com/telesma-app/kit/internal/logging"
	"github.com/telesma-app/kit/model/failure"
	"github.com/telesma-app/kit/model/report"
	"github.com/telesma-app/kit/transport"
)

type devicePowerCycleLease struct {
	target         *Authenticator
	original       attachment
	originalReport report.DeviceReport
	detached       bool
	detachedReady  chan struct{}
	candidates     chan attachment
	rejected       map[report.AttachmentID]struct{}

	mu                 sync.Mutex
	generation         uint64
	connectionDetached bool
	detachErr          error
}

type beginDevicePowerCycle struct {
	ctx    context.Context
	target *Authenticator
	reply  chan beginDevicePowerCycleResult
}

type beginDevicePowerCycleResult struct {
	lease *devicePowerCycleLease
	err   error
}

type markDevicePowerCycleDetached struct {
	lease *devicePowerCycleLease
	reply chan error
}

type abortDevicePowerCycle struct {
	lease *devicePowerCycleLease
	reply chan abortDevicePowerCycleResult
}

type abortDevicePowerCycleResult struct {
	detached bool
	err      error
}

type rejectDevicePowerCycleCandidate struct {
	lease *devicePowerCycleLease
	id    report.AttachmentID
	reply chan error
}

type commitDevicePowerCycle struct {
	lease      *devicePowerCycleLease
	attachment attachment
	report     report.DeviceReport
	reply      chan error
}

func (m *DeviceManager) powerCycleSelected(
	ctx context.Context,
	target *Authenticator,
	action func(context.Context) error,
) error {
	lease, err := m.acquirePowerCycleLease(ctx, target)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return errors.Join(err, m.finishInterruptedPowerCycle(lease))
	}

	if lease.original.mode == transport.ModeSmartCard {
		if !lease.isDetached() {
			if err := m.markPowerCycleLeaseDetached(lease); err != nil {
				return err
			}
		}
	} else if !lease.isDetached() {
		actionCtx, cancel := context.WithCancel(ctx)
		stop := context.AfterFunc(m.ctx, cancel)
		err := action(actionCtx)
		stop()
		cancel()
		if err != nil {
			return errors.Join(err, m.finishInterruptedPowerCycle(lease))
		}
	}

	if err := m.waitForPowerCycleDetach(ctx, lease); err != nil {
		return errors.Join(err, m.finishInterruptedPowerCycle(lease))
	}
	detachedGeneration, detachErr := lease.detachTarget()
	if detachedGeneration == 0 {
		return detachErr
	}

	for {
		candidate, err := m.nextPowerCycleCandidate(ctx, lease)
		if err != nil {
			return errors.Join(detachErr, err)
		}

		opened, selected, err := m.openPowerCycleCandidate(ctx, candidate, lease.originalReport)
		if err != nil {
			return errors.Join(detachErr, err)
		}
		if !powerCycleIdentityMatches(lease.original, lease.originalReport, candidate, selected) {
			closeErr := opened.Lifecycle.Close()
			rejectErr := m.rejectPowerCycleCandidate(lease, candidate.report.Attachment.ID)
			if err := errors.Join(closeErr, rejectErr); err != nil {
				return errors.Join(detachErr, err)
			}

			continue
		}
		preservePowerCycleMetadata(&selected, lease.originalReport)

		installedGeneration, installErr := target.installConnection(detachedGeneration, selected, opened)
		current, currentGeneration, installed := target.connection.Current()
		if !installed || current != opened || currentGeneration != installedGeneration {
			return errors.Join(detachErr, installErr)
		}
		lease.setGeneration(installedGeneration)
		commitErr := m.commitPowerCycleLease(lease, candidate, selected)

		return errors.Join(detachErr, installErr, commitErr)
	}
}

func (m *DeviceManager) acquirePowerCycleLease(
	ctx context.Context,
	target *Authenticator,
) (*devicePowerCycleLease, error) {
	reply := make(chan beginDevicePowerCycleResult, 1)
	command := beginDevicePowerCycle{ctx: ctx, target: target, reply: reply}
	if err := m.send(ctx, command); err != nil {
		return nil, err
	}

	select {
	case result := <-reply:
		return result.lease, result.err
	case <-m.ctx.Done():
		return nil, managerClosedError()
	}
}

func (m *DeviceManager) beginPowerCycle(
	records map[report.AttachmentID]*deviceRecord,
	command beginDevicePowerCycle,
) beginDevicePowerCycleResult {
	if err := command.ctx.Err(); err != nil {
		return beginDevicePowerCycleResult{err: err}
	}
	if m.cycle != nil {
		if m.cycle.target != command.target {
			return beginDevicePowerCycleResult{err: devicePowerCyclePendingError()}
		}
		m.offerCurrentPowerCycleCandidates(records, m.cycle)

		return beginDevicePowerCycleResult{lease: m.cycle}
	}
	if m.selected != command.target {
		return beginDevicePowerCycleResult{err: devicePowerCycleTargetError()}
	}

	selected := command.target.Device()
	record := records[selected.Attachment.ID]
	if record == nil {
		return beginDevicePowerCycleResult{err: devicePowerCycleTargetError()}
	}
	_, generation, ok := command.target.connection.Current()
	if !ok {
		return beginDevicePowerCycleResult{err: devicePowerCycleTargetError()}
	}

	lease := &devicePowerCycleLease{
		target:         command.target,
		original:       record.attachment,
		originalReport: selected,
		detachedReady:  make(chan struct{}),
		candidates:     make(chan attachment, 8),
		rejected:       make(map[report.AttachmentID]struct{}),
		generation:     generation,
	}
	m.cycle = lease

	return beginDevicePowerCycleResult{lease: lease}
}

func (m *DeviceManager) markPowerCycleLeaseDetached(lease *devicePowerCycleLease) error {
	reply := make(chan error, 1)
	command := markDevicePowerCycleDetached{lease: lease, reply: reply}
	if err := m.send(m.ctx, command); err != nil {
		return err
	}

	select {
	case err := <-reply:
		return err
	case <-m.ctx.Done():
		return managerClosedError()
	}
}

func (m *DeviceManager) markPowerCycleDetached(lease *devicePowerCycleLease) error {
	if m.cycle != lease {
		return devicePowerCycleStateError()
	}
	if !lease.detached {
		lease.detached = true
		close(lease.detachedReady)
		if lease.original.mode == transport.ModeSmartCard {
			lease.offer(lease.original)
		}
	}

	return nil
}

func (m *DeviceManager) waitForPowerCycleDetach(
	ctx context.Context,
	lease *devicePowerCycleLease,
) error {
	select {
	case <-lease.detachedReady:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-m.ctx.Done():
		return managerClosedError()
	}
}

func (m *DeviceManager) finishInterruptedPowerCycle(lease *devicePowerCycleLease) error {
	if lease.isDetached() {
		_, err := lease.detachTarget()

		return err
	}

	reply := make(chan abortDevicePowerCycleResult, 1)
	command := abortDevicePowerCycle{lease: lease, reply: reply}
	if err := m.send(m.ctx, command); err != nil {
		return err
	}

	select {
	case result := <-reply:
		if result.detached {
			_, detachErr := lease.detachTarget()

			return errors.Join(result.err, detachErr)
		}

		return result.err
	case <-m.ctx.Done():
		return nil
	}
}

func (m *DeviceManager) abortPowerCycle(lease *devicePowerCycleLease) (bool, error) {
	if m.cycle != lease {
		return false, devicePowerCycleStateError()
	}
	if lease.detached {
		return true, nil
	}
	m.cycle = nil

	return false, nil
}

func (m *DeviceManager) nextPowerCycleCandidate(
	ctx context.Context,
	lease *devicePowerCycleLease,
) (attachment, error) {
	select {
	case candidate := <-lease.candidates:
		return candidate, nil
	case <-ctx.Done():
		return attachment{}, ctx.Err()
	case <-m.ctx.Done():
		return attachment{}, managerClosedError()
	}
}

func (m *DeviceManager) rejectPowerCycleCandidate(
	lease *devicePowerCycleLease,
	id report.AttachmentID,
) error {
	reply := make(chan error, 1)
	command := rejectDevicePowerCycleCandidate{lease: lease, id: id, reply: reply}
	if err := m.send(m.ctx, command); err != nil {
		return err
	}

	select {
	case err := <-reply:
		return err
	case <-m.ctx.Done():
		return managerClosedError()
	}
}

func (m *DeviceManager) rejectPowerCycleCandidateState(
	lease *devicePowerCycleLease,
	id report.AttachmentID,
) error {
	if m.cycle != lease {
		return devicePowerCycleStateError()
	}
	lease.rejected[id] = struct{}{}

	return nil
}

func (m *DeviceManager) commitPowerCycleLease(
	lease *devicePowerCycleLease,
	attached attachment,
	selected report.DeviceReport,
) error {
	reply := make(chan error, 1)
	command := commitDevicePowerCycle{
		lease:      lease,
		attachment: attached,
		report:     selected,
		reply:      reply,
	}
	if err := m.send(m.ctx, command); err != nil {
		return err
	}

	select {
	case err := <-reply:
		return err
	case <-m.ctx.Done():
		return managerClosedError()
	}
}

func (m *DeviceManager) commitPowerCycle(
	records map[report.AttachmentID]*deviceRecord,
	command commitDevicePowerCycle,
) error {
	if m.cycle != command.lease || m.selected != command.lease.target {
		return devicePowerCycleStateError()
	}

	originalID := command.lease.original.report.Attachment.ID
	nextID := command.report.Attachment.ID
	if originalID != nextID {
		delete(records, originalID)
	}
	record := records[nextID]
	if record == nil {
		record = &deviceRecord{}
		records[nextID] = record
	}
	record.attachment = command.attachment
	record.attachment.report = command.report
	record.openErr = nil
	m.cycle = nil

	return nil
}

func (m *DeviceManager) applyPowerCycleEvent(
	records map[report.AttachmentID]*deviceRecord,
	event devicewatch.Event,
) (bool, error) {
	lease := m.cycle
	if lease == nil {
		return false, nil
	}

	attached := newAttachment(event.Candidate)
	id := attached.report.Attachment.ID
	if !event.Connected {
		delete(records, id)
		delete(lease.rejected, id)
		if !lease.detached && id == lease.original.report.Attachment.ID {
			lease.detached = true
			close(lease.detachedReady)
		}

		return true, nil
	}

	record := records[id]
	if record == nil {
		record = &deviceRecord{}
		records[id] = record
	}
	record.attachment = attached
	record.openErr = nil
	if _, rejected := lease.rejected[id]; rejected {
		return true, nil
	}
	if powerCycleCandidateMatches(lease.original, lease.originalReport, attached) {
		if lease.detached {
			lease.offer(attached)
		}

		return true, nil
	}

	return false, nil
}

func (m *DeviceManager) offerCurrentPowerCycleCandidates(
	records map[report.AttachmentID]*deviceRecord,
	lease *devicePowerCycleLease,
) {
	if !lease.detached {
		return
	}
	for _, record := range sortedRecords(records) {
		id := record.attachment.report.Attachment.ID
		if _, rejected := lease.rejected[id]; rejected {
			continue
		}
		if powerCycleCandidateMatches(lease.original, lease.originalReport, record.attachment) {
			lease.offer(record.attachment)
		}
	}
}

func (lease *devicePowerCycleLease) offer(candidate attachment) {
	select {
	case lease.candidates <- candidate:
	default:
	}
}

func (lease *devicePowerCycleLease) isDetached() bool {
	select {
	case <-lease.detachedReady:
		return true
	default:
		return false
	}
}

func (lease *devicePowerCycleLease) detachTarget() (uint64, error) {
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.connectionDetached {
		return lease.generation, lease.detachErr
	}

	generation, err := lease.target.detachConnection(lease.generation)
	lease.generation = generation
	lease.connectionDetached = true
	lease.detachErr = err

	return generation, err
}

func (lease *devicePowerCycleLease) setGeneration(generation uint64) {
	lease.mu.Lock()
	lease.generation = generation
	lease.mu.Unlock()
}

func (m *DeviceManager) openPowerCycleCandidate(
	ctx context.Context,
	target attachment,
	original report.DeviceReport,
) (*rtauthenticator.Opened, report.DeviceReport, error) {
	openCtx, cancel := context.WithCancel(m.ctx)
	stop := context.AfterFunc(ctx, cancel)
	defer func() {
		stop()
		cancel()
	}()

	var metadata deviceMetadata
	var err error
	if target.mode == transport.ModeSmartCard {
		metadata, err = m.resolve(openCtx, target, nil)
		if err != nil {
			return nil, report.DeviceReport{}, NormalizeError(err, failure.PhaseIdentity)
		}
	}

	opened, err := m.openPowerCycleConnection(openCtx, target)
	if err != nil {
		return nil, report.DeviceReport{}, err
	}
	if target.mode != transport.ModeSmartCard {
		metadata, err = m.resolve(openCtx, target, opened.Vendor)
		if err != nil {
			return nil, report.DeviceReport{}, errors.Join(
				NormalizeError(err, failure.PhaseIdentity),
				opened.Lifecycle.Close(),
			)
		}
	}

	selected := target.report
	if !deviceMetadataEmpty(metadata) {
		applyDeviceMetadata(&selected, metadata)
	}
	if selected.Identity == nil && original.Identity == nil {
		preservePowerCycleMetadata(&selected, original)
	}

	return opened, selected, nil
}

func (m *DeviceManager) openPowerCycleConnection(
	ctx context.Context,
	target attachment,
) (*rtauthenticator.Opened, error) {
	var config authenticatorConfig
	for _, option := range m.options {
		if option != nil {
			option(&config)
		}
	}

	var recorder logging.Recorder
	if config.journal != nil {
		recorder = config.journal.journal
	}

	return m.open(logging.WithRecorder(ctx, recorder), target.mode, target.path)
}

func preservePowerCycleMetadata(selected *report.DeviceReport, original report.DeviceReport) {
	if selected.Identity == nil {
		selected.Identity = original.Identity
	}
	if selected.VendorMetadata == nil {
		selected.VendorMetadata = original.VendorMetadata
	}
}

func devicePowerCyclePendingError() error {
	return failure.New(
		failure.CodeAuthenticatorOperationPending,
		failure.WithPhase(failure.PhaseAuthenticator),
	)
}

func devicePowerCycleTargetError() error {
	return failure.New(
		failure.CodeConformanceTargetInvalid,
		failure.WithPhase(failure.PhaseIdentity),
	)
}

func devicePowerCycleStateError() error {
	return failure.New(
		failure.CodeTransportFailure,
		failure.WithPhase(failure.PhaseAuthenticator),
	)
}
