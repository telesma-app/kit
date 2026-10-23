package ctapkit

import (
	"context"
	"errors"
	"sync"

	ctaptransport "github.com/telesma-app/ctap/transport"
	rtauthenticator "github.com/telesma-app/kit/internal/authenticator"
	rtinspect "github.com/telesma-app/kit/internal/inspect"
	"github.com/telesma-app/kit/model/failure"
	"github.com/telesma-app/kit/model/operation"
	"github.com/telesma-app/kit/model/report"
)

type readSources struct {
	ctx   context.Context
	id    report.AttachmentID
	reply chan reportReply
}

type reportReply struct {
	report report.EndpointReport
	err    error
}

type sourceRead struct {
	request   readSources
	record    *deviceRecord
	session   *Authenticator
	gateOwner *Authenticator
	cancel    context.CancelFunc
	done      chan sourceReadResult
}

type sourceReadResult struct {
	report  report.EndpointReport
	openErr error
	err     error
}

// ReadEndpointSources reads one endpoint, serialized with physical-device workflows.
// Source errors remain in the report; cancellation and invalidation also return an error.
func (m *DeviceManager) ReadEndpointSources(ctx context.Context, id report.AttachmentID) (report.EndpointReport, error) {
	reply := make(chan reportReply, 1)
	select {
	case m.sources <- readSources{ctx: ctx, id: id, reply: reply}:
	case <-ctx.Done():
		return report.EndpointReport{}, NormalizeError(ctx.Err(), failure.PhaseAuthenticator)
	case <-m.done:
		return report.EndpointReport{}, managerClosedError()
	}

	select {
	case result := <-reply:
		return result.report, result.err
	case <-m.done:
		return report.EndpointReport{}, managerClosedError()
	}
}

func (m *DeviceManager) startSourceRead(record *deviceRecord, request readSources) *sourceRead {
	ctx, cancel := m.operationContext(request.ctx)

	reading := &sourceRead{request: request, record: record, cancel: cancel, done: make(chan sourceReadResult, 1)}
	if m.selected != nil && m.sameDevice(request.id, m.selectedID) {
		reading.gateOwner = m.selected
	}

	if m.selectedID == request.id {
		reading.session = m.selected
	}

	target := record.attachment
	previousOpenErr := record.openErr

	record.attachment.report.Sources.Yubico.State = report.SourceLoading
	record.attachment.report.Sources.Token2.State = report.SourceLoading

	m.publish(nil)

	go func() {
		if reading.gateOwner == nil || reading.gateOwner == reading.session {
			reading.done <- m.readAttachmentSources(ctx, target, reading.session)
			return
		}
		// A management read on a sibling interface belongs to the same physical
		// operation boundary as workflows on the selected authenticator.
		result := sourceReadResult{report: target.report, openErr: previousOpenErr}

		_, err := executeSerializedOperation(reading.gateOwner, ctx, operation.ReadSources, func(ctx context.Context) (struct{}, error) {
			result = m.readAttachmentSources(ctx, target, nil)
			return struct{}{}, result.err
		})
		if err != nil && result.err == nil {
			result.err = NormalizeError(err, failure.PhaseAuthenticator)
			result.report.Sources.Yubico.Outcome = sourceOutcome(err)
			result.report.Sources.Token2.Outcome = sourceOutcome(err)
		}

		reading.done <- result
	}()

	return reading
}

func (m *DeviceManager) finishSourceRead(reading *sourceRead, result sourceReadResult) {
	reading.cancel()

	record := reading.record
	m.observeRecord(record, result.report, result.openErr)

	if m.selected != nil && m.selected == reading.gateOwner && m.selected.Closed() {
		m.selected = nil
	}

	m.publish(result.err)

	reading.request.reply <- reportReply{report: record.attachment.report, err: result.err}
}

// Close must unblock the workflow before waiting for the source reader.
func (m *DeviceManager) stopSourceRead(reading *sourceRead) error {
	reading.cancel()

	var err error
	if reading.session != nil {
		err = reading.session.Close()
	}

	m.finishSourceRead(reading, <-reading.done)

	return err
}

func (m *DeviceManager) readAttachmentSources(ctx context.Context, target attachment, session *Authenticator) sourceReadResult {
	var (
		openErr error
		values  vendorSources
		err     error
	)

	if session != nil {
		readCtx := ctx

		var stopClosing func()

		values, err = executeSerializedOperation(session, ctx, operation.ReadSources, func(ctx context.Context) (vendorSources, error) {
			stopClosing = closeOnCancellation(readCtx, session.Close)

			info, infoErr := rtauthenticator.ResolveInfo(ctx, session.opened.Info)

			target.report.Sources.GetInfo.Outcome = sourceOutcome(infoErr)
			if infoErr == nil {
				target.report.Sources.GetInfo.Data = new(rtinspect.BuildInfo(info))
			} else if fatal := lifecycleError(infoErr); fatal != nil {
				return vendorSources{yubico: report.YubicoSource{Outcome: sourceOutcome(fatal)}, token2: report.Token2Source{Outcome: sourceOutcome(fatal)}}, fatal
			}

			return m.readSources(ctx, target, session.opened)
		})

		if stopClosing != nil {
			stopClosing()
		}

		if _, invalidated := errors.AsType[*ctaptransport.DeviceInvalidatedError](err); invalidated || session.Closed() {
			err = errors.Join(err, session.Close())
		}
	} else {
		opened, openingErr := openDevice(ctx, target, m.open, m.options...)
		openErr = openingErr
		observeOpen(&target, opened, openErr)

		var (
			closeOpened func() error
			stopClosing func()
		)

		if opened != nil {
			closeOpened = sync.OnceValue(opened.Lifecycle.Close)
			stopClosing = closeOnCancellation(ctx, closeOpened)
		}

		if fatal := lifecycleError(openErr); fatal != nil {
			values = vendorSources{yubico: report.YubicoSource{Outcome: sourceOutcome(fatal)}, token2: report.Token2Source{Outcome: sourceOutcome(fatal)}}
			err = fatal
		} else {
			values, err = m.readSources(ctx, target, opened)
		}

		if opened != nil {
			stopClosing()

			err = errors.Join(err, closeOpened())
		}
	}

	if values.yubico.State == "" {
		values.yubico.Outcome = sourceOutcome(err)
	}

	if values.token2.State == "" {
		values.token2.Outcome = sourceOutcome(err)
	}

	target.report.Sources.Yubico = values.yubico
	target.report.Sources.Token2 = values.token2

	return sourceReadResult{report: target.report, openErr: openErr, err: NormalizeError(err, failure.PhaseAuthenticator)}
}
