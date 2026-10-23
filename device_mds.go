package ctapkit

import (
	"context"
	"uuid"

	"github.com/telesma-app/kit/model/failure"
	"github.com/telesma-app/kit/model/report"
	"github.com/telesma-app/mds"
	mdsmodel "github.com/telesma-app/mds/model"
)

type beginMetadata struct {
	id    report.AttachmentID
	reply chan metadataRequest
}

type metadataRequest struct {
	record   *deviceRecord
	revision uint64
	report   report.EndpointReport
	aaguid   uuid.UUID
	err      error
}

type finishMetadata struct {
	request metadataRequest
	result  mdsmodel.LookupResult
	err     error
	reply   chan reportReply
}

// RefreshMetadata looks up the attachment's AAGUID without blocking local operations.
// Refresh failures retain verified cached data.
func (m *DeviceManager) RefreshMetadata(ctx context.Context, id report.AttachmentID, client *mds.Client, options mds.LookupOptions) (report.EndpointReport, error) {
	begin := make(chan metadataRequest, 1)
	if err := m.send(ctx, beginMetadata{id: id, reply: begin}); err != nil {
		return report.EndpointReport{}, err
	}

	var request metadataRequest
	select {
	case request = <-begin:
	case <-m.done:
		return report.EndpointReport{}, managerClosedError()
	}

	if request.err != nil || request.aaguid == uuid.Nil() {
		return request.report, request.err
	}

	lookupCtx, cancel := m.operationContext(ctx)
	result, lookupErr := client.Lookup(lookupCtx, request.aaguid, options)

	cancel()

	reply := make(chan reportReply, 1)
	if err := m.send(m.ctx, finishMetadata{request: request, result: result, err: lookupErr, reply: reply}); err != nil {
		return request.report, err
	}

	select {
	case result := <-reply:
		return result.report, result.err
	case <-m.done:
		return request.report, managerClosedError()
	}
}

func (m *DeviceManager) beginMetadata(command beginMetadata) {
	record := m.records[command.id]
	if record == nil {
		command.reply <- metadataRequest{err: attachmentNotFound()}
		return
	}

	record.metadataRevision++
	request := metadataRequest{record: record, revision: record.metadataRevision}
	source := &record.attachment.report.Sources.MDS

	info := record.attachment.report.Sources.GetInfo.Data
	if info == nil || info.AAGUID == uuid.Nil() {
		source.Outcome = report.Outcome{State: report.SourceUnavailable, Reason: report.ReasonAAGUIDMissing}
	} else {
		source.Outcome = report.Outcome{State: report.SourceLoading}
		request.aaguid = info.AAGUID
	}

	request.report = record.attachment.report

	m.publish(nil)

	command.reply <- request
}

func (m *DeviceManager) finishMetadata(command finishMetadata) {
	request := command.request

	record := m.records[request.report.Attachment.ID]
	if record != request.record {
		command.reply <- reportReply{report: request.report, err: attachmentNotFound()}
		return
	}

	err := NormalizeError(lifecycleError(command.err), failure.PhaseMetadata)
	if record.metadataRevision != request.revision {
		command.reply <- reportReply{report: record.attachment.report, err: err}
		return
	}

	source := &record.attachment.report.Sources.MDS

	source.Outcome = metadataOutcome(command.err)
	if command.err == nil {
		source.Data = &command.result
		if !command.result.Found {
			source.State = report.SourceAbsent
		}

		if command.result.RefreshErr != nil {
			source.Outcome = metadataOutcome(command.result.RefreshErr)
		}
	}

	m.publish(nil)

	command.reply <- reportReply{report: record.attachment.report, err: err}
}

func metadataOutcome(err error) report.Outcome {
	if err == nil {
		return report.Outcome{State: report.SourceAvailable}
	}

	return report.Outcome{State: report.SourceFailed, Error: failure.Snapshot(NormalizeError(err, failure.PhaseMetadata))}
}
