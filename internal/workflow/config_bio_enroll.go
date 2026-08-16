package workflow

import (
	"context"
	"encoding/hex"
	"time"

	"github.com/telesma-app/ctap/protocol"
	rtconfig "github.com/telesma-app/kit/internal/config"
	"github.com/telesma-app/kit/internal/errornorm"
	rtruntime "github.com/telesma-app/kit/internal/runtime"
	"github.com/telesma-app/kit/model"
	appconfig "github.com/telesma-app/kit/model/config"
	"github.com/telesma-app/kit/model/failure"
	"github.com/telesma-app/kit/model/safety"
)

const bioEnrollmentCancelTimeout = 2 * time.Second

func (r Runner) BioEnroll(
	ctx context.Context,
	device BioDevice,
	req appconfig.BioEnrollOperation,
) (appconfig.BioEnrollOutput, error) {
	info, err := r.getAuthenticatorInfo(ctx, device)
	if err != nil {
		return appconfig.BioEnrollOutput{}, err
	}
	status := rtconfig.BuildStatusReport(r.env.Selected, info)

	mode := safety.PreviewModeExecute
	if req.DryRun {
		mode = safety.PreviewModeDryRun
	}

	preview, err := rtconfig.BuildBioEnrollPreview(status, req.TimeoutMilliseconds, mode)
	if err != nil {
		return appconfig.BioEnrollOutput{}, err
	}

	if req.DryRun {
		return appconfig.BioEnrollOutput{Preview: preview}, nil
	}

	var responses []protocol.AuthenticatorBioEnrollmentResponse
	err = r.env.Tokens.Use(ctx, rtruntime.TokenUse{
		Permission: protocol.PermissionBioEnrollment,
	}, func(token []byte) error {
		current, err := r.runBioEnrollment(
			ctx,
			device,
			appconfig.BioEnrollRequest{
				TimeoutMilliseconds: req.TimeoutMilliseconds,
			},
			bioEnrollmentCommand(status),
			token,
		)
		if err != nil {
			return err
		}
		responses = current

		return nil
	})
	if err != nil {
		return appconfig.BioEnrollOutput{}, err
	}

	return appconfig.BioEnrollOutput{
		Preview: preview,
		Result:  buildBioEnrollmentResult(preview, responses),
	}, nil
}

func (r Runner) bioEnrollmentProgress(
	ctx context.Context,
) func(protocol.AuthenticatorBioEnrollmentResponse) {
	var completed uint64

	return func(response protocol.AuthenticatorBioEnrollmentResponse) {
		completed++
		event := model.OperationEvent{
			Stage:        model.OperationStageCapturingBioSample,
			Completed:    new(completed),
			SampleStatus: bioEnrollmentSampleStatus(response),
		}

		if response.RemainingSamples != nil {
			total := completed + uint64(*response.RemainingSamples)
			event.Total = new(total)
		}
		r.env.Events.Emit(ctx, event)
	}
}

func (r Runner) runBioEnrollment(
	ctx context.Context,
	device BioDevice,
	req appconfig.BioEnrollRequest,
	command protocol.Command,
	token []byte,
) ([]protocol.AuthenticatorBioEnrollmentResponse, error) {
	progress := r.bioEnrollmentProgress(ctx)

	cancelAfterFailure := func(cause error) ([]protocol.AuthenticatorBioEnrollmentResponse, error) {
		cancelCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), bioEnrollmentCancelTimeout)
		defer cancel()
		_ = device.CancelCurrentEnrollment(cancelCtx)

		return nil, cause
	}

	begin, err := device.EnrollBegin(ctx, token, req.TimeoutMilliseconds)
	if err != nil {
		return nil, errornorm.Annotate(err, errornorm.WithBioEnrollmentSubCommand(
			failure.PhaseAuthenticatorCommand,
			command,
			protocol.BioEnrollmentSubCommandEnrollBegin,
		))
	}

	responses := []protocol.AuthenticatorBioEnrollmentResponse{begin}
	progress(begin)

	remaining := begin.RemainingSamples
	for remaining != nil && *remaining > 0 {
		if err := ctx.Err(); err != nil {
			return cancelAfterFailure(errornorm.Annotate(err, errornorm.WithBioEnrollmentSubCommand(
				failure.PhaseAuthenticatorCommand,
				command,
				protocol.BioEnrollmentSubCommandEnrollCaptureNextSample,
			)))
		}

		next, err := device.EnrollCaptureNextSample(ctx, token, begin.TemplateID, req.TimeoutMilliseconds)
		if err != nil {
			return cancelAfterFailure(errornorm.Annotate(err, errornorm.WithBioEnrollmentSubCommand(
				failure.PhaseAuthenticatorCommand,
				command,
				protocol.BioEnrollmentSubCommandEnrollCaptureNextSample,
			)))
		}

		responses = append(responses, next)
		remaining = next.RemainingSamples
		progress(next)
	}

	return responses, nil
}

func buildBioEnrollmentResult(
	preview appconfig.BioEnrollPreview,
	responses []protocol.AuthenticatorBioEnrollmentResponse,
) *appconfig.BioEnrollResult {
	result := &appconfig.BioEnrollResult{
		AttachmentID: preview.Device.Attachment.ID,
		PreviewOnly:  preview.PreviewOnly,
		Samples:      make([]appconfig.BioEnrollSample, 0, len(responses)),
	}

	for _, response := range responses {
		if len(response.TemplateID) > 0 {
			result.TemplateIDHex = hex.EncodeToString(response.TemplateID)
		}

		result.LastEnrollSampleStatus = bioEnrollmentSampleStatus(response)
		result.RemainingSamples = response.RemainingSamples
		result.Samples = append(result.Samples, appconfig.BioEnrollSample{
			Status:           result.LastEnrollSampleStatus,
			RemainingSamples: result.RemainingSamples,
		})
	}

	return result
}

func bioEnrollmentSampleStatus(
	response protocol.AuthenticatorBioEnrollmentResponse,
) string {
	if response.LastEnrollSampleStatus == nil {
		return ""
	}

	return response.LastEnrollSampleStatus.String()
}
