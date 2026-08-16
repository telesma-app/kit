package workflow

import (
	"context"

	"github.com/telesma-app/ctap/protocol"
	rtconfig "github.com/telesma-app/kit/internal/config"
	"github.com/telesma-app/kit/internal/errornorm"
	appconfig "github.com/telesma-app/kit/model/config"
	"github.com/telesma-app/kit/model/failure"
)

func (r Runner) ConfigStatus(
	ctx context.Context,
	device ConfigStatusDevice,
) (appconfig.StatusReport, error) {
	if err := ctx.Err(); err != nil {
		return appconfig.StatusReport{}, errornorm.Annotate(err, errornorm.WithPhase(failure.PhaseAuthenticatorCommand))
	}

	info, err := r.getAuthenticatorInfo(ctx, device)
	if err != nil {
		return appconfig.StatusReport{}, err
	}
	rep := rtconfig.BuildStatusReport(r.env.Selected, info)
	if rep.PIN.Configured != nil && *rep.PIN.Configured {
		retries, powerCycle, err := device.GetPINRetries(ctx)
		if err != nil {
			return appconfig.StatusReport{}, errornorm.Annotate(
				err,
				errornorm.WithClientPINSubCommand(
					failure.PhaseAuthenticatorCommand,
					protocol.ClientPINSubCommandGetPINRetries,
				),
			)
		}
		rep.PIN.Retries = appconfig.RetryState{
			State:           appconfig.StateSupported,
			Remaining:       new(retries),
			PowerCycleState: powerCycle,
		}
	}

	if rep.UV.Supported &&
		rep.UV.Configured != nil &&
		*rep.UV.Configured {
		retries, err := device.GetUVRetries(ctx)
		if err != nil {
			return appconfig.StatusReport{}, errornorm.Annotate(
				err,
				errornorm.WithClientPINSubCommand(
					failure.PhaseAuthenticatorCommand,
					protocol.ClientPINSubCommandGetUVRetries,
				),
			)
		}
		rep.UV.Retries = appconfig.RetryState{
			State:     appconfig.StateSupported,
			Remaining: new(retries),
		}
	}

	return rep, nil
}
