package workflow

import (
	"context"

	"github.com/telesma-app/kit/internal/authenticator"
	rtinspect "github.com/telesma-app/kit/internal/inspect"
	appinspect "github.com/telesma-app/kit/model/inspect"
)

func (r Runner) GetInfo(ctx context.Context, device authenticator.InfoProvider) (appinspect.Info, error) {
	info, err := r.getAuthenticatorInfo(ctx, device)
	if err != nil {
		return appinspect.Info{}, err
	}

	return rtinspect.BuildInfo(info), nil
}
