package inspect

import (
	"github.com/telesma-app/ctap/protocol"
	"github.com/telesma-app/kit/internal/getinfo"
	appinspect "github.com/telesma-app/kit/model/inspect"
	"github.com/telesma-app/kit/model/report"
)

func BuildResult(device report.DeviceReport, info protocol.AuthenticatorGetInfoResponse) appinspect.Result {
	result := appinspect.Result{
		Device: device,
		Info: appinspect.Info{
			AuthenticatorGetInfoResponse: info,
			Assessment:                   getinfo.Resolve(info),
		},
	}

	if info.UvModality != nil {
		result.Info.UVModalityLabel = info.UvModality.String()
	}

	return result
}
