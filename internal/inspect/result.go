package inspect

import (
	"github.com/telesma-app/ctap/protocol"
	"github.com/telesma-app/kit/internal/getinfo"
	appinspect "github.com/telesma-app/kit/model/inspect"
)

func BuildInfo(info protocol.AuthenticatorGetInfoResponse) appinspect.Info {
	result := appinspect.Info{
		AuthenticatorGetInfoResponse: info,
		Assessment:                   getinfo.Resolve(info),
	}
	if info.UvModality != nil {
		result.UVModalityLabel = info.UvModality.String()
	}

	return result
}
