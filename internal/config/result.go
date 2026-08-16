package config

import (
	appconfig "github.com/telesma-app/kit/model/config"
	"github.com/telesma-app/kit/model/report"
)

func AlwaysUVResult(attachmentID report.AttachmentID, target appconfig.AlwaysUVTarget, requestedAlwaysUV bool) *appconfig.AuthenticatorConfigResult {
	state := appconfig.StateNotConfigured
	if requestedAlwaysUV {
		state = appconfig.StateConfigured
	}

	return &appconfig.AuthenticatorConfigResult{
		Operation:    appconfig.AuthenticatorConfigAlwaysUV,
		AttachmentID: attachmentID,
		Target:       target,
		State:        state,
	}
}
