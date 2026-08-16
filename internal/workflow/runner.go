package workflow

import (
	"github.com/telesma-app/kit/internal/authenticator"
)

type Runner struct {
	env Environment
}

func NewRunner(env Environment) Runner {
	return Runner{env: env}
}

type LargeBlobDevice = authenticator.LargeBlobDevice
type ConfigStatusDevice = authenticator.ConfigStatusDevice
type ConfigDevice = authenticator.ConfigDevice
type BioDevice = authenticator.BioDevice
