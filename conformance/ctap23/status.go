package ctap23

import (
	"errors"
	"slices"
	"strings"

	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
)

func expectCTAPStatus(err error, expected ...ctaptransport.StatusCode) error {
	if err == nil {
		return conformance.Failf("command succeeded, want CTAP status %s", formatCTAPStatuses(expected))
	}

	var ctapError *ctaptransport.CTAPError
	if !errors.As(err, &ctapError) {
		return err
	}
	if slices.Contains(expected, ctapError.StatusCode) {
		return nil
	}

	return conformance.Failf(
		"command returned CTAP status %s, want %s",
		ctapError.StatusCode,
		formatCTAPStatuses(expected),
	)
}

func formatCTAPStatuses(statuses []ctaptransport.StatusCode) string {
	if len(statuses) == 1 {
		return statuses[0].String()
	}

	values := make([]string, len(statuses))
	for index, status := range statuses {
		values[index] = status.String()
	}

	return "one of [" + strings.Join(values, ", ") + "]"
}
