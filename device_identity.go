package ctapkit

import (
	"strconv"

	"github.com/telesma-app/kit/model/report"
)

// Identity is derived from the same saved vendor observations used by callers.
// No additional command or silent error path exists just for grouping.
func identityFromSources(sources report.Sources) report.DeviceIdentity {
	if info := sources.Yubico.Data; info != nil && info.SerialNumber != nil && *info.SerialNumber != 0 {
		return report.DeviceIdentity{Vendor: report.VendorYubico, SerialNumber: strconv.FormatUint(uint64(*info.SerialNumber), 10)}
	}

	if info := sources.Token2.Data; info != nil && info.SerialNumber.Value != nil && *info.SerialNumber.Value != "" {
		return report.DeviceIdentity{Vendor: report.VendorToken2, SerialNumber: *info.SerialNumber.Value}
	}

	return report.DeviceIdentity{}
}
