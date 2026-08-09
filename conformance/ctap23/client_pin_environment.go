package ctap23

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/client"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
)

func validateClientPINProtocolSupport(
	fields map[uint64]cbor.RawMessage,
	info protocol.AuthenticatorGetInfoResponse,
	config Config,
	version protocol.PinUvAuthProtocol,
) error {
	_, extensionsPresent := fields[2]
	supported := extensionsPresent && slices.Contains(info.PinUvAuthProtocols, version)
	if supported {
		return nil
	}

	switch version {
	case protocol.PinUvAuthProtocolOne:
		if !config.Featureful {
			return conformance.Skip("PIN/UV protocol 1 is not advertised by the non-featureful profile")
		}
		switch config.Transport {
		case AuthenticatorTransportNFC:
			return conformance.Skip("PIN/UV protocol 1 is optional for the CTAP 2.3 featureful NFC profile")
		case AuthenticatorTransportHID, AuthenticatorTransportBLE:
			return conformance.Fail("pinUvAuthProtocols does not contain PIN/UV protocol 1")
		default:
			return fmt.Errorf("ctap23: authenticator transport %q cannot assess protocol 1 support", config.Transport)
		}
	case protocol.PinUvAuthProtocolTwo:
		if config.Featureful {
			return conformance.Fail("featureful profile requires PIN/UV protocol 2 with the extensions field present")
		}

		return conformance.Skip("authenticator does not advertise PIN/UV protocol 2 with its extensions")
	default:
		panic("ctap23: unsupported PIN/UV protocol support check")
	}
}

func unexpectedCTAPStatus(operation string, err error) error {
	if err == nil {
		return nil
	}

	var ctapErr *ctaptransport.CTAPError
	if errors.As(err, &ctapErr) {
		return conformance.Failf("%s returned %s", operation, ctapErr.StatusCode)
	}

	return err
}

func ctapMessageEncodingReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "ctap-2.3-ps-20260226:8:message-encoding",
		Specification: conformance.SpecificationCTAP23,
		Section:       "8",
		Clause:        "message-encoding",
		URL:           "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#message-encoding",
		Level:         conformance.RequirementMust,
	}
}

func resetAuthenticatorForTest(
	ctx context.Context,
	client *client.Client,
	resetter AuthenticatorResetter,
) error {
	if resetter != nil {
		return resetCommandError(resetter(ctx, client))
	}

	return resetCommandError(client.Reset(ctx))
}
