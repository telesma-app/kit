package ctap23

import (
	"context"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/client"
	"github.com/telesma-app/ctap/credential"
	ctapcrypto "github.com/telesma-app/ctap/crypto"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
	"golang.org/x/text/unicode/norm"
)

const (
	clientPINRetryRPID = "pin-retries.ctap23-conformance.example"
	clientPINRetryName = "CTAP 2.3 PIN retries conformance"
)

var clientPINRetryClientDataHash = [...]byte{
	0x7d, 0x42, 0x49, 0xb3, 0x5f, 0x21, 0x9c, 0x4a,
	0x9e, 0x16, 0x88, 0xa3, 0x2c, 0x49, 0x68, 0x15,
	0xf5, 0x12, 0x0d, 0x84, 0x6f, 0x8b, 0x45, 0x9e,
	0x43, 0x6c, 0x63, 0x8b, 0x80, 0x92, 0x3d, 0xe2,
}

func readClientPINRetries(
	ctx context.Context,
	device ctaptransport.CBOR,
	pinUvAuthProtocol protocol.PinUvAuthProtocol,
) (uint, error) {
	return readClientPINRetryValue(
		ctx,
		device,
		pinUvAuthProtocol,
		protocol.ClientPINSubCommandGetPINRetries,
		3,
		"pinRetries",
		0,
		8,
	)
}

func readClientUVRetries(
	ctx context.Context,
	device ctaptransport.CBOR,
	pinUvAuthProtocol protocol.PinUvAuthProtocol,
) (uint, error) {
	return readClientPINRetryValue(
		ctx,
		device,
		pinUvAuthProtocol,
		protocol.ClientPINSubCommandGetUVRetries,
		5,
		"uvRetries",
		1,
		25,
	)
}

func readClientPINRetryValue(
	ctx context.Context,
	device ctaptransport.CBOR,
	pinUvAuthProtocol protocol.PinUvAuthProtocol,
	subCommand protocol.ClientPINSubCommand,
	responseKey uint64,
	name string,
	minimum uint,
	maximum uint,
) (uint, error) {
	request := []byte{
		byte(protocol.AuthenticatorClientPIN),
		0xa2,
		0x01, byte(pinUvAuthProtocol),
		0x02, byte(subCommand),
	}
	response, err := device.CBOR(ctx, request)
	if err == nil {
		response, err = ctaptransport.ValidateCBORResponse(protocol.AuthenticatorClientPIN, response)
	}
	if err != nil {
		var ctapError *ctaptransport.CTAPError
		if errors.As(err, &ctapError) {
			return 0, conformance.Failf("authenticatorClientPIN %s returned %s", subCommandName(subCommand), ctapError.StatusCode)
		}

		return 0, err
	}

	if err := validateCanonicalClientPINResponse(response.Data); err != nil {
		return 0, err
	}

	var fields map[uint64]cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(response.Data, &fields); err != nil {
		return 0, conformance.Failf("invalid authenticatorClientPIN response CBOR: %v", err)
	}
	raw, present := fields[responseKey]
	if !present {
		return 0, conformance.Failf("authenticatorClientPIN response is missing %s", name)
	}
	if !hasCBORMajorType(raw, 0) {
		return 0, conformance.Failf("%s is not a CBOR unsigned integer", name)
	}

	var value uint
	if err := getInfoDecMode.Unmarshal(raw, &value); err != nil {
		return 0, conformance.Failf("invalid %s value: %v", name, err)
	}
	if value < minimum || value > maximum {
		return 0, conformance.Failf("%s is %d, want %d..%d", name, value, minimum, maximum)
	}

	return value, nil
}

func subCommandName(subCommand protocol.ClientPINSubCommand) string {
	name, ok := subCommand.Name()
	if ok {
		return name
	}

	return subCommand.String()
}

func getLegacyPINToken(
	ctx context.Context,
	client *client.Client,
	pinUvAuthProtocol protocol.PinUvAuthProtocol,
	pin string,
) ([]byte, error) {
	keyAgreement, err := client.GetKeyAgreement(ctx, pinUvAuthProtocol)
	if err != nil {
		return nil, err
	}

	return client.GetPinToken(ctx, pinUvAuthProtocol, keyAgreement, pin)
}

func makeCredentialWithPINToken(
	ctx context.Context,
	client *client.Client,
	pinUvAuthProtocol protocol.PinUvAuthProtocol,
	pinUvAuthToken []byte,
	algorithms []credential.PublicKeyCredentialParameters,
) (protocol.AuthenticatorMakeCredentialResponse, error) {
	publicKeyAlgorithms := make([]credential.PublicKeyCredentialParameters, 0, len(algorithms))
	for _, algorithm := range algorithms {
		if algorithm.Type == credential.PublicKeyCredentialTypePublicKey {
			publicKeyAlgorithms = append(publicKeyAlgorithms, algorithm)
		}
	}
	if len(publicKeyAlgorithms) == 0 {
		return protocol.AuthenticatorMakeCredentialResponse{}, conformance.Fail(
			"GetInfo algorithms contains no public-key credential algorithm",
		)
	}

	response, err := client.MakeCredential(
		ctx,
		pinUvAuthProtocol,
		pinUvAuthToken,
		clientPINRetryClientDataHash[:],
		credential.PublicKeyCredentialRpEntity{
			ID:   clientPINRetryRPID,
			Name: clientPINRetryName,
		},
		credential.PublicKeyCredentialUserEntity{
			ID:          []byte("pin-retries-user"),
			Name:        "pin-retries-user",
			DisplayName: clientPINRetryName,
		},
		publicKeyAlgorithms,
		nil,
		nil,
		nil,
		0,
		nil,
	)

	return response, unexpectedCTAPStatus("authenticatorMakeCredential", err)
}

func temporaryPINRequest(info protocol.AuthenticatorGetInfoResponse) TemporaryPINRequest {
	return TemporaryPINRequest{
		MinCodePoints: info.EffectiveMinPINLength(),
		MaxCodePoints: info.EffectiveMaxPINLength(),
	}
}

func validateTemporaryPIN(pin []byte, request TemporaryPINRequest) error {
	if !utf8.Valid(pin) {
		return fmt.Errorf("ctap23: temporary PIN provider returned invalid UTF-8")
	}
	if len(pin) > 63 {
		return fmt.Errorf("ctap23: temporary PIN provider returned %d UTF-8 bytes, want at most 63", len(pin))
	}
	if !norm.NFC.IsNormal(pin) {
		return fmt.Errorf("ctap23: temporary PIN provider returned a PIN that is not NFC-normalized")
	}
	codePoints := uint(utf8.RuneCount(pin))
	if codePoints < request.MinCodePoints || codePoints > request.MaxCodePoints {
		return fmt.Errorf(
			"ctap23: temporary PIN provider returned %d code points, want %d..%d",
			codePoints,
			request.MinCodePoints,
			request.MaxCodePoints,
		)
	}

	return nil
}

func setPINForPolicyTest(
	ctx context.Context,
	ctapClient *client.Client,
	device ctaptransport.CBOR,
	pinUvAuthProtocol protocol.PinUvAuthProtocol,
	paddedPIN *[64]byte,
) error {
	keyAgreement, err := ctapClient.GetKeyAgreement(ctx, pinUvAuthProtocol)
	if err != nil {
		return unexpectedCTAPStatus("authenticatorClientPIN getKeyAgreement", err)
	}
	pinProtocol, err := ctapcrypto.NewPinUvAuthProtocol(pinUvAuthProtocol)
	if err != nil {
		return err
	}
	platformKey, sharedSecret, err := pinProtocol.Encapsulate(keyAgreement)
	if err != nil {
		return err
	}
	defer clear(sharedSecret)

	newPINEnc, err := pinProtocol.Encrypt(sharedSecret, paddedPIN[:])
	if err != nil {
		return err
	}
	defer clear(newPINEnc)
	pinUvAuthParam := ctapcrypto.Authenticate(pinUvAuthProtocol, sharedSecret, newPINEnc)
	defer clear(pinUvAuthParam)

	_, err = exchangeCTAP2(ctx, device, protocol.AuthenticatorClientPIN, protocol.AuthenticatorClientPINRequest{
		PinUvAuthProtocol: pinUvAuthProtocol,
		SubCommand:        protocol.ClientPINSubCommandSetPIN,
		KeyAgreement:      platformKey,
		NewPinEnc:         newPINEnc,
		PinUvAuthParam:    pinUvAuthParam,
	})

	return err
}

func differentTemporaryPIN(pin []byte) []byte {
	runes := []rune(string(pin))
	defer clear(runes)

	if runes[0] == '0' {
		runes[0] = '1'
	} else {
		runes[0] = '0'
	}

	return []byte(string(runes))
}

func clientPINRetriesReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "ctap-2.3-ps-20260226:6.5.2.3:pin-and-uv-retries-counters",
		Specification: conformance.SpecificationCTAP23,
		Section:       "6.5.2.3",
		Clause:        "pin-and-uv-retries-counters",
		URL:           "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#pin-entry-and-user-verification-retries-counters",
		Level:         conformance.RequirementConstraint,
	}
}

func clientPINMaximumRetriesReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "ctap-2.3-ps-20260226:6.5.2.3:pin-retries-maximum",
		Specification: conformance.SpecificationCTAP23,
		Section:       "6.5.2.3",
		Clause:        "pin-retries-maximum",
		URL:           "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#pinRetries",
		Level:         conformance.RequirementMust,
	}
}

func clientPINSetReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "ctap-2.3-ps-20260226:6.5.5.5:set-pin",
		Specification: conformance.SpecificationCTAP23,
		Section:       "6.5.5.5",
		Clause:        "set-pin",
		URL:           "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#settingNewPin",
		Level:         conformance.RequirementConstraint,
	}
}

func clientPINPowerCycleReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "ctap-2.3-ps-20260226:6.5.5.1:pin-protocol-power-cycle",
		Specification: conformance.SpecificationCTAP23,
		Section:       "6.5.5.1",
		Clause:        "pin-protocol-power-cycle",
		URL:           "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#powerCycle",
		Level:         conformance.RequirementConstraint,
	}
}

func clientPINGetRetriesReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "ctap-2.3-ps-20260226:6.5.5.2:get-pin-retries-response",
		Specification: conformance.SpecificationCTAP23,
		Section:       "6.5.5.2",
		Clause:        "get-pin-retries-response",
		URL:           "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#getRetries",
		Level:         conformance.RequirementConstraint,
	}
}

func clientPINLegacyTokenReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "ctap-2.3-ps-20260226:6.5.5.7.1:get-pin-token-retries",
		Specification: conformance.SpecificationCTAP23,
		Section:       "6.5.5.7.1",
		Clause:        "get-pin-token-retries",
		URL:           "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#getPinToken",
		Level:         conformance.RequirementConstraint,
	}
}

func clientPINMakeCredentialReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "ctap-2.3-ps-20260226:6.1:pin-uv-authenticated-make-credential",
		Specification: conformance.SpecificationCTAP23,
		Section:       "6.1",
		Clause:        "pin-uv-authenticated-make-credential",
		URL:           "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorMakeCredential",
		Level:         conformance.RequirementConstraint,
	}
}
