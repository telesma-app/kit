package ctap23

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/telesma-app/ctap/attestation"
	"github.com/telesma-app/ctap/client"
	"github.com/telesma-app/ctap/cose"
	"github.com/telesma-app/ctap/credential"
	ctapcrypto "github.com/telesma-app/ctap/crypto"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
)

type residentKeyTestCredential struct {
	id   []byte
	user credential.PublicKeyCredentialUserEntity
	key  cose.Key
}

type residentKeyTestDevice struct {
	t                 testing.TB
	residentKeys      bool
	protocolTwo       bool
	uvPresent         bool
	uvConfigured      bool
	alwaysUV          bool
	storeStatePresent bool
	storeState        []byte
	credentials       []residentKeyTestCredential
	pending           []int
	selectedUser      []byte
	credentialCounter byte
	badCount          bool
	transportError    error
	getNextCalls      int
	operations        []string
	responseBuffers   [][]byte
	token             []byte
}

func newResidentKeyTestDevice(t testing.TB) *residentKeyTestDevice {
	state := append(bytes.Repeat([]byte{0x10}, 16), bytes.Repeat([]byte{0x20}, 16)...)
	return &residentKeyTestDevice{
		t:                 t,
		residentKeys:      true,
		protocolTwo:       true,
		uvPresent:         true,
		storeStatePresent: true,
		storeState:        state,
		token:             bytes.Repeat([]byte{0x5a}, 32),
	}
}

func (device *residentKeyTestDevice) CBOR(
	ctx context.Context,
	request []byte,
) (ctaptransport.CBORResponse, error) {
	device.t.Helper()
	if err := ctx.Err(); err != nil {
		return ctaptransport.CBORResponse{}, err
	}
	if len(request) == 0 {
		device.t.Fatal("empty CTAP request")
	}

	switch protocol.Command(request[0]) {
	case protocol.AuthenticatorGetInfo:
		if len(request) != 1 {
			device.t.Fatalf("GetInfo request length = %d, want 1", len(request))
		}
		return device.getInfo(), nil
	case protocol.AuthenticatorMakeCredential:
		return device.makeCredential(request[1:])
	case protocol.AuthenticatorGetAssertion:
		return device.getAssertion(request[1:])
	case protocol.AuthenticatorGetNextAssertion:
		if len(request) != 1 {
			device.t.Fatalf("GetNextAssertion request length = %d, want 1", len(request))
		}
		return device.getNextAssertion()
	default:
		device.t.Fatalf("unexpected CTAP command %s", protocol.Command(request[0]))
		return ctaptransport.CBORResponse{}, nil
	}
}

func (device *residentKeyTestDevice) getInfo() ctaptransport.CBORResponse {
	options := map[string]any{
		string(protocol.OptionResidentKeys):     device.residentKeys,
		string(protocol.OptionAlwaysUv):         device.alwaysUV,
		string(protocol.OptionUserVerification): device.uvConfigured,
		string(protocol.OptionPinUvAuthToken):   true,
	}
	protocols := []uint{}
	if device.protocolTwo {
		protocols = append(protocols, uint(protocol.PinUvAuthProtocolTwo))
	}
	fields := map[uint64]any{
		1: []string{string(protocol.FIDO_2_3)},
		2: []string{},
		3: make([]byte, 16),
		4: options,
		6: protocols,
		10: []map[string]any{{
			"type": string(credential.PublicKeyCredentialTypePublicKey),
			"alg":  int(cose.AlgorithmES256),
		}},
	}
	if !device.uvPresent {
		delete(options, string(protocol.OptionUserVerification))
	}
	if device.storeStatePresent {
		fields[30] = slices.Clone(device.storeState)
	}

	return device.success(fields)
}

func (device *residentKeyTestDevice) makeCredential(
	body []byte,
) (ctaptransport.CBORResponse, error) {
	device.operations = append(device.operations, "makeCredential")
	if device.transportError != nil {
		return ctaptransport.CBORResponse{}, device.transportError
	}

	var request protocol.AuthenticatorMakeCredentialRequest
	if err := getInfoDecMode.Unmarshal(body, &request); err != nil {
		device.t.Fatal(err)
	}
	if len(request.Options) != 1 || !request.Options[protocol.OptionResidentKeys] {
		device.t.Fatalf("MakeCredential options = %#v, want only rk=true", request.Options)
	}
	device.requireAuthorization(
		request.PinUvAuthProtocol,
		request.PinUvAuthParam,
		request.ClientDataHash,
		device.uvConfigured || device.alwaysUV,
	)

	device.credentialCounter++
	credentialID := []byte{0xc0, device.credentialCounter}
	key := cose.Key{
		cose.KeyParameterKty:    cose.KeyTypeEC2,
		cose.KeyParameterAlg:    cose.AlgorithmES256,
		cose.EC2KeyParameterCrv: cose.EllipticCurveP256,
		cose.EC2KeyParameterX:   bytes.Repeat([]byte{device.credentialCounter}, 32),
		cose.EC2KeyParameterY:   bytes.Repeat([]byte{device.credentialCounter + 1}, 32),
	}
	entry := residentKeyTestCredential{
		id: slices.Clone(credentialID),
		user: credential.PublicKeyCredentialUserEntity{
			ID:          slices.Clone(request.User.ID),
			Name:        request.User.Name,
			DisplayName: request.User.DisplayName,
		},
		key: key,
	}
	replaced := false
	for index := range device.credentials {
		if bytes.Equal(device.credentials[index].user.ID, request.User.ID) {
			device.clearCredential(&device.credentials[index])
			device.credentials[index] = entry
			replaced = true
			break
		}
	}
	if !replaced {
		device.credentials = append(device.credentials, entry)
	}

	device.storeState = append(
		bytes.Repeat([]byte{0x10 + device.credentialCounter}, 16),
		bytes.Repeat([]byte{0x20 + device.credentialCounter}, 16)...,
	)
	flags := protocol.AuthDataFlagUserPresent | protocol.AuthDataFlagAttestedCredentialDataIncluded
	if device.uvConfigured || device.alwaysUV {
		flags |= protocol.AuthDataFlagUserVerified
	}
	response := map[uint64]any{
		1: string(attestation.AttestationStatementFormatIdentifierNone),
		2: residentKeyTestMakeCredentialAuthData(device.t, credentialID, key, flags),
		3: map[string]any{},
	}
	return device.success(response), nil
}

func (device *residentKeyTestDevice) getAssertion(
	body []byte,
) (ctaptransport.CBORResponse, error) {
	device.operations = append(device.operations, "getAssertion")
	if device.transportError != nil {
		return ctaptransport.CBORResponse{}, device.transportError
	}

	var request protocol.AuthenticatorGetAssertionRequest
	if err := getInfoDecMode.Unmarshal(body, &request); err != nil {
		device.t.Fatal(err)
	}
	device.requireAuthorization(
		request.PinUvAuthProtocol,
		request.PinUvAuthParam,
		request.ClientDataHash,
		device.uvConfigured || device.alwaysUV,
	)

	indices := make([]int, 0, len(device.credentials))
	if len(request.AllowList) != 0 {
		if len(request.AllowList) != 1 ||
			request.AllowList[0].Type != credential.PublicKeyCredentialTypePublicKey {
			device.t.Fatalf("GetAssertion allowList = %#v", request.AllowList)
		}
		for index := range device.credentials {
			if bytes.Equal(device.credentials[index].id, request.AllowList[0].ID) {
				indices = append(indices, index)
			}
		}
	} else if len(device.selectedUser) != 0 {
		for index := range device.credentials {
			if bytes.Equal(device.credentials[index].user.ID, device.selectedUser) {
				indices = append(indices, index)
			}
		}
	} else {
		for index := range device.credentials {
			indices = append(indices, index)
		}
	}
	if len(indices) == 0 {
		return ctaptransport.CBORResponse{
			StatusCode: ctaptransport.CTAP2_ERR_NO_CREDENTIALS,
		}, nil
	}

	selected := len(device.selectedUser) != 0
	device.selectedUser = nil
	device.pending = append(device.pending[:0], indices[1:]...)
	return device.assertion(indices[0], !selected && len(indices) > 1, selected), nil
}

func (device *residentKeyTestDevice) getNextAssertion() (ctaptransport.CBORResponse, error) {
	device.operations = append(device.operations, "getNextAssertion")
	device.getNextCalls++
	if len(device.pending) == 0 {
		return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_ERR_NOT_ALLOWED}, nil
	}
	index := device.pending[0]
	device.pending = device.pending[1:]
	return device.assertion(index, false, false), nil
}

func (device *residentKeyTestDevice) assertion(
	index int,
	includeCount bool,
	selected bool,
) ctaptransport.CBORResponse {
	entry := device.credentials[index]
	user := map[string]any{"id": slices.Clone(entry.user.ID)}
	if device.uvConfigured || device.alwaysUV {
		user["name"] = entry.user.Name
		user["displayName"] = entry.user.DisplayName
	}
	flags := protocol.AuthDataFlagUserPresent
	if device.uvConfigured || device.alwaysUV {
		flags |= protocol.AuthDataFlagUserVerified
	}
	response := map[uint64]any{
		1: map[string]any{
			"type": string(credential.PublicKeyCredentialTypePublicKey),
			"id":   slices.Clone(entry.id),
		},
		2: residentKeyTestAssertionAuthData(flags),
		3: []byte{0x30, 0x00},
		4: user,
	}
	if includeCount {
		count := uint(len(device.credentials))
		if device.badCount {
			count--
		}
		response[5] = count
	}
	if selected {
		response[6] = true
	}
	return device.success(response)
}

func (device *residentKeyTestDevice) requireAuthorization(
	protocolValue protocol.PinUvAuthProtocol,
	parameter []byte,
	clientDataHash []byte,
	required bool,
) {
	device.t.Helper()
	if !required {
		if protocolValue != 0 || len(parameter) != 0 {
			device.t.Fatal("unauthenticated request unexpectedly contained PIN/UV authorization")
		}
		return
	}
	if protocolValue != protocol.PinUvAuthProtocolTwo {
		device.t.Fatalf("pinUvAuthProtocol = %d, want 2", protocolValue)
	}
	expected := ctapcrypto.Authenticate(protocol.PinUvAuthProtocolTwo, device.token, clientDataHash)
	defer clear(expected)
	if !bytes.Equal(parameter, expected) {
		device.t.Fatalf("invalid protocol 2 pinUvAuthParam: %x", parameter)
	}
}

func (device *residentKeyTestDevice) success(value any) ctaptransport.CBORResponse {
	data, err := ctap2EncMode.Marshal(value)
	if err != nil {
		device.t.Fatal(err)
	}
	device.responseBuffers = append(device.responseBuffers, data)
	return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_OK, Data: data}
}

func (device *residentKeyTestDevice) reset() {
	for index := range device.credentials {
		device.clearCredential(&device.credentials[index])
	}
	clear(device.credentials)
	device.credentials = nil
	device.pending = nil
	clear(device.selectedUser)
	device.selectedUser = nil
	device.credentialCounter = 0
	device.uvConfigured = false
	clear(device.storeState)
	device.storeState = append(bytes.Repeat([]byte{0x10}, 16), bytes.Repeat([]byte{0x20}, 16)...)
}

func (device *residentKeyTestDevice) clearCredential(value *residentKeyTestCredential) {
	clear(value.id)
	value.id = nil
	clear(value.user.ID)
	value.user.ID = nil
	clearResidentKeyCOSEKey(value.key)
	value.key = nil
}

func residentKeyTestMakeCredentialAuthData(
	t testing.TB,
	credentialID []byte,
	key cose.Key,
	flags protocol.AuthDataFlag,
) []byte {
	t.Helper()
	keyData, err := ctap2EncMode.Marshal(key)
	if err != nil {
		t.Fatal(err)
	}
	authData := make([]byte, 0, 37+16+2+len(credentialID)+len(keyData))
	authData = append(authData, make([]byte, 32)...)
	authData = append(authData, byte(flags), 0, 0, 0, 0)
	authData = append(authData, make([]byte, 16)...)
	authData = append(authData, byte(len(credentialID)>>8), byte(len(credentialID)))
	authData = append(authData, credentialID...)
	authData = append(authData, keyData...)
	clear(keyData)
	return authData
}

func residentKeyTestAssertionAuthData(flags protocol.AuthDataFlag) []byte {
	authData := make([]byte, 37)
	authData[32] = byte(flags)
	return authData
}

type residentKeyTestEnvironment struct {
	device        *residentKeyTestDevice
	events        []string
	tokenRequests []PinUvAuthTokenRequest
	tokenBuffers  [][]byte
	pinBuffers    [][]byte
	hookError     error
}

func (environment *residentKeyTestEnvironment) config() Config {
	return Config{
		Featureful:              true,
		AccountSelectionDisplay: AccountSelectionDisplayAbsent,
		PowerCycler: func(context.Context) error {
			environment.events = append(environment.events, "power-cycle")
			return nil
		},
		Resetter: func(context.Context, *client.Client) error {
			environment.events = append(environment.events, "reset")
			environment.device.reset()
			return nil
		},
		TemporaryPINProvider: func(context.Context, TemporaryPINRequest) ([]byte, error) {
			pin := []byte("1234")
			environment.pinBuffers = append(environment.pinBuffers, pin)
			return pin, nil
		},
		UVConfigurator: func(context.Context, []byte) error {
			environment.events = append(environment.events, "configure-uv")
			environment.device.uvConfigured = true
			return nil
		},
		TokenProvider: func(
			_ context.Context,
			_ *client.Client,
			request PinUvAuthTokenRequest,
		) (PinUvAuthToken, error) {
			environment.tokenRequests = append(environment.tokenRequests, request)
			value := slices.Clone(environment.device.token)
			environment.tokenBuffers = append(environment.tokenBuffers, value)
			return PinUvAuthToken{Protocol: protocol.PinUvAuthProtocolTwo, Value: value}, nil
		},
		PrepareAccountSelection: func(_ context.Context, request AccountSelectionRequest) error {
			environment.events = append(environment.events, "hook:"+fmt.Sprintf("%x", request.UserID))
			if environment.hookError != nil {
				return environment.hookError
			}
			environment.device.selectedUser = slices.Clone(request.UserID)
			return nil
		},
	}
}

func allZeroResidentKey(value []byte) bool {
	return !slices.ContainsFunc(value, func(item byte) bool { return item != 0 })
}

var errResidentKeyTransport = errors.New("resident-key test transport disconnected")
