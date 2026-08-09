package ctap23

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"slices"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
	"github.com/telesma-app/ctap/attestation"
	"github.com/telesma-app/ctap/client"
	"github.com/telesma-app/ctap/cose"
	"github.com/telesma-app/ctap/credential"
	ctapcrypto "github.com/telesma-app/ctap/crypto"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
)

type enterpriseAttestationRecord struct {
	rpID string
	mode uint
}

type enterpriseAttestationTestDevice struct {
	t testing.TB

	profile       SecurityProfile
	enabled       bool
	enterpriseKey *ecdsa.PrivateKey
	enterpriseDER []byte
	regularKey    *ecdsa.PrivateKey
	regularDER    []byte
	token         []byte
	activeTokens  map[protocol.Permission][]byte
	tokenAliases  [][]byte
	responseData  [][]byte
	tokenRequests []PinUvAuthTokenRequest
	records       []enterpriseAttestationRecord
	resetCalls    int
	powerCycles   int
	configCalls   int
	forceEPFalse  bool
	reuseEPLeaf   bool
}

func newEnterpriseAttestationTestDevice(
	t testing.TB,
	profile SecurityProfile,
) *enterpriseAttestationTestDevice {
	enterpriseKey, enterpriseDER := enterpriseAttestationCertificate(t, 1, "Enterprise")
	regularKey, regularDER := enterpriseAttestationCertificate(t, 2, "Regular")
	return &enterpriseAttestationTestDevice{
		t:             t,
		profile:       profile,
		enterpriseKey: enterpriseKey,
		enterpriseDER: enterpriseDER,
		regularKey:    regularKey,
		regularDER:    regularDER,
		token:         bytes.Repeat([]byte{0x5a}, 32),
		activeTokens:  make(map[protocol.Permission][]byte),
	}
}

func (d *enterpriseAttestationTestDevice) config() Config {
	return Config{
		SecurityProfile: d.profile,
		PowerCycler: func(context.Context) error {
			d.powerCycles++
			return nil
		},
		Resetter: func(context.Context, *client.Client) error {
			d.resetCalls++
			d.enabled = false
			for permission, token := range d.activeTokens {
				clear(token)
				delete(d.activeTokens, permission)
			}
			return nil
		},
		TokenProvider: func(
			_ context.Context,
			_ *client.Client,
			request PinUvAuthTokenRequest,
		) (PinUvAuthToken, error) {
			d.tokenRequests = append(d.tokenRequests, request)
			value := slices.Clone(d.token)
			d.tokenAliases = append(d.tokenAliases, value)
			d.activeTokens[request.Permission] = slices.Clone(value)
			return PinUvAuthToken{Protocol: protocol.PinUvAuthProtocolTwo, Value: value}, nil
		},
	}
}

func (d *enterpriseAttestationTestDevice) CBOR(
	ctx context.Context,
	request []byte,
) (ctaptransport.CBORResponse, error) {
	if err := ctx.Err(); err != nil {
		return ctaptransport.CBORResponse{}, err
	}
	if len(request) == 0 {
		d.t.Fatal("empty CBOR request")
	}
	switch protocol.Command(request[0]) {
	case protocol.AuthenticatorGetInfo:
		return ctaptransport.CBORResponse{
			StatusCode: ctaptransport.CTAP2_OK,
			Data:       marshalGetAssertionFixture(d.t, d.info()),
		}, nil
	case protocol.AuthenticatorConfig:
		return d.configResponse(request[1:]), nil
	case protocol.AuthenticatorMakeCredential:
		return d.makeCredentialResponse(request[1:]), nil
	default:
		d.t.Fatalf("unexpected command %s", protocol.Command(request[0]))
		return ctaptransport.CBORResponse{}, nil
	}
}

func (d *enterpriseAttestationTestDevice) info() protocol.AuthenticatorGetInfoResponse {
	options := map[protocol.Option]bool{
		protocol.OptionAuthenticatorConfig: true,
		protocol.OptionClientPIN:           false,
		protocol.OptionPinUvAuthToken:      true,
	}
	if d.profile == SecurityProfileEnterprise {
		options[protocol.OptionEnterpriseAttestation] = d.enabled
	}
	return protocol.AuthenticatorGetInfoResponse{
		Versions:           []protocol.Version{protocol.FIDO_2_3},
		AAGUID:             uuid.UUID{},
		Options:            options,
		PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo},
		Algorithms: []credential.PublicKeyCredentialParameters{{
			Type:      credential.PublicKeyCredentialTypePublicKey,
			Algorithm: cose.AlgorithmES256,
		}},
		AttestationFormats: []attestation.AttestationStatementFormatIdentifier{
			attestation.AttestationStatementFormatIdentifierPacked,
		},
		AuthenticatorConfigCommands: []protocol.ConfigSubCommand{
			protocol.ConfigSubCommandEnableEnterpriseAttestation,
		},
	}
}

func (d *enterpriseAttestationTestDevice) response(value any) ctaptransport.CBORResponse {
	data := marshalGetAssertionFixture(d.t, value)
	d.responseData = append(d.responseData, data)
	return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_OK, Data: data}
}

func (d *enterpriseAttestationTestDevice) configResponse(body []byte) ctaptransport.CBORResponse {
	d.configCalls++
	var request protocol.AuthenticatorConfigRequest
	if err := getInfoDecMode.Unmarshal(body, &request); err != nil {
		d.t.Fatal(err)
	}
	if request.SubCommand != protocol.ConfigSubCommandEnableEnterpriseAttestation ||
		request.PinUvAuthProtocol != protocol.PinUvAuthProtocolTwo {
		d.t.Fatalf("config request = %#v", request)
	}
	token := d.consumeToken(protocol.PermissionAuthenticatorConfiguration)
	message := slices.Concat(bytes.Repeat([]byte{0xff}, 32), []byte{
		0x0d,
		byte(protocol.ConfigSubCommandEnableEnterpriseAttestation),
	})
	want := ctapcrypto.Authenticate(protocol.PinUvAuthProtocolTwo, token, message)
	clear(token)
	clear(message)
	if !bytes.Equal(request.PinUvAuthParam, want) {
		d.t.Fatalf("config authorization = %x, want %x", request.PinUvAuthParam, want)
	}
	d.enabled = true
	return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_OK}
}

func (d *enterpriseAttestationTestDevice) makeCredentialResponse(body []byte) ctaptransport.CBORResponse {
	var fields map[uint64]cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(body, &fields); err != nil {
		d.t.Fatal(err)
	}
	defer clearCTAP2RawFields(fields)
	rawMode, present := fields[10]
	if !present || !hasCBORMajorType(rawMode, 0) {
		return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_ERR_INVALID_CBOR}
	}
	var request protocol.AuthenticatorMakeCredentialRequest
	if err := getInfoDecMode.Unmarshal(body, &request); err != nil {
		d.t.Fatal(err)
	}
	d.records = append(d.records, enterpriseAttestationRecord{
		rpID: request.RP.ID,
		mode: request.EnterpriseAttestation,
	})
	token := d.consumeToken(protocol.PermissionMakeCredential)
	want := ctapcrypto.Authenticate(
		request.PinUvAuthProtocol,
		token,
		request.ClientDataHash,
	)
	clear(token)
	if request.PinUvAuthProtocol != protocol.PinUvAuthProtocolTwo ||
		!bytes.Equal(request.PinUvAuthParam, want) {
		d.t.Fatalf("MakeCredential authorization = %x, want %x", request.PinUvAuthParam, want)
	}
	if d.profile == SecurityProfileConsumer {
		return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP1_ERR_INVALID_PARAMETER}
	}
	if request.EnterpriseAttestation != 1 && request.EnterpriseAttestation != 2 {
		return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_ERR_INVALID_OPTION}
	}

	key := d.enterpriseKey
	der := d.enterpriseDER
	epAtt := true
	if request.RP.ID != enterpriseAttestationRPID {
		key = d.regularKey
		der = d.regularDER
		epAtt = false
		if d.reuseEPLeaf {
			key = d.enterpriseKey
			der = d.enterpriseDER
		}
	}
	if d.forceEPFalse {
		epAtt = false
	}
	chain := [][]byte{der}
	if !epAtt && !d.reuseEPLeaf {
		chain = append(chain, der)
	}
	authData := getAssertionFixtureMakeCredentialAuthData(d.t, bytes.Repeat([]byte{0x71}, 16))
	signedData := slices.Concat(authData, request.ClientDataHash)
	digest := sha256.Sum256(signedData)
	signature, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	clear(signedData)
	if err != nil {
		d.t.Fatal(err)
	}
	return d.response(protocol.AuthenticatorMakeCredentialResponse{
		Format:      attestation.AttestationStatementFormatIdentifierPacked,
		AuthDataRaw: authData,
		AttestationStatement: map[string]any{
			"alg": cose.AlgorithmES256,
			"sig": signature,
			"x5c": chain,
		},
		EnterpriseAttestation: epAtt,
	})
}

func (d *enterpriseAttestationTestDevice) consumeToken(
	permission protocol.Permission,
) []byte {
	token := d.activeTokens[permission]
	delete(d.activeTokens, permission)
	if len(token) == 0 {
		d.t.Fatalf("missing %s token", permission)
	}
	return token
}

func (d *enterpriseAttestationTestDevice) assertWiped(t testing.TB) {
	t.Helper()
	for index, value := range d.tokenAliases {
		if !allZeroResidentKey(value) {
			t.Fatalf("token alias %d was not wiped: %x", index, value)
		}
	}
	for index, value := range d.responseData {
		if !allZeroResidentKey(value) {
			t.Fatalf("response Data %d was not wiped: %x", index, value)
		}
	}
}

func enterpriseAttestationCertificate(
	t testing.TB,
	serial int64,
	name string,
) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Unix(0, 0),
		NotAfter:     time.Unix(1<<31, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return key, der
}

func TestEnterpriseAttestationDefinitionsMatchPinnedSource(t *testing.T) {
	tests := enterpriseAttestationTests(Config{})
	wantIDs := []conformance.TestID{
		TestIDEnterpriseAttestationP1,
		TestIDEnterpriseAttestationP2,
		TestIDEnterpriseAttestationP3,
		TestIDEnterpriseAttestationF1,
		TestIDEnterpriseAttestationF2,
		TestIDEnterpriseAttestationF3,
		TestIDEnterpriseAttestationF4,
		TestIDEnterpriseAttestationF5,
		TestIDEnterpriseAttestationF6,
	}
	wantMarkers := []string{"P-1", "P-2", "P-3", "F-1", "F-2", "F-3", "F-4", "F-5", "F-6"}
	if len(tests) != len(wantIDs) {
		t.Fatalf("tests = %d, want %d", len(tests), len(wantIDs))
	}
	for index, test := range tests {
		if test.ID != wantIDs[index] || test.Source.Path != enterpriseAttestationSourcePath ||
			test.Source.Case != wantMarkers[index] || !test.Destructive || test.Run == nil {
			t.Fatalf("test[%d] = %#v", index, test)
		}
	}
}

func TestEnterpriseAttestationCasesExecuteExactProfilesAndWire(t *testing.T) {
	for _, profile := range []SecurityProfile{SecurityProfileEnterprise, SecurityProfileConsumer} {
		for index, definition := range enterpriseAttestationTests(Config{}) {
			if profile == SecurityProfileEnterprise && index >= 3 && index <= 5 ||
				profile == SecurityProfileConsumer && (index < 3 || index >= 6) {
				continue
			}
			t.Run(string(profile)+"/"+definition.Source.Case, func(t *testing.T) {
				device := newEnterpriseAttestationTestDevice(t, profile)
				digest := sha256.Sum256(device.enterpriseDER)
				config := device.config()
				test := enterpriseAttestationTestsWithDigest(config, digest)[index]
				result := runEnterpriseAttestationTest(t, device, test)
				if result.Status != conformance.StatusPassed {
					t.Fatalf("result = %#v, want passed", result)
				}
				wantConfigCalls := 0
				if profile == SecurityProfileEnterprise {
					wantConfigCalls = 1
				}
				if device.configCalls != wantConfigCalls || device.resetCalls != 2 ||
					device.powerCycles != 4 {
					t.Fatalf(
						"config/reset/cycles = %d/%d/%d, want %d/2/4",
						device.configCalls,
						device.resetCalls,
						device.powerCycles,
						wantConfigCalls,
					)
				}
				if index != 0 && index != 3 && index != 6 && len(device.records) != 1 {
					t.Fatal("case did not issue MakeCredential")
				}
				wantTokens := 0
				if profile == SecurityProfileEnterprise {
					wantTokens = 1
					if index != 0 {
						wantTokens = 2
					}
				} else if index != 3 {
					wantTokens = 1
				}
				if len(device.tokenRequests) != wantTokens {
					t.Fatalf("token requests = %#v, want %d", device.tokenRequests, wantTokens)
				}
				for tokenIndex, request := range device.tokenRequests {
					if tokenIndex == 0 && profile == SecurityProfileEnterprise {
						if request.Permission != protocol.PermissionAuthenticatorConfiguration || request.RPID != "" {
							t.Fatalf("configuration token = %#v", request)
						}
						continue
					}
					wantRPID := enterpriseAttestationRPID
					if index == 8 {
						wantRPID = enterpriseAttestationWrongRPID
					}
					if request.Permission != protocol.PermissionMakeCredential || request.RPID != wantRPID {
						t.Fatalf("MakeCredential token = %#v, want RP %q", request, wantRPID)
					}
				}
				device.assertWiped(t)
			})
		}
	}
}

func TestEnterpriseAttestationProfilesStopBeforeMutation(t *testing.T) {
	device := newEnterpriseAttestationTestDevice(t, SecurityProfileEnterprise)
	config := device.config()
	test := enterpriseAttestationTests(config)[3]
	result := runEnterpriseAttestationTest(t, device, test)
	if result.Status != conformance.StatusSkipped || device.resetCalls != 0 || device.powerCycles != 0 {
		t.Fatalf("opposite profile = %s reset/cycles %d/%d", result.Status, device.resetCalls, device.powerCycles)
	}

	device = newEnterpriseAttestationTestDevice(t, SecurityProfileUnspecified)
	config = device.config()
	result = runEnterpriseAttestationTest(t, device, enterpriseAttestationTests(config)[0])
	if result.Status != conformance.StatusSkipped || device.resetCalls != 0 || device.powerCycles != 0 {
		t.Fatalf("unspecified profile = %s reset/cycles %d/%d", result.Status, device.resetCalls, device.powerCycles)
	}
}

func TestEnterpriseAttestationRejectsWrongIdentitySignals(t *testing.T) {
	device := newEnterpriseAttestationTestDevice(t, SecurityProfileEnterprise)
	digest := sha256.Sum256(device.enterpriseDER)
	device.forceEPFalse = true
	config := device.config()
	result := runEnterpriseAttestationTest(
		t,
		device,
		enterpriseAttestationTestsWithDigest(config, digest)[1],
	)
	if result.Status != conformance.StatusFailed {
		t.Fatalf("epAtt=false status = %s, want failed", result.Status)
	}
	device.assertWiped(t)

	device = newEnterpriseAttestationTestDevice(t, SecurityProfileEnterprise)
	digest = sha256.Sum256(device.enterpriseDER)
	device.reuseEPLeaf = true
	config = device.config()
	result = runEnterpriseAttestationTest(
		t,
		device,
		enterpriseAttestationTestsWithDigest(config, digest)[8],
	)
	if result.Status != conformance.StatusFailed {
		t.Fatalf("enterprise leaf for unrelated RP status = %s, want failed", result.Status)
	}
	device.assertWiped(t)
}

func runEnterpriseAttestationTest(
	t *testing.T,
	device *enterpriseAttestationTestDevice,
	test conformance.Test,
) conformance.SuiteResult {
	t.Helper()
	runner, err := conformance.NewRunner(device)
	if err != nil {
		t.Fatal(err)
	}
	result, err := runner.Run(t.Context(), conformance.Suite{
		ID:    "enterprise-attestation-test",
		Name:  "Enterprise attestation test",
		Tests: []conformance.Test{test},
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}
