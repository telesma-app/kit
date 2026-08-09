package ctap23

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
)

const getInfoSourcePath = "tests/CTAP2/Protocol/Authr-Generic-1.js"

var getInfoDecMode = func() cbor.DecMode {
	mode, err := cbor.DecOptions{
		DupMapKey:   cbor.DupMapKeyEnforcedAPF,
		IndefLength: cbor.IndefLengthForbidden,
		TagsMd:      cbor.TagsForbidden,
		UTF8:        cbor.UTF8RejectInvalid,
	}.DecMode()
	if err != nil {
		panic(err)
	}

	return mode
}()

var supportedOptions = map[protocol.Option]bool{
	protocol.OptionPlatformDevice:                         true,
	protocol.OptionResidentKeys:                           true,
	protocol.OptionClientPIN:                              true,
	protocol.OptionUserPresence:                           true,
	protocol.OptionUserVerification:                       true,
	protocol.OptionUvToken:                                true,
	protocol.OptionPinUvAuthToken:                         true,
	protocol.OptionNoMcGaPermissionsWithClientPin:         true,
	protocol.OptionLargeBlobs:                             true,
	protocol.OptionEnterpriseAttestation:                  true,
	protocol.OptionBioEnroll:                              true,
	protocol.OptionUserVerificationMgmtPreview:            true,
	protocol.OptionUvBioEnroll:                            true,
	protocol.OptionAuthenticatorConfig:                    true,
	protocol.OptionUvAcfg:                                 true,
	protocol.OptionCredentialManagement:                   true,
	protocol.OptionPersistentCredentialManagementReadOnly: true,
	protocol.OptionCredentialManagementPreview:            true,
	protocol.OptionSetMinPINLength:                        true,
	protocol.OptionMakeCredentialUvNotRequired:            true,
	protocol.OptionAlwaysUv:                               true,
}

var certificationMaximums = map[string]uint64{
	"FIPS-CMVP-2":     4,
	"FIPS-CMVP-3":     4,
	"FIPS-CMVP-2-PHY": 4,
	"FIPS-CMVP-3-PHY": 4,
	"CC-EAL":          7,
	"FIDO":            6,
	"CCN-CPSTIC":      1,
}

func getInfoTest(metadata Metadata) conformance.Test {
	reference := getInfoReference()

	return conformance.Test{
		ID:          TestIDAuthrGeneric1P1,
		Name:        "Authenticator GetInfo response",
		Description: "Validates the CTAP 2.3 GetInfo wire response, declared capabilities, and metadata agreement",
		Source: conformance.SourceLocation{
			Path: getInfoSourcePath,
			Case: "P-1",
		},
		References: []conformance.RequirementRef{reference},
		Run: func(test *conformance.TestContext) {
			var responseData []byte
			if !test.Step(conformance.Step{
				ID:         "get-info.request",
				Name:       "Send authenticatorGetInfo",
				References: []conformance.RequirementRef{reference},
				Run: func(ctx context.Context) error {
					response, err := test.CBOR().CBOR(ctx, []byte{byte(protocol.AuthenticatorGetInfo)})
					if err != nil {
						var ctapErr *ctaptransport.CTAPError
						if errors.As(err, &ctapErr) {
							return conformance.Failf("authenticatorGetInfo returned %s", ctapErr.StatusCode)
						}

						return err
					}
					if response.StatusCode != ctaptransport.CTAP2_OK {
						return conformance.Failf("authenticatorGetInfo returned %s", response.StatusCode)
					}
					responseData = response.Data

					return nil
				},
			}) {
				return
			}

			var (
				fields map[uint64]cbor.RawMessage
				info   protocol.AuthenticatorGetInfoResponse
			)
			if !test.Step(conformance.Step{
				ID:         "get-info.wire",
				Name:       "Decode the CTAP 2.3 CBOR map",
				References: []conformance.RequirementRef{reference},
				Run: func(context.Context) error {
					var err error
					fields, info, err = decodeGetInfoResponse(responseData)
					if err != nil {
						return conformance.Failf("invalid authenticatorGetInfo CBOR: %v", err)
					}

					return nil
				},
			}) {
				return
			}

			if !test.Step(conformance.Step{
				ID:         "get-info.required-fields",
				Name:       "Check required CTAP 2.3 fields",
				References: []conformance.RequirementRef{reference},
				Run: func(context.Context) error {
					return validateRequiredGetInfoFields(fields, info)
				},
			}) {
				return
			}

			if !test.Step(conformance.Step{
				ID:         "get-info.declared-fields",
				Name:       "Check declared optional fields",
				References: []conformance.RequirementRef{reference},
				Run: func(context.Context) error {
					return validateDeclaredGetInfoFields(fields, info)
				},
			}) {
				return
			}

			if !test.Step(conformance.Step{
				ID:         "get-info.requirements",
				Name:       "Assess CTAP 2.3 capability relationships",
				References: []conformance.RequirementRef{reference},
				Run: func(context.Context) error {
					return validateGetInfoAssessment(info)
				},
			}) {
				return
			}

			test.Step(conformance.Step{
				ID:         "get-info.metadata",
				Name:       "Compare GetInfo with authenticator metadata",
				References: []conformance.RequirementRef{reference},
				Run: func(context.Context) error {
					return validateGetInfoMetadata(fields, info, metadata)
				},
			})
		},
	}
}

func getInfoReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "ctap-2.3-ps-20260226:6.4:authenticator-get-info",
		Specification: conformance.SpecificationCTAP23,
		Section:       "6.4",
		Clause:        "authenticator-get-info",
		URL:           "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorGetInfo",
		Level:         conformance.RequirementConstraint,
	}
}

func decodeGetInfoResponse(data []byte) (map[uint64]cbor.RawMessage, protocol.AuthenticatorGetInfoResponse, error) {
	fields := make(map[uint64]cbor.RawMessage)
	if err := getInfoDecMode.Unmarshal(data, &fields); err != nil {
		return nil, protocol.AuthenticatorGetInfoResponse{}, err
	}
	for key := range fields {
		if key < 1 || key > 31 {
			return nil, protocol.AuthenticatorGetInfoResponse{}, fmt.Errorf("unsupported field 0x%x", key)
		}
	}

	var info protocol.AuthenticatorGetInfoResponse
	if err := getInfoDecMode.Unmarshal(data, &info); err != nil {
		return nil, protocol.AuthenticatorGetInfoResponse{}, err
	}

	return fields, info, nil
}

func rawGetInfoOption(
	fields map[uint64]cbor.RawMessage,
	option protocol.Option,
) (bool, bool, error) {
	rawOptions, present := fields[4]
	if !present {
		return false, false, nil
	}

	var options map[string]cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(rawOptions, &options); err != nil {
		return false, false, conformance.Failf("invalid GetInfo options map: %v", err)
	}
	if options == nil {
		return false, false, conformance.Fail("invalid GetInfo options: want a map, got null")
	}
	raw, present := options[string(option)]
	if !present {
		return false, false, nil
	}

	var decoded any
	if err := getInfoDecMode.Unmarshal(raw, &decoded); err != nil {
		return false, false, conformance.Failf("invalid GetInfo option %q: %v", option, err)
	}
	value, ok := decoded.(bool)
	if !ok {
		return false, false, conformance.Failf(
			"invalid GetInfo option %q type %T, want boolean",
			option,
			decoded,
		)
	}

	return value, true, nil
}

func validateRequiredGetInfoFields(fields map[uint64]cbor.RawMessage, info protocol.AuthenticatorGetInfoResponse) error {
	if _, present := fields[1]; !present {
		return conformance.Fail("versions field is missing")
	}
	if !slices.Contains(info.Versions, protocol.FIDO_2_3) {
		return conformance.Fail("versions does not contain FIDO_2_3")
	}
	if _, present := fields[2]; !present {
		return conformance.Fail("extensions field is missing")
	}

	rawAAGUID, present := fields[3]
	if !present {
		return conformance.Fail("aaguid field is missing")
	}
	var aaguid []byte
	if err := getInfoDecMode.Unmarshal(rawAAGUID, &aaguid); err != nil {
		return conformance.Failf("aaguid is not a byte string: %v", err)
	}
	if len(aaguid) != 16 {
		return conformance.Failf("aaguid length is %d, want 16", len(aaguid))
	}

	return nil
}

func validateDeclaredGetInfoFields(fields map[uint64]cbor.RawMessage, info protocol.AuthenticatorGetInfoResponse) error {
	for option := range info.Options {
		if !supportedOptions[option] {
			return conformance.Failf("options contains unsupported identifier %q", option)
		}
	}
	if info.Options[protocol.OptionUvToken] {
		if _, present := info.Options[protocol.OptionPinUvAuthToken]; !present {
			return conformance.Fail("uvToken requires the pinUvAuthToken option")
		}
	}
	if residentKeys, present := info.Options[protocol.OptionResidentKeys]; present && !residentKeys && !info.Options[protocol.OptionCredentialManagement] {
		return conformance.Fail("rk=false requires credential management support")
	}

	if rawAlgorithms, present := fields[10]; present {
		if err := validateAlgorithms(rawAlgorithms); err != nil {
			return err
		}
	}
	for certification, level := range info.Certifications {
		maximum, supported := certificationMaximums[certification]
		if !supported {
			return conformance.Failf("certifications contains unsupported identifier %q", certification)
		}
		if level == 0 || level > maximum {
			return conformance.Failf("certification %q level is outside 1..%d", certification, maximum)
		}
	}

	if present(fields, 5) && info.MaxMsgSize == 0 {
		return conformance.Fail("maxMsgSize must be greater than zero")
	}
	if present(fields, 7) && info.MaxCredentialCountInList == 0 {
		return conformance.Fail("maxCredentialCountInList must be greater than zero")
	}
	if present(fields, 8) && info.MaxCredentialIdLength == 0 {
		return conformance.Fail("maxCredentialIdLength must be greater than zero")
	}
	if present(fields, 11) && info.MaxSerializedLargeBlobArray < 1024 {
		return conformance.Fail("maxSerializedLargeBlobArray must be at least 1024")
	}
	if present(fields, 12) && info.ForcePINChange && !present(fields, 6) {
		return conformance.Fail("forcePINChange requires pinUvAuthProtocols")
	}
	if present(fields, 13) && info.MinPINLength < 4 {
		return conformance.Fail("minPINLength must be at least 4")
	}
	if present(fields, 14) && info.FirmwareVersion == nil {
		return conformance.Fail("firmwareVersion must not be null")
	}
	if present(fields, 15) && info.MaxCredBlobLength < 32 {
		return conformance.Fail("maxCredBlobLength must be at least 32")
	}
	if present(fields, 17) && info.PreferredPlatformUvAttempts == 0 {
		return conformance.Fail("preferredPlatformUvAttempts must be greater than zero")
	}
	if present(fields, 18) && (info.UvModality == nil || *info.UvModality == 0) {
		return conformance.Fail("uvModality must be greater than zero")
	}
	if present(fields, 25) && len(info.EncIdentifier) != 32 {
		return conformance.Failf("encIdentifier length is %d, want 32", len(info.EncIdentifier))
	}
	if present(fields, 28) && len(info.PinComplexityPolicyURL) == 0 {
		return conformance.Fail("pinComplexityPolicyURL must not be empty")
	}
	if present(fields, 29) && (info.MaxPINLength < 8 || info.MaxPINLength > 63) {
		return conformance.Failf("maxPINLength is %d, want 8..63", info.MaxPINLength)
	}
	if present(fields, 30) && len(info.EncCredStoreState) != 32 {
		return conformance.Failf("encCredStoreState length is %d, want 32", len(info.EncCredStoreState))
	}

	return nil
}

func validateGetInfoAssessment(info protocol.AuthenticatorGetInfoResponse) error {
	assessment, err := conformance.AssessGetInfoAgainst(info, conformance.Target{
		Specification: conformance.SpecificationCTAP23,
		Profile:       conformance.ProfileFIDO23,
	})
	if err != nil {
		return err
	}
	if len(assessment.Findings) == 0 {
		return nil
	}

	rules := make([]string, len(assessment.Findings))
	for index, finding := range assessment.Findings {
		rules[index] = string(finding.RuleID)
	}

	return conformance.Failf("GetInfo violates rules: %s", strings.Join(rules, ", "))
}

func validateGetInfoMetadata(
	fields map[uint64]cbor.RawMessage,
	info protocol.AuthenticatorGetInfoResponse,
	metadata Metadata,
) error {
	actualFields := make([]uint64, 0, len(fields))
	for key := range fields {
		actualFields = append(actualFields, key)
	}
	slices.Sort(actualFields)
	expectedFields := slices.Clone(metadata.GetInfoFields)
	slices.Sort(expectedFields)
	if !slices.Equal(actualFields, expectedFields) {
		return conformance.Failf("GetInfo field set is %v, metadata declares %v", actualFields, expectedFields)
	}

	normalizedInfo := info
	normalizedInfo.Options = maps.Clone(info.Options)
	delete(normalizedInfo.Options, protocol.OptionUvToken)
	if field := mismatchedGetInfoField(normalizedInfo, metadata.GetInfo); field != "" {
		return conformance.Failf("GetInfo field %s differs from authenticator metadata", field)
	}

	return validateMetadataUVMethods(info, metadata)
}

func validateMetadataUVMethods(info protocol.AuthenticatorGetInfoResponse, metadata Metadata) error {
	if info.UvModality != nil && *info.UvModality&^metadata.UserVerificationMethods != 0 {
		return conformance.Fail("uvModality contains a method absent from authenticator metadata")
	}

	return nil
}

func validateAlgorithms(raw cbor.RawMessage) error {
	var algorithms []map[string]cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(raw, &algorithms); err != nil {
		return conformance.Failf("algorithms is not an array of maps: %v", err)
	}
	for index, algorithm := range algorithms {
		if len(algorithm) != 2 {
			return conformance.Failf("algorithms[%d] must contain exactly type and alg", index)
		}
		rawType, hasType := algorithm["type"]
		rawAlgorithm, hasAlgorithm := algorithm["alg"]
		if !hasType || !hasAlgorithm {
			return conformance.Failf("algorithms[%d] must contain type and alg", index)
		}

		var typ string
		if err := getInfoDecMode.Unmarshal(rawType, &typ); err != nil {
			return conformance.Failf("algorithms[%d].type is not text: %v", index, err)
		}
		var identifier int64
		if err := getInfoDecMode.Unmarshal(rawAlgorithm, &identifier); err != nil {
			return conformance.Failf("algorithms[%d].alg is not an integer: %v", index, err)
		}
	}

	return nil
}

func mismatchedGetInfoField(actual, expected protocol.AuthenticatorGetInfoResponse) string {
	actualValue := reflect.ValueOf(actual)
	expectedValue := reflect.ValueOf(expected)
	typeInfo := actualValue.Type()
	for index := range actualValue.NumField() {
		if !reflect.DeepEqual(actualValue.Field(index).Interface(), expectedValue.Field(index).Interface()) {
			return typeInfo.Field(index).Name
		}
	}

	return ""
}

func present(fields map[uint64]cbor.RawMessage, key uint64) bool {
	_, ok := fields[key]

	return ok
}
