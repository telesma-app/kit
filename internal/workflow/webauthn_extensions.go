package workflow

import (
	"encoding/hex"

	"github.com/telesma-app/ctap/extension"
	"github.com/telesma-app/ctap/protocol"
	ctapwebauthn "github.com/telesma-app/ctap/webauthn"
	appwebauthn "github.com/telesma-app/kit/model/webauthn"
)

func makeCredentialExtensionResults(
	input *ctapwebauthn.CreateAuthenticationExtensionsClientInputs,
	response protocol.AuthenticatorMakeCredentialResponse,
) *appwebauthn.MakeCredentialExtensionResults {
	output := response.ExtensionOutputs
	var authenticatorOutput *protocol.CreateExtensionOutputs
	if response.AuthData != nil {
		authenticatorOutput = response.AuthData.Extensions
	}

	result := new(appwebauthn.MakeCredentialExtensionResults)
	client := new(appwebauthn.MakeCredentialClientExtensionResults)
	authenticator := new(appwebauthn.MakeCredentialAuthenticatorExtensionOutputs)
	rawHMACMCRequested := input != nil && input.CreateHMACSecretMCInputs != nil
	hasClientResult := false
	hasAuthenticatorOutput := false
	if output != nil && output.CreateCredentialPropertiesOutputs != nil {
		hasClientResult = true
		client.CredentialProperties = &output.CredentialProperties
	}

	if authenticatorOutput != nil && authenticatorOutput.CredProtect != 0 {
		hasAuthenticatorOutput = true
		policy := extension.CredentialProtectionPolicy("")
		switch authenticatorOutput.CredProtect {
		case 0x01:
			policy = extension.CredentialProtectionPolicyUserVerificationOptional
		case 0x02:
			policy = extension.CredentialProtectionPolicyUserVerificationOptionalWithCredentialIDList
		case 0x03:
			policy = extension.CredentialProtectionPolicyUserVerificationRequired
		}
		authenticator.CredentialProtection = &appwebauthn.CredentialProtectionOutput{Policy: policy}
	}

	if output != nil && output.CreateCredentialBlobOutputs != nil {
		hasClientResult = true
		client.CredentialBlob = &appwebauthn.CredentialBlobCreateOutput{Accepted: output.CredBlob}
	}

	if output != nil && output.CreateHMACSecretOutputs != nil {
		hasClientResult = true
		client.HMACSecret = &appwebauthn.HMACSecretCreateOutput{Enabled: output.HMACCreateSecret}
	}

	if output != nil && output.LargeBlobOutputs != nil && output.LargeBlob.Supported != nil {
		hasClientResult = true
		client.LargeBlob = &appwebauthn.LargeBlobCreateOutput{Supported: *output.LargeBlob.Supported}
	}

	if output != nil && output.CreateHMACSecretMCOutputs != nil {
		hasClientResult = true
		client.HMACSecretMC = hmacSecretOutput(output.CreateHMACSecretMCOutputs.HMACGetSecret)
	} else if rawHMACMCRequested && output != nil && output.CreatePRFOutputs != nil {
		hasClientResult = true
		client.HMACSecretMC = &appwebauthn.HMACSecretOutput{
			Output1Hex: hex.EncodeToString(output.PRF.Results.First),
			Output2Hex: hex.EncodeToString(output.PRF.Results.Second),
		}
	}

	if authenticatorOutput != nil && authenticatorOutput.MinPinLength != 0 {
		hasAuthenticatorOutput = true
		authenticator.MinPINLength = &appwebauthn.MinPINLengthOutput{
			Value: authenticatorOutput.MinPinLength,
		}
	}

	if authenticatorOutput != nil && authenticatorOutput.CreatePinComplexityPolicyOutput != nil {
		hasAuthenticatorOutput = true
		authenticator.PINComplexityPolicy = &appwebauthn.PINComplexityPolicyOutput{
			Enabled: authenticatorOutput.CreatePinComplexityPolicyOutput.PinComplexityPolicy,
		}
	}

	if !rawHMACMCRequested && output != nil && output.CreatePRFOutputs != nil {
		hasClientResult = true
		client.PRF = &appwebauthn.MakeCredentialPRFOutput{
			Enabled: output.PRF.Enabled,
			Results: output.PRF.Results,
		}
	}

	if output != nil && output.PreviewSignOutputs != nil {
		hasClientResult = true
		client.PreviewSign = &appwebauthn.MakeCredentialPreviewSignOutput{}
		if output.PreviewSign.GeneratedKey != nil {
			client.PreviewSign.GeneratedKey = &appwebauthn.PreviewSignGeneratedKey{
				KeyHandleHex:             hex.EncodeToString(output.PreviewSign.GeneratedKey.KeyHandle),
				PublicKeyCOSEHex:         hex.EncodeToString(output.PreviewSign.GeneratedKey.PublicKey),
				Algorithm:                output.PreviewSign.GeneratedKey.Algorithm,
				AttestationObjectCBORHex: hex.EncodeToString(output.PreviewSign.GeneratedKey.AttestationObject),
			}
		}
	}

	if hasClientResult {
		result.Client = client
	}

	if hasAuthenticatorOutput {
		result.Authenticator = authenticator
	}

	if !hasClientResult && !hasAuthenticatorOutput {
		return nil
	}

	return result
}

func getAssertionExtensionResults(
	input *ctapwebauthn.GetAuthenticationExtensionsClientInputs,
	response protocol.AuthenticatorGetAssertionResponse,
) *appwebauthn.GetAssertionExtensionResults {
	output := response.ExtensionOutputs
	client := new(appwebauthn.GetAssertionClientExtensionResults)
	hasClientResult := false
	if output != nil && output.GetCredentialBlobOutputs != nil {
		hasClientResult = true
		client.CredentialBlob = &appwebauthn.CredentialBlobGetOutput{
			ValueHex: hex.EncodeToString(output.GetCredBlob),
		}
	}

	if output != nil && output.GetHMACSecretOutputs != nil {
		hasClientResult = true
		client.HMACSecret = hmacSecretOutput(output.GetHMACSecretOutputs.HMACGetSecret)
	}

	if output != nil && output.GetPRFOutputs != nil {
		hasClientResult = true
		client.PRF = &appwebauthn.GetAssertionPRFOutput{
			Results: output.PRF.Results,
		}
	}

	if output != nil && output.LargeBlobOutputs != nil {
		hasClientResult = true
		largeBlob := &appwebauthn.LargeBlobGetOutput{
			Written: output.LargeBlob.Written,
		}

		if output.LargeBlob.Blob != nil {
			largeBlob.BlobHex = new(hex.EncodeToString(output.LargeBlob.Blob))
		}
		client.LargeBlob = largeBlob
	}

	if output != nil && output.PreviewSignOutputs != nil {
		hasClientResult = true
		client.PreviewSign = &appwebauthn.GetAssertionPreviewSignOutput{
			SignatureHex: hex.EncodeToString(output.PreviewSign.Signature),
			Inspection:   inspectPreviewSignSignature(input, response),
		}
	}

	authenticator := new(appwebauthn.GetAssertionAuthenticatorExtensionOutputs)
	hasAuthenticatorResult := false
	if response.AuthData != nil && response.AuthData.Extensions != nil &&
		response.AuthData.Extensions.GetThirdPartyPaymentOutput != nil {
		hasAuthenticatorResult = true
		authenticator.ThirdPartyPayment = &response.AuthData.Extensions.GetThirdPartyPaymentOutput.ThirdPartyPayment
	}

	if !hasClientResult && !hasAuthenticatorResult {
		return nil
	}

	result := new(appwebauthn.GetAssertionExtensionResults)
	if hasClientResult {
		result.Client = client
	}

	if hasAuthenticatorResult {
		result.Authenticator = authenticator
	}

	return result
}

func hmacSecretOutput(output ctapwebauthn.HMACGetSecretOutput) *appwebauthn.HMACSecretOutput {
	return &appwebauthn.HMACSecretOutput{
		Output1Hex: hex.EncodeToString(output.Output1),
		Output2Hex: hex.EncodeToString(output.Output2),
	}
}
