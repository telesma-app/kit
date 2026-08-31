package workflow

import (
	"context"
	"encoding/hex"
	"slices"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/extension"
	"github.com/telesma-app/ctap/protocol"
	ctapwebauthn "github.com/telesma-app/ctap/webauthn"
	"github.com/telesma-app/kit/internal/authenticator"
	"github.com/telesma-app/kit/internal/errornorm"
	rtruntime "github.com/telesma-app/kit/internal/runtime"
	rtwebauthn "github.com/telesma-app/kit/internal/webauthn"
	"github.com/telesma-app/kit/model/failure"
	"github.com/telesma-app/kit/model/report"
	appwebauthn "github.com/telesma-app/kit/model/webauthn"
)

func (r Runner) MakeCredential(
	ctx context.Context,
	device authenticator.WebAuthnManager,
	req appwebauthn.MakeCredentialOperation,
) (appwebauthn.MakeCredentialOutput, error) {
	input, err := rtwebauthn.NormalizeMakeCredentialInput(req.MakeCredentialInput)
	if err != nil {
		return appwebauthn.MakeCredentialOutput{}, err
	}

	info, err := r.getAuthenticatorInfo(ctx, device)
	if err != nil {
		return appwebauthn.MakeCredentialOutput{}, err
	}
	preview := rtwebauthn.BuildMakeCredentialPreview(r.env.Selected, info, input)
	if req.DryRun {
		return appwebauthn.MakeCredentialOutput{Preview: preview}, nil
	}

	var response protocol.AuthenticatorMakeCredentialResponse
	err = r.env.Tokens.Use(ctx, rtruntime.TokenUse{
		Permission:      protocol.PermissionMakeCredential,
		RPID:            input.RP.ID,
		TryWithoutToken: makeCredentialShouldTryWithoutToken(info, input),
	}, func(token []byte) error {
		r.env.Effects.Record(rtruntime.StateEffectCredentialInventoryChanged)

		current, err := device.MakeCredential(
			ctx,
			token,
			input.ClientDataJSON,
			input.RP,
			input.User,
			input.PubKeyCredParams,
			input.ExcludeList,
			input.Extensions,
			ctapAuthenticatorOptions(input.Options, token != nil),
			input.EnterpriseAttestation,
			input.AttestationFormatsPreference,
		)
		if err != nil {
			return err
		}

		response = current

		return nil
	})
	if err != nil {
		return appwebauthn.MakeCredentialOutput{}, errornorm.Annotate(err, errornorm.WithCommand(
			failure.PhaseAuthenticatorCommand,
			protocol.AuthenticatorMakeCredential,
		))
	}
	result, err := makeCredentialResult(r.env.Selected.Attachment.ID, input.RP.ID, input.Extensions, response)
	if err != nil {
		return appwebauthn.MakeCredentialOutput{}, err
	}
	r.afterUserPresence(result.UserPresent)

	return appwebauthn.MakeCredentialOutput{
		Preview: preview,
		Result:  &result,
	}, nil
}

func makeCredentialShouldTryWithoutToken(
	info protocol.AuthenticatorGetInfoResponse,
	input appwebauthn.MakeCredentialInput,
) bool {
	extensions := input.Extensions
	if extensions == nil || extensions.PRFInputs == nil || extensions.PRF.Eval.First == nil {
		return true
	}
	if !slices.Contains(info.Extensions, extension.ExtensionIdentifierHMACSecret) ||
		!slices.Contains(info.Extensions, extension.ExtensionIdentifierHMACSecretMC) {
		return true
	}

	return (!info.Options[protocol.OptionUserVerification] ||
		!info.Options[protocol.OptionPinUvAuthToken]) &&
		(!info.Options[protocol.OptionClientPIN] ||
			info.Options[protocol.OptionNoMcGaPermissionsWithClientPin])
}

func (r Runner) GetAssertion(
	ctx context.Context,
	device authenticator.WebAuthnManager,
	req appwebauthn.GetAssertionOperation,
) (appwebauthn.GetAssertionOutput, error) {
	input, err := rtwebauthn.NormalizeGetAssertionInput(req.GetAssertionInput)
	if err != nil {
		return appwebauthn.GetAssertionOutput{}, err
	}

	info, err := r.getAuthenticatorInfo(ctx, device)
	if err != nil {
		return appwebauthn.GetAssertionOutput{}, err
	}
	preview := rtwebauthn.BuildGetAssertionPreview(r.env.Selected, info, input)
	if req.DryRun {
		return appwebauthn.GetAssertionOutput{Preview: preview}, nil
	}

	var responses []protocol.AuthenticatorGetAssertionResponse

	if err := r.env.Tokens.Use(ctx, rtruntime.TokenUse{
		Permission:      protocol.PermissionGetAssertion,
		RPID:            input.RPID,
		TryWithoutToken: true,
	}, func(token []byte) error {
		if input.Extensions != nil &&
			input.Extensions.LargeBlobInputs != nil &&
			input.Extensions.LargeBlob.Write != nil {
			r.env.Effects.Record(rtruntime.StateEffectLargeBlobArrayChanged)
		}

		var current []protocol.AuthenticatorGetAssertionResponse
		for response, err := range device.GetAssertion(
			ctx,
			token,
			input.RPID,
			input.ClientDataJSON,
			input.AllowList,
			input.Extensions,
			ctapAuthenticatorOptions(input.Options, token != nil),
		) {
			if err != nil {
				return errornorm.Annotate(err, errornorm.WithCommand(
					failure.PhaseAuthenticatorCommand,
					protocol.AuthenticatorGetAssertion,
				))
			}

			current = append(current, response)
		}

		responses = current

		return nil
	}); err != nil {
		return appwebauthn.GetAssertionOutput{}, err
	}

	result := appwebauthn.GetAssertionResult{
		AttachmentID: r.env.Selected.Attachment.ID,
		RPID:         input.RPID,
		Assertions:   make([]appwebauthn.Assertion, 0, len(responses)),
	}
	for index, response := range responses {
		result.Assertions = append(result.Assertions, assertionResult(uint(index), response))
	}
	for _, assertion := range result.Assertions {
		if assertion.UserPresent {
			r.afterUserPresence(true)

			break
		}
	}

	return appwebauthn.GetAssertionOutput{
		Preview: preview,
		Result:  &result,
	}, nil
}

func (r Runner) afterUserPresence(present bool) {
	if present {
		r.env.Tokens.InvalidateUnlessPermission(protocol.PermissionLargeBlobWrite)
	}
}

func makeCredentialResult(
	attachmentID report.AttachmentID,
	rpID string,
	extensions *ctapwebauthn.CreateAuthenticationExtensionsClientInputs,
	response protocol.AuthenticatorMakeCredentialResponse,
) (appwebauthn.MakeCredentialResult, error) {
	if response.AuthData == nil || response.AuthData.AttestedCredentialData == nil {
		return appwebauthn.MakeCredentialResult{}, failure.New(failure.CodeAttestedCredentialDataMissing,
			failure.WithPhase(failure.PhaseDecode),
		)
	}

	publicKeyCOSE, err := cbor.Marshal(response.AuthData.AttestedCredentialData.CredentialPublicKey)
	if err != nil {
		return appwebauthn.MakeCredentialResult{}, errornorm.Annotate(
			err,
			errornorm.WithPhase(failure.PhaseDecode),
		)
	}

	attestationObjectCBOR, err := attestationObjectCBOR(response)
	if err != nil {
		return appwebauthn.MakeCredentialResult{}, errornorm.Annotate(
			err,
			errornorm.WithPhase(failure.PhaseDecode),
		)
	}

	return appwebauthn.MakeCredentialResult{
		AttachmentID:             attachmentID,
		RPID:                     rpID,
		Format:                   response.Format,
		CredentialIDHex:          hex.EncodeToString(response.AuthData.AttestedCredentialData.CredentialID),
		PublicKeyCOSEHex:         hex.EncodeToString(publicKeyCOSE),
		AuthenticatorDataHex:     hex.EncodeToString(response.AuthDataRaw),
		AttestationObjectCBORHex: hex.EncodeToString(attestationObjectCBOR),
		AAGUID:                   response.AuthData.AttestedCredentialData.AAGUID.String(),
		SignCount:                response.AuthData.SignCount,
		UserPresent:              response.AuthData.Flags.UserPresent(),
		UserVerified:             response.AuthData.Flags.UserVerified(),
		EnterpriseAttestation:    response.EnterpriseAttestation,
		ExtensionResults:         makeCredentialExtensionResults(extensions, response),
	}, nil
}

func attestationObjectCBOR(response protocol.AuthenticatorMakeCredentialResponse) ([]byte, error) {
	attestationStatement := response.AttestationStatement
	if attestationStatement == nil {
		attestationStatement = map[string]any{}
	}

	encMode, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		return nil, err
	}

	encoded, err := encMode.Marshal(map[string]any{
		"fmt":      response.Format,
		"authData": response.AuthDataRaw,
		"attStmt":  attestationStatement,
	})
	if err != nil {
		return nil, err
	}

	return encoded, nil
}

func assertionResult(
	index uint,
	response protocol.AuthenticatorGetAssertionResponse,
) appwebauthn.Assertion {
	assertion := appwebauthn.Assertion{
		Index:                index,
		Credential:           response.Credential,
		AuthenticatorDataHex: hex.EncodeToString(response.AuthDataRaw),
		SignatureHex:         hex.EncodeToString(response.Signature),
		NumberOfCredentials:  response.NumberOfCredentials,
		UserSelected:         response.UserSelected,
		ExtensionResults:     getAssertionExtensionResults(response),
	}

	if response.AuthData != nil {
		assertion.SignCount = response.AuthData.SignCount
		assertion.UserPresent = response.AuthData.Flags.UserPresent()
		assertion.UserVerified = response.AuthData.Flags.UserVerified()
	}

	if response.User != nil {
		assertion.User = response.User
	}

	return assertion
}

func ctapAuthenticatorOptions(options appwebauthn.AuthenticatorOptions, withToken bool) map[protocol.Option]bool {
	out := make(map[protocol.Option]bool)
	if options.ResidentKey != nil {
		out[protocol.OptionResidentKeys] = *options.ResidentKey
	}

	if options.UserPresence != nil {
		out[protocol.OptionUserPresence] = *options.UserPresence
	}

	if options.UserVerification != nil && !withToken {
		out[protocol.OptionUserVerification] = *options.UserVerification
	}

	if len(out) == 0 {
		return nil
	}

	return out
}
