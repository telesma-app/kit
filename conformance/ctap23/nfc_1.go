package ctap23

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/kit/conformance"
)

const (
	nfc1SourcePath = "tests/CTAP2/Transports/nfc-1.js"
	nfc1RPIDSuffix = "nfc-1.ctap23-conformance.example"

	nfc1CLAISO                              = 0x00
	nfc1CLACTAP                             = 0x80
	nfc1INSSelect                           = 0xa4
	nfc1INSNFCCTAPMsg                       = 0x10
	nfc1INSInvalid                          = 0x75
	nfc1P1SelectByName                      = 0x04
	nfc1ShortChunkSize                      = 240
	nfc1MixedChunkSize                      = 97
	nfc1SWINSUnsupported iso7816.StatusWord = 0x6d00
	nfc1SWWrongLength    iso7816.StatusWord = 0x6700

	TestIDNFC1P1 conformance.TestID = "fido.ctap2.3.nfc-1.p-1"
	TestIDNFC1P2 conformance.TestID = "fido.ctap2.3.nfc-1.p-2"
	TestIDNFC1P3 conformance.TestID = "fido.ctap2.3.nfc-1.p-3"
	TestIDNFC1P4 conformance.TestID = "fido.ctap2.3.nfc-1.p-4"
	TestIDNFC1F1 conformance.TestID = "fido.ctap2.3.nfc-1.f-1"
	TestIDNFC1F2 conformance.TestID = "fido.ctap2.3.nfc-1.f-2"
	TestIDNFC1F3 conformance.TestID = "fido.ctap2.3.nfc-1.f-3"
	TestIDNFC1F4 conformance.TestID = "fido.ctap2.3.nfc-1.f-4"
)

var nfc1FIDOAppletAID = [...]byte{0xa0, 0x00, 0x00, 0x06, 0x47, 0x2f, 0x00, 0x01}

type nfc1Case struct {
	id          conformance.TestID
	marker      string
	name        string
	destructive bool
	references  []conformance.RequirementRef
	run         func(context.Context, iso7816.Card) error
	makeCred    nfc1MakeCredentialEncoding
}

type nfc1MakeCredentialEncoding uint8

const (
	nfc1MakeCredentialNone nfc1MakeCredentialEncoding = iota
	nfc1MakeCredentialExtended
	nfc1MakeCredentialShort
	nfc1MakeCredentialMixedShort
)

func nfc1Tests(config Config) []conformance.Test {
	selectionReference := nfc1Reference("11.3.3", "nfc-applet-selection", conformance.RequirementMust)
	framingReference := nfc1Reference("11.3.5", "nfc-framing", conformance.RequirementMust)
	fragmentationReference := nfc1Reference("11.3.6", "nfc-fragmentation", conformance.RequirementMust)
	messageReference := nfc1Reference("11.3.7.1", "nfc-nfcctap-msg", conformance.RequirementMust)
	isoReference := nfc1Reference("11.3.1", "iso-7816-4-conformance", conformance.RequirementMust)

	definitions := []nfc1Case{
		{
			id:         TestIDNFC1P1,
			marker:     "P-1",
			name:       "Select the FIDO NFC applet",
			references: []conformance.RequirementRef{selectionReference},
			run: func(ctx context.Context, card iso7816.Card) error {
				return nfc1SelectApplet(ctx, card, nfc1ExpectedAppletVersion(config.Metadata.GetInfo))
			},
		},
		{
			id:          TestIDNFC1P2,
			marker:      "P-2",
			name:        "Send MakeCredential in an extended APDU",
			destructive: true,
			references:  []conformance.RequirementRef{framingReference, messageReference},
			makeCred:    nfc1MakeCredentialExtended,
		},
		{
			id:          TestIDNFC1P3,
			marker:      "P-3",
			name:        "Send MakeCredential in short APDUs",
			destructive: true,
			references:  []conformance.RequirementRef{framingReference, fragmentationReference, messageReference},
			makeCred:    nfc1MakeCredentialShort,
		},
		{
			id:          TestIDNFC1P4,
			marker:      "P-4",
			name:        "Send MakeCredential in mixed-size short APDUs",
			destructive: true,
			references:  []conformance.RequirementRef{framingReference, fragmentationReference, messageReference},
			makeCred:    nfc1MakeCredentialMixedShort,
		},
		{
			id:         TestIDNFC1F1,
			marker:     "F-1",
			name:       "Reject an unsupported INS in a short APDU",
			references: []conformance.RequirementRef{framingReference, isoReference},
			run: func(ctx context.Context, card iso7816.Card) error {
				return nfc1ExpectStatus(ctx, card, iso7816.Command{
					CLA: nfc1CLACTAP, INS: nfc1INSInvalid, Data: []byte{byte(protocol.AuthenticatorGetInfo)},
					Le: 256, Encoding: iso7816.EncodingShort,
				}, nfc1SWINSUnsupported)
			},
		},
		{
			id:         TestIDNFC1F2,
			marker:     "F-2",
			name:       "Reject an unsupported INS in an extended APDU",
			references: []conformance.RequirementRef{framingReference, isoReference},
			run: func(ctx context.Context, card iso7816.Card) error {
				return nfc1ExpectStatus(ctx, card, iso7816.Command{
					CLA: nfc1CLACTAP, INS: nfc1INSInvalid, Data: []byte{byte(protocol.AuthenticatorGetInfo)},
					Le: 65536, Encoding: iso7816.EncodingExtended,
				}, nfc1SWINSUnsupported)
			},
		},
		{
			id:         TestIDNFC1F3,
			marker:     "F-3",
			name:       "Reject an invalid short-APDU Lc",
			references: []conformance.RequirementRef{framingReference, isoReference},
			run: func(ctx context.Context, card iso7816.Card) error {
				return nfc1ExpectInvalidLengthStatus(ctx, card, iso7816.Command{
					CLA: nfc1CLACTAP, INS: nfc1INSNFCCTAPMsg, Data: []byte{byte(protocol.AuthenticatorGetInfo)},
					Le: 256, Encoding: iso7816.EncodingShort,
				}, 4)
			},
		},
		{
			id:         TestIDNFC1F4,
			marker:     "F-4",
			name:       "Reject an invalid extended-APDU Lc",
			references: []conformance.RequirementRef{framingReference, isoReference},
			run: func(ctx context.Context, card iso7816.Card) error {
				return nfc1ExpectInvalidLengthStatus(ctx, card, iso7816.Command{
					CLA: nfc1CLACTAP, INS: nfc1INSNFCCTAPMsg, Data: []byte{byte(protocol.AuthenticatorGetInfo)},
					Le: 65536, Encoding: iso7816.EncodingExtended,
				}, 6)
			},
		},
	}

	tests := make([]conformance.Test, 0, len(definitions))
	for _, definition := range definitions {
		definition := definition
		tests = append(tests, nfc1Test(config, selectionReference, definition))
	}

	return tests
}

func nfc1Test(
	config Config,
	selectionReference conformance.RequirementRef,
	definition nfc1Case,
) conformance.Test {
	references := slices.Concat([]conformance.RequirementRef{selectionReference}, definition.references)
	stepPrefix := "nfc-1." + strings.ToLower(definition.marker)

	return conformance.Test{
		ID:          definition.id,
		Name:        definition.name,
		Description: definition.name,
		Source:      conformance.SourceLocation{Path: nfc1SourcePath, Case: definition.marker},
		References:  references,
		Destructive: definition.destructive,
		Run: func(test *conformance.TestContext) {
			if !test.Step(conformance.Step{
				ID:         conformance.StepID(stepPrefix + ".applicability"),
				Name:       "Confirm raw NFC applicability",
				References: []conformance.RequirementRef{selectionReference},
				Run: func(context.Context) error {
					if config.Transport != AuthenticatorTransportNFC {
						return conformance.Skip("case requires the NFC transport")
					}
					if config.NFCCardProvider == nil {
						return conformance.Skip("raw NFC card access is unavailable")
					}

					return nil
				},
			}) {
				return
			}

			if definition.makeCred == nfc1MakeCredentialNone {
				test.Step(conformance.Step{
					ID:         conformance.StepID(stepPrefix + ".exchange"),
					Name:       definition.name,
					References: references,
					Run: func(ctx context.Context) error {
						return config.NFCCardProvider(ctx, func(cardCtx context.Context, card iso7816.Card) error {
							if definition.marker != "P-1" {
								if err := nfc1SelectApplet(cardCtx, card, nfc1ExpectedAppletVersion(config.Metadata.GetInfo)); err != nil {
									return err
								}
							}

							return definition.run(cardCtx, card)
						})
					},
				})

				return
			}

			var fixture makeCredentialFixture
			if !test.Step(conformance.Step{
				ID:         conformance.StepID(stepPrefix + ".prepare"),
				Name:       "Prepare an isolated authorized MakeCredential request",
				References: references,
				Run: func(ctx context.Context) error {
					var err error
					fixture, err = prepareMakeCredentialFixture(ctx, test, config, definition.marker+"."+nfc1RPIDSuffix)

					return err
				},
			}) {
				return
			}
			defer fixture.clear()
			defer clear(fixture.Request.PinUvAuthParam)

			test.Step(conformance.Step{
				ID:         conformance.StepID(stepPrefix + ".exchange"),
				Name:       definition.name,
				References: references,
				Run: func(ctx context.Context) error {
					return nfc1MakeCredential(ctx, config, fixture.Request, definition.makeCred)
				},
			})
		},
	}
}

func nfc1MakeCredential(
	ctx context.Context,
	config Config,
	request protocol.AuthenticatorMakeCredentialRequest,
	encoding nfc1MakeCredentialEncoding,
) error {
	body, err := ctap2EncMode.Marshal(request)
	if err != nil {
		clear(body)

		return fmt.Errorf("ctap23: encode NFC MakeCredential request: %w", err)
	}
	defer clear(body)
	commandData := slices.Concat([]byte{byte(protocol.AuthenticatorMakeCredential)}, body)
	defer clear(commandData)

	return config.NFCCardProvider(ctx, func(cardCtx context.Context, card iso7816.Card) error {
		if err := nfc1SelectApplet(cardCtx, card, nfc1ExpectedAppletVersion(config.Metadata.GetInfo)); err != nil {
			return err
		}

		switch encoding {
		case nfc1MakeCredentialExtended:
			response, err := iso7816.Exchange(cardCtx, card, iso7816.Command{
				CLA: nfc1CLACTAP, INS: nfc1INSNFCCTAPMsg, Data: commandData,
				Le: 65536, Encoding: iso7816.EncodingExtended,
			}, iso7816.WithMoreDataStatusBytes(0x61, 0x9f))
			if err != nil {
				return nfc1ExchangeError(err)
			}
			defer clear(response.Data)

			return nfc1RequireCTAPSuccess(response)
		case nfc1MakeCredentialShort, nfc1MakeCredentialMixedShort:
			chunkSize := nfc1ShortChunkSize
			if encoding == nfc1MakeCredentialMixedShort {
				chunkSize = nfc1MixedChunkSize
			}
			commands, err := iso7816.Chain(iso7816.Command{
				CLA: nfc1CLACTAP, INS: nfc1INSNFCCTAPMsg, Data: commandData,
				Le: 256, Encoding: iso7816.EncodingShort,
			}, chunkSize)
			if err != nil {
				return err
			}
			defer func() {
				for index := range commands {
					clear(commands[index].Data)
				}
			}()

			return nfc1ExchangeCommandChain(cardCtx, card, commands)
		default:
			panic("ctap23: missing NFC MakeCredential APDU encoding")
		}
	})
}

func nfc1ExchangeCommandChain(
	ctx context.Context,
	card iso7816.Card,
	commands []iso7816.Command,
) error {
	for _, command := range commands[:len(commands)-1] {
		response, err := iso7816.Transmit(ctx, card, command)
		if err != nil {
			return nfc1ExchangeError(err)
		}
		if len(response.Data) != 0 || response.Status != iso7816.StatusSuccess {
			clear(response.Data)

			return conformance.Failf(
				"intermediate NFC command returned %d data bytes and SW=%s, want no data and SW=9000",
				len(response.Data), response.Status,
			)
		}
		clear(response.Data)
	}

	response, err := iso7816.Exchange(
		ctx,
		card,
		commands[len(commands)-1],
		iso7816.WithMoreDataStatusBytes(0x61, 0x9f),
	)
	if err != nil {
		return nfc1ExchangeError(err)
	}
	defer clear(response.Data)

	return nfc1RequireCTAPSuccess(response)
}

func nfc1SelectApplet(ctx context.Context, card iso7816.Card, expected protocol.Version) error {
	response, err := iso7816.Exchange(ctx, card, iso7816.Command{
		CLA: nfc1CLAISO, INS: nfc1INSSelect, P1: nfc1P1SelectByName,
		Data: nfc1FIDOAppletAID[:], Le: 256, Encoding: iso7816.EncodingShort,
	}, iso7816.WithMoreDataStatusBytes(0x61, 0x9f))
	if err != nil {
		return nfc1ExchangeError(err)
	}
	defer clear(response.Data)
	if response.Status != iso7816.StatusSuccess {
		return conformance.Failf("FIDO applet selection returned SW=%s, want 9000", response.Status)
	}
	if !bytes.Equal(response.Data, []byte(expected)) {
		return conformance.Failf("FIDO applet selection returned %q, want %q", response.Data, expected)
	}

	return nil
}

func nfc1ExpectedAppletVersion(info protocol.AuthenticatorGetInfoResponse) protocol.Version {
	if info.Versions.Supports(protocol.U2F_V2) {
		return protocol.U2F_V2
	}

	return protocol.FIDO_2_0
}

func nfc1RequireCTAPSuccess(response iso7816.Response) error {
	if response.Status != iso7816.StatusSuccess {
		return conformance.Failf("NFCCTAP_MSG returned SW=%s, want 9000", response.Status)
	}
	if len(response.Data) == 0 {
		return conformance.Fail("NFCCTAP_MSG response omitted the CTAP status byte")
	}
	status := ctaptransport.StatusCode(response.Data[0])
	if status != ctaptransport.CTAP2_OK {
		return conformance.Failf("authenticatorMakeCredential returned %s", status)
	}

	return nil
}

func nfc1ExpectStatus(
	ctx context.Context,
	card iso7816.Card,
	command iso7816.Command,
	expected iso7816.StatusWord,
) error {
	response, err := iso7816.Transmit(ctx, card, command)
	if err != nil {
		return nfc1ExchangeError(err)
	}
	defer clear(response.Data)
	if response.Status != expected {
		return conformance.Failf("NFC command returned SW=%s, want %s", response.Status, expected)
	}

	return nil
}

func nfc1ExpectInvalidLengthStatus(
	ctx context.Context,
	card iso7816.Card,
	command iso7816.Command,
	lcIndex int,
) error {
	apdu, err := command.MarshalBinary()
	if err != nil {
		return err
	}
	defer clear(apdu)
	apdu[lcIndex] = 0xff

	raw, err := card.Transmit(ctx, apdu)
	if err != nil {
		clear(raw)

		return err
	}
	defer clear(raw)
	response, err := iso7816.ParseResponse(raw)
	if err != nil {
		return conformance.Failf("invalid NFC response APDU: %v", err)
	}
	defer clear(response.Data)
	if response.Status != nfc1SWWrongLength {
		return conformance.Failf("NFC command returned SW=%s, want %s", response.Status, nfc1SWWrongLength)
	}

	return nil
}

func nfc1ExchangeError(err error) error {
	if err == iso7816.ErrInvalidResponse {
		return conformance.Failf("invalid NFC response APDU: %v", err)
	}

	return err
}

func nfc1Reference(
	section string,
	clause string,
	level conformance.RequirementLevel,
) conformance.RequirementRef {
	return conformance.RequirementRef{
		ID: conformance.RequirementID(
			"ctap-2.3-ps-20260226:" + section + ":" + clause,
		),
		Specification: conformance.SpecificationCTAP23,
		Section:       section,
		Clause:        clause,
		URL:           "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#nfc",
		Level:         level,
	}
}
