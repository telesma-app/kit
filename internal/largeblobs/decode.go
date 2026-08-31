// Package largeblobs owns runtime processing of large-blob DTOs.
package largeblobs

import (
	"encoding/json"
	"fmt"
	"unicode/utf8"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/kit/model/failure"
	applargeblobs "github.com/telesma-app/kit/model/largeblobs"
)

func Decode(
	raw []byte,
	mode applargeblobs.DecodeMode,
) (applargeblobs.DecodeResult, error) {
	switch mode {
	case applargeblobs.DecodeModeUTF8:
		if !utf8.Valid(raw) {
			return applargeblobs.DecodeResult{}, failure.New(
				failure.CodeLargeBlobUTF8Invalid,
				failure.WithPhase(failure.PhaseDecode),
			)
		}

		return applargeblobs.DecodeResult{
			Mode: mode,
			Text: string(raw),
		}, nil
	case applargeblobs.DecodeModeJSON:
		var value any
		if err := json.Unmarshal(raw, &value); err != nil {
			return applargeblobs.DecodeResult{}, failure.Wrap(
				failure.CodeLargeBlobJSONInvalid,
				err,
				failure.WithPhase(failure.PhaseDecode),
			)
		}

		return applargeblobs.DecodeResult{
			Mode:  mode,
			Value: value,
		}, nil
	case applargeblobs.DecodeModeCBOR:
		var value any
		if err := cbor.Unmarshal(raw, &value); err != nil {
			return applargeblobs.DecodeResult{}, failure.Wrap(
				failure.CodeLargeBlobCBORInvalid,
				err,
				failure.WithPhase(failure.PhaseDecode),
			)
		}

		return applargeblobs.DecodeResult{
			Mode:  mode,
			Value: jsonFriendlyDecodedValue(value),
		}, nil
	default:
		return applargeblobs.DecodeResult{}, failure.New(
			failure.CodeLargeBlobDecodeModeUnsupported,
			failure.WithPhase(failure.PhaseDecode),
		)
	}
}

func jsonFriendlyDecodedValue(value any) any {
	switch typed := value.(type) {
	case map[any]any:
		mapped := make(map[string]any, len(typed))
		for key, value := range typed {
			mapped[fmt.Sprint(key)] = jsonFriendlyDecodedValue(value)
		}

		return mapped
	case []any:
		mapped := make([]any, len(typed))
		for i, value := range typed {
			mapped[i] = jsonFriendlyDecodedValue(value)
		}

		return mapped
	default:
		return typed
	}
}
