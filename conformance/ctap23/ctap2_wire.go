package ctap23

import (
	"bytes"
	"context"
	"fmt"
	"slices"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
)

var ctap2EncMode = func() cbor.EncMode {
	mode, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		panic(err)
	}

	return mode
}()

func ctap2WireFields(operation string, request any) map[uint64]any {
	encoded, err := ctap2EncMode.Marshal(request)
	if err != nil {
		clear(encoded)

		panic(fmt.Sprintf("ctap23: encode trusted %s fixture: %v", operation, err))
	}
	defer clear(encoded)

	var fields map[uint64]any
	if err := getInfoDecMode.Unmarshal(encoded, &fields); err != nil {
		clearCTAP2WireValue(fields)

		panic(fmt.Sprintf("ctap23: decode trusted %s fixture: %v", operation, err))
	}
	for key, value := range fields {
		normalized := normalizeCTAP2WireValue(value)
		clearCTAP2WireValue(value)
		fields[key] = normalized
	}

	return fields
}

func exchangeCTAP2(
	ctx context.Context,
	device ctaptransport.CBOR,
	command protocol.Command,
	request any,
) (ctaptransport.CBORResponse, error) {
	body, err := ctap2EncMode.Marshal(request)
	if err != nil {
		clear(body)

		return ctaptransport.CBORResponse{}, fmt.Errorf(
			"ctap23: encode %s request: %w",
			command,
			err,
		)
	}
	defer clear(body)

	commandData := slices.Concat([]byte{byte(command)}, body)
	defer clear(commandData)

	response, err := device.CBOR(ctx, commandData)
	if err != nil {
		clearCTAP2ResponseData(response)

		return ctaptransport.CBORResponse{}, err
	}

	validated, err := ctaptransport.ValidateCBORResponse(command, response)
	if err != nil {
		clearCTAP2ResponseData(response)

		return ctaptransport.CBORResponse{}, err
	}

	return validated, nil
}

func clearCTAP2ResponseData(response ctaptransport.CBORResponse) {
	clear(response.Data)
}

func validateCanonicalCTAP2Response(operation string, data []byte) error {
	var value any
	defer func() {
		clearCTAP2WireValue(value)
	}()
	if err := getInfoDecMode.Unmarshal(data, &value); err != nil {
		return conformance.Failf("invalid %s response CBOR: %v", operation, err)
	}

	canonical, err := ctap2EncMode.Marshal(value)
	if err != nil {
		clear(canonical)

		return conformance.Failf("invalid %s response value: %v", operation, err)
	}
	defer clear(canonical)
	if !bytes.Equal(data, canonical) {
		return conformance.Failf("%s response is not CTAP2 canonical CBOR", operation)
	}

	return nil
}

type requiredCBORField struct {
	key       uint64
	name      string
	majorType byte
	typeName  string
}

func validateRequiredCBORFields(
	operation string,
	data []byte,
	required []requiredCBORField,
) error {
	var fields map[uint64]cbor.RawMessage
	defer func() {
		clearCTAP2RawFields(fields)
	}()
	if err := getInfoDecMode.Unmarshal(data, &fields); err != nil {
		return conformance.Failf("invalid %s response CBOR: %v", operation, err)
	}
	for _, field := range required {
		raw, present := fields[field.key]
		if !present {
			return conformance.Failf(
				"%s response is missing required %s field",
				operation,
				field.name,
			)
		}
		if !hasCBORMajorType(raw, field.majorType) {
			return conformance.Failf(
				"%s response required %s field is not a CBOR %s",
				operation,
				field.name,
				field.typeName,
			)
		}
	}

	return nil
}

func hasCBORMajorType(raw cbor.RawMessage, majorType byte) bool {
	return len(raw) != 0 && raw[0]>>5 == majorType
}

func normalizeCTAP2WireValue(value any) any {
	switch value := value.(type) {
	case []byte:
		return slices.Clone(value)
	case []any:
		result := make([]any, len(value))
		for index, item := range value {
			result[index] = normalizeCTAP2WireValue(item)
		}

		return result
	case map[any]any:
		if result, ok := normalizeCTAP2StringMap(value); ok {
			return result
		}
		if result, ok := normalizeCTAP2UintMap(value); ok {
			return result
		}

		result := make(map[any]any, len(value))
		for key, item := range value {
			result[key] = normalizeCTAP2WireValue(item)
		}

		return result
	default:
		return value
	}
}

func clearCTAP2WireValue(value any) {
	switch value := value.(type) {
	case []byte:
		clear(value)
	case cbor.RawMessage:
		clear(value)
	case []any:
		for _, item := range value {
			clearCTAP2WireValue(item)
		}
	case map[string]any:
		for key, item := range value {
			clearCTAP2WireValue(item)
			delete(value, key)
		}
	case map[uint64]any:
		for key, item := range value {
			clearCTAP2WireValue(item)
			delete(value, key)
		}
	case map[any]any:
		for key, item := range value {
			clearCTAP2WireValue(item)
			delete(value, key)
		}
	}
}

func clearCTAP2RawFields(fields map[uint64]cbor.RawMessage) {
	for key, raw := range fields {
		clear(raw)
		delete(fields, key)
	}
}

func normalizeCTAP2StringMap(value map[any]any) (map[string]any, bool) {
	result := make(map[string]any, len(value))
	for key, item := range value {
		name, ok := key.(string)
		if !ok {
			return nil, false
		}
		result[name] = normalizeCTAP2WireValue(item)
	}

	return result, true
}

func normalizeCTAP2UintMap(value map[any]any) (map[uint64]any, bool) {
	result := make(map[uint64]any, len(value))
	for key, item := range value {
		number, ok := key.(uint64)
		if !ok {
			return nil, false
		}
		result[number] = normalizeCTAP2WireValue(item)
	}

	return result, true
}
