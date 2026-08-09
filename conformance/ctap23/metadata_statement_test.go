package ctap23

import (
	"slices"
	"strings"
	"testing"
)

func TestMetadataStatementPreservesPresenceAndUnknownFields(t *testing.T) {
	statement, err := parseMetadataStatement(`{"optionalFalse":false,"optionalZero":0,"optionalNull":null,"futureField":"value"}`)
	if err != nil {
		t.Fatal(err)
	}

	var optionalFalse bool
	present, err := statement.field("optionalFalse", &optionalFalse)
	if err != nil {
		t.Fatal(err)
	}
	if !present || optionalFalse {
		t.Fatalf("optionalFalse = (%t, %t), want (true, false)", present, optionalFalse)
	}

	var optionalZero uint64
	present, err = statement.field("optionalZero", &optionalZero)
	if err != nil {
		t.Fatal(err)
	}
	if !present || optionalZero != 0 {
		t.Fatalf("optionalZero = (%t, %d), want (true, 0)", present, optionalZero)
	}
	if !statement.has("optionalNull") || statement.has("absent") {
		t.Fatalf("statement presence = %#v", statement.fields)
	}

	names := statement.fieldNames()
	slices.Sort(names)
	if !slices.Equal(names, []string{"futureField", "optionalFalse", "optionalNull", "optionalZero"}) {
		t.Fatalf("field names = %v", names)
	}
}

func TestMetadataStatementRejectsMissingMalformedAndTrailingInput(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "missing", want: "metadata statement is required"},
		{name: "null", input: "null", want: "top-level value must be an object"},
		{name: "array", input: "[]", want: "top-level value must be an object"},
		{name: "trailing", input: "{} {}", want: "trailing JSON value"},
		{name: "duplicate", input: `{"name":1,"\u006eame":2}`, want: "duplicate object member"},
		{name: "invalid surrogate", input: `{"name":"\uD800"}`, want: "high surrogate"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := parseMetadataStatement(test.input)
			if err == nil || !strings.HasPrefix(err.Error(), "ctap23: ") || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("parseMetadataStatement error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestMetadataStatementReportsFieldTypeErrors(t *testing.T) {
	statement, err := parseMetadataStatement(`{"value":"not-a-number"}`)
	if err != nil {
		t.Fatal(err)
	}

	var value uint64
	present, err := statement.field("value", &value)
	if !present || err == nil || !strings.Contains(err.Error(), "ctap23: metadata field value") {
		t.Fatalf("field result = (%t, %v)", present, err)
	}
}
