package ctap23

import (
	"reflect"
	"strings"
	"testing"

	"github.com/telesma-app/kit/conformance"
)

func TestHMACSecretExactMarkersMetadataAndReusableCredentialMatrix(t *testing.T) {
	tests := hmacSecretTests(Config{})
	wantIDs := []conformance.TestID{
		TestIDHMACSecretP1,
		TestIDHMACSecretP2,
		TestIDHMACSecretP3,
		TestIDHMACSecretF1,
		TestIDHMACSecretF2,
		TestIDHMACSecretF3,
	}
	wantMarkers := []string{"P-1", "P-2", "P-3", "F-1", "F-2", "F-3"}
	wantGetAssertionReference := []bool{false, true, true, false, true, true}
	if len(tests) != len(wantIDs) {
		t.Fatalf("tests = %d, want %d", len(tests), len(wantIDs))
	}
	for index, test := range tests {
		if test.ID != wantIDs[index] || test.Source.Path != hmacSecretSourcePath ||
			test.Source.Case != wantMarkers[index] || !test.Destructive || test.Run == nil {
			t.Fatalf("test %d metadata = %#v", index, test)
		}

		sections := make(map[string]bool)
		referenceIDs := make(map[conformance.RequirementID]bool)
		for _, reference := range test.References {
			sections[reference.Section] = true
			referenceIDs[reference.ID] = true
		}
		if !sections["9"] || !sections["12.7"] || !sections["6.5.6"] ||
			!sections["6.6"] || !sections["6.5.5.1"] ||
			!sections["6.1"] || !sections["8"] ||
			sections["6.2"] != wantGetAssertionReference[index] {
			t.Fatalf("test %s reference sections = %#v", test.ID, sections)
		}
		if !referenceIDs[authrMakeCredReq1CommandReference().ID] ||
			!referenceIDs[ctapMessageEncodingReference().ID] ||
			referenceIDs[authrGetAssertionReq1CommandReference().ID] != wantGetAssertionReference[index] {
			t.Fatalf("test %s command/encoding reference IDs = %#v", test.ID, referenceIDs)
		}
	}

	var kinds []bool
	if err := runHMACSecretCredentialKinds(func(discoverable bool) error {
		kinds = append(kinds, discoverable)

		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(kinds, []bool{false, true}) {
		t.Fatalf("credential-kind matrix = %#v", kinds)
	}
}

func TestHMACSecretCommandAndEncodingReferenceDefinitions(t *testing.T) {
	tests := []struct {
		name      string
		got       conformance.RequirementRef
		wantID    conformance.RequirementID
		section   string
		clause    string
		fragment  string
		wantLevel conformance.RequirementLevel
	}{
		{
			name:      "MakeCredential",
			got:       authrMakeCredReq1CommandReference(),
			wantID:    "ctap-2.3-ps-20260226:6.1:authenticator-make-credential-request",
			section:   "6.1",
			clause:    "authenticator-make-credential-request",
			fragment:  "#authenticatorMakeCredential",
			wantLevel: conformance.RequirementConstraint,
		},
		{
			name:      "GetAssertion",
			got:       authrGetAssertionReq1CommandReference(),
			wantID:    "ctap-2.3-ps-20260226:6.2:authenticator-get-assertion-request",
			section:   "6.2",
			clause:    "authenticator-get-assertion-request",
			fragment:  "#authenticatorGetAssertion",
			wantLevel: conformance.RequirementConstraint,
		},
		{
			name:      "message encoding",
			got:       ctapMessageEncodingReference(),
			wantID:    "ctap-2.3-ps-20260226:8:message-encoding",
			section:   "8",
			clause:    "message-encoding",
			fragment:  "#message-encoding",
			wantLevel: conformance.RequirementMust,
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			if testCase.got.ID != testCase.wantID ||
				testCase.got.Specification != conformance.SpecificationCTAP23 ||
				testCase.got.Section != testCase.section ||
				testCase.got.Clause != testCase.clause ||
				testCase.got.Level != testCase.wantLevel ||
				!strings.HasSuffix(testCase.got.URL, testCase.fragment) {
				t.Fatalf("reference = %#v", testCase.got)
			}
		})
	}
}
