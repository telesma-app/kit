package config

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/telesma-app/ctap/protocol"
	. "github.com/telesma-app/kit/model/config"
	"github.com/telesma-app/kit/model/failure"
	"github.com/telesma-app/kit/model/safety"
)

func TestBioEnrollPreviewAllowsSupportedAuthenticatorWithNoEnrollments(t *testing.T) {
	status := BuildStatusReport(nilDevice(), protocol.AuthenticatorGetInfoResponse{
		Options: map[protocol.Option]bool{
			protocol.OptionBioEnroll: false,
		},
	})

	preview, err := BuildBioEnrollPreview(status, 60000, safety.PreviewModeDryRun)
	if err != nil {
		t.Fatalf("BuildBioEnrollPreview: %v", err)
	}

	if preview.PreviewOnly {
		t.Fatalf("unexpected preview: %#v", preview)
	}
}

func TestBioMutationPreviewRejectsKnownEmptyEnrollmentSet(t *testing.T) {
	status := BuildStatusReport(nilDevice(), protocol.AuthenticatorGetInfoResponse{
		Options: map[protocol.Option]bool{
			protocol.OptionBioEnroll: false,
		},
	})

	if _, err := BuildBioMutationPreview(status, BioMutationRename, "01", "left thumb", safety.PreviewModeDryRun); !failure.IsCode(err, failure.CodeBioNoEnrollments) {
		t.Fatalf("BuildBioMutationPreview(rename) error = %v, want %s", err, failure.CodeBioNoEnrollments)
	}

	if _, err := BuildBioMutationPreview(status, BioMutationRemove, "01", "", safety.PreviewModeDryRun); !failure.IsCode(err, failure.CodeBioNoEnrollments) {
		t.Fatalf("BuildBioMutationPreview(remove) error = %v, want %s", err, failure.CodeBioNoEnrollments)
	}
}

func TestBioEnrollJSONPreservesExplicitZeroRemainingSamples(t *testing.T) {
	result := BioEnrollResult{
		TemplateIDHex:    "abcd",
		RemainingSamples: new(uint(0)),
		Samples: []BioEnrollSample{
			{Status: "good", RemainingSamples: new(uint(0))},
		},
	}

	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	if got := strings.Count(string(raw), `"remainingSamples":0`); got != 2 {
		t.Fatalf("JSON = %s, want two explicit zero remainingSamples fields", raw)
	}

	raw, err = json.Marshal(BioEnrollResult{TemplateIDHex: "abcd"})
	if err != nil {
		t.Fatalf("Marshal absent: %v", err)
	}

	if strings.Contains(string(raw), "remainingSamples") {
		t.Fatalf("JSON = %s, want absent remainingSamples omitted", raw)
	}
}
