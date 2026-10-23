package inspect

import (
	"testing"

	"github.com/telesma-app/ctap/protocol"
	model "github.com/telesma-app/kit/model/inspect"
)

func TestBuildResultIncludesGetInfoAssessment(t *testing.T) {
	result := BuildInfo(protocol.AuthenticatorGetInfoResponse{
		Options: map[protocol.Option]bool{
			protocol.OptionClientPIN: false,
		},
	})

	if len(result.Assessment.Facts) == 0 {
		t.Fatal("assessment facts are empty")
	}

	for _, fact := range result.Assessment.Facts {
		if fact.ID != model.FactIDClientPIN {
			continue
		}

		if fact.State != model.FactStateNotConfigured || fact.Value.Boolean == nil || *fact.Value.Boolean {
			t.Fatalf("client PIN fact = %#v, want reported not configured", fact)
		}

		return
	}

	t.Fatal("client PIN fact not found")
}
