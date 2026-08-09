package upstream_test

import (
	"testing"

	"github.com/telesma-app/kit/conformance/upstream"
)

func TestCurrentWorkplanExactlyCoversCTAP23Catalog(t *testing.T) {
	catalog := upstream.CurrentCatalog()
	workplan := upstream.CurrentWorkplan()

	if workplan.Totals != (upstream.WorkplanTotals{Tasks: 56, Scripts: 49, Cases: 295}) {
		t.Fatalf("workplan totals = %+v", workplan.Totals)
	}
	if workplan.Totals.Scripts != catalog.Totals.Scripts || workplan.Totals.Cases != catalog.Totals.Cases {
		t.Fatalf("workplan totals = %+v, catalog totals = %+v", workplan.Totals, catalog.Totals)
	}
}

func TestValidateWorkplanRejectsOverlappingCaseAssignments(t *testing.T) {
	catalog := upstream.CurrentCatalog()
	workplan := upstream.CurrentWorkplan()
	first := workplanTaskIndex(t, workplan, "ctap23-metadata-stmt-1-01-14")
	second := workplanTaskIndex(t, workplan, "ctap23-metadata-stmt-1-15-24")
	workplan.Tasks[second].Cases = []string{workplan.Tasks[first].Cases[0]}

	if err := upstream.ValidateWorkplan(workplan, catalog); err == nil {
		t.Fatal("ValidateWorkplan accepted overlapping case assignments")
	}
}

func TestValidateWorkplanRejectsNoncontiguousCaseRange(t *testing.T) {
	catalog := upstream.CurrentCatalog()
	workplan := upstream.CurrentWorkplan()
	index := workplanTaskIndex(t, workplan, "ctap23-authr-generic-1")
	workplan.Tasks[index].Cases = []string{"P-1", "P-3"}

	if err := upstream.ValidateWorkplan(workplan, catalog); err == nil {
		t.Fatal("ValidateWorkplan accepted a noncontiguous case range")
	}
}

func TestValidateWorkplanRejectsOversizedTask(t *testing.T) {
	catalog := upstream.CurrentCatalog()
	workplan := upstream.CurrentWorkplan()
	index := workplanTaskIndex(t, workplan, "ctap23-hid-1-p-01-10")
	workplan.Tasks[index].Cases = make([]string, 16)

	if err := upstream.ValidateWorkplan(workplan, catalog); err == nil {
		t.Fatal("ValidateWorkplan accepted a task with more than 15 cases")
	}
}

func TestValidateWorkplanRejectsDependencyCycle(t *testing.T) {
	catalog := upstream.CurrentCatalog()
	workplan := upstream.CurrentWorkplan()
	first := workplanTaskIndex(t, workplan, "ctap23-authr-make-cred-req-1")
	second := workplanTaskIndex(t, workplan, "ctap23-authr-make-cred-req-2")
	workplan.Tasks[first].DependsOn = []string{workplan.Tasks[second].ID}
	workplan.Tasks[second].DependsOn = []string{workplan.Tasks[first].ID}

	if err := upstream.ValidateWorkplan(workplan, catalog); err == nil {
		t.Fatal("ValidateWorkplan accepted a dependency cycle")
	}
}

func TestValidateWorkplanRejectsReadyTaskWithUnmergedDependency(t *testing.T) {
	catalog := upstream.CurrentCatalog()
	workplan := upstream.CurrentWorkplan()
	index := workplanTaskIndex(t, workplan, "ctap23-authr-client-pin2-get-pin-token")
	dependency := workplanTaskIndex(t, workplan, workplan.Tasks[index].DependsOn[0])
	workplan.Tasks[index].Status = upstream.TaskStatusReady
	workplan.Tasks[index].BlockedReason = ""
	workplan.Tasks[dependency].Status = upstream.TaskStatusReview

	if err := upstream.ValidateWorkplan(workplan, catalog); err == nil {
		t.Fatal("ValidateWorkplan accepted a ready task with an unmerged dependency")
	}
}

func workplanTaskIndex(t *testing.T, workplan upstream.Workplan, id string) int {
	t.Helper()

	for index, task := range workplan.Tasks {
		if task.ID == id {
			return index
		}
	}

	t.Fatalf("workplan has no task %q", id)

	return 0
}
