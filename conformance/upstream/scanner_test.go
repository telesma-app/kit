package upstream_test

import (
	"testing"
	"testing/fstest"

	"github.com/telesma-app/kit/conformance"
	"github.com/telesma-app/kit/conformance/upstream"
)

func TestScanCountsReferencesUniqueScriptsAndCases(t *testing.T) {
	corpus := fstest.MapFS{
		"modules/example/first.json": {
			Data: []byte(`{"tests":{"alpha":{"cases":["tests/a.js","tests/b.js"]}}}`),
		},
		"modules/example/second.json": {
			Data: []byte(`{"tests":{"beta":{"cases":["tests/a.js"]}}}`),
		},
		"modules/example/tests/a.js": {
			Data: []byte("describe('a', () => { it('P-1', () => {}); it (`P-2`, () => {}); });"),
		},
		"modules/example/tests/b.js": {
			Data: []byte("it('P-1', () => {});"),
		},
	}
	template := upstream.Manifest{
		SchemaVersion: upstream.SchemaVersion,
		Source: conformance.Source{
			Artifact: "example-suite",
			Version:  "2.0.0",
			Digest:   "sha256:fixture",
		},
		Modules: []upstream.Module{{
			ID:   "example",
			Name: "Example",
			TestLists: []string{
				"modules/example/first.json",
				"modules/example/second.json",
			},
		}},
	}

	observed, err := upstream.Scan(corpus, template)
	if err != nil {
		t.Fatal(err)
	}

	want := upstream.Counts{TestLists: 2, References: 3, Scripts: 2, Cases: 3}
	if observed.Totals != want || observed.Modules[0].Counts != want {
		t.Fatalf("observed counts = totals %+v, module %+v; want %+v", observed.Totals, observed.Modules[0].Counts, want)
	}
	if !upstream.Diff(observed, observed).Empty() {
		t.Fatal("manifest differs from itself")
	}
}

func TestScanReportsMissingReferencedScript(t *testing.T) {
	corpus := fstest.MapFS{
		"modules/example/list.json": {
			Data: []byte(`{"tests":{"alpha":{"cases":["tests/missing.js"]}}}`),
		},
	}
	template := upstream.Manifest{
		SchemaVersion: upstream.SchemaVersion,
		Source: conformance.Source{
			Artifact: "example-suite",
			Version:  "2.0.0",
			Digest:   "sha256:fixture",
		},
		Modules: []upstream.Module{{
			ID:        "example",
			Name:      "Example",
			TestLists: []string{"modules/example/list.json"},
		}},
	}

	if _, err := upstream.Scan(corpus, template); err == nil {
		t.Fatal("Scan succeeded with a missing referenced script")
	}
}

func TestScanRejectsCaseReferenceOutsideTestList(t *testing.T) {
	corpus := fstest.MapFS{
		"modules/example/list.json": {
			Data: []byte(`{"tests":{"alpha":{"cases":["../outside.js"]}}}`),
		},
		"modules/outside.js": {
			Data: []byte("it('P-1', () => {});"),
		},
	}
	template := upstream.Manifest{
		SchemaVersion: upstream.SchemaVersion,
		Source: conformance.Source{
			Artifact: "example-suite",
			Version:  "2.0.0",
			Digest:   "sha256:fixture",
		},
		Modules: []upstream.Module{{
			ID:        "example",
			Name:      "Example",
			TestLists: []string{"modules/example/list.json"},
		}},
	}

	if _, err := upstream.Scan(corpus, template); err == nil {
		t.Fatal("Scan succeeded with a case reference outside the test list")
	}
}

func TestDiffReportsSourceAndModuleDrift(t *testing.T) {
	expected := upstream.Manifest{
		SchemaVersion: upstream.SchemaVersion,
		Source: conformance.Source{
			Artifact: "example-suite",
			Version:  "1.0.0",
			Digest:   "sha256:old",
		},
		Totals: upstream.Counts{TestLists: 1, References: 1, Scripts: 1, Cases: 1},
		Modules: []upstream.Module{{
			ID:        "example",
			Name:      "Example",
			TestLists: []string{"modules/example/list.json"},
			Counts:    upstream.Counts{TestLists: 1, References: 1, Scripts: 1, Cases: 1},
		}},
	}
	observed := expected
	observed.Source.Version = "2.0.0"
	observed.Totals.Cases = 2
	observed.Modules = []upstream.Module{
		expected.Modules[0],
		{
			ID:        "added",
			Name:      "Added",
			TestLists: []string{"modules/added/list.json"},
			Counts:    upstream.Counts{TestLists: 1, References: 1, Scripts: 1, Cases: 1},
		},
	}
	observed.Modules[0].Counts.Cases = 2

	changes := upstream.Diff(expected, observed)
	if changes.Empty() || !changes.SourceChanged || !changes.TotalsChanged {
		t.Fatalf("changes = %#v", changes)
	}
	if len(changes.Modules) != 2 || changes.Modules[0].ID != "added" || changes.Modules[1].ID != "example" {
		t.Fatalf("module changes = %#v", changes.Modules)
	}
	if changes.Modules[0].Expected != nil || changes.Modules[0].Observed == nil {
		t.Fatalf("added module change = %#v", changes.Modules[0])
	}

	reverse := upstream.Diff(observed, expected)
	if len(reverse.Modules) != 2 || reverse.Modules[0].Expected == nil || reverse.Modules[0].Observed != nil {
		t.Fatalf("removed module changes = %#v", reverse.Modules)
	}
}
