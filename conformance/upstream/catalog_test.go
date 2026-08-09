package upstream_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/telesma-app/kit/conformance/upstream"
)

func TestGenerateCatalogPreservesObservedOrderingHashesAndMarkers(t *testing.T) {
	corpus := catalogFixture(t, 49, 295)

	catalog, err := upstream.GenerateCatalog(corpus)
	if err != nil {
		t.Fatal(err)
	}

	if catalog.Totals != (upstream.CatalogTotals{Scripts: 49, Cases: 295}) {
		t.Fatalf("totals = %+v", catalog.Totals)
	}
	if len(catalog.Groups) != 2 || catalog.Groups[0].ID != "later-name" || catalog.Groups[1].ID != "earlier-name" {
		t.Fatalf("group order = %#v", catalog.Groups)
	}
	if !reflect.DeepEqual(catalog.Groups[0].Helpers, []string{"/js/helper.js"}) {
		t.Fatalf("helpers = %#v", catalog.Groups[0].Helpers)
	}

	first := catalog.Groups[0].Scripts[0]
	if first.Source != "tests/script-01.js" {
		t.Fatalf("first source = %q", first.Source)
	}
	wantDigest := sha256.Sum256(corpus[firstCatalogScriptPath].Data)
	if first.SHA256 != hex.EncodeToString(wantDigest[:]) {
		t.Fatalf("first SHA-256 = %q", first.SHA256)
	}
	if got, want := first.Cases[:2], []upstream.CatalogCase{{Marker: "P-1", Line: 2}, {Marker: "P-2", Line: 3}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("first cases = %#v, want %#v", got, want)
	}

	encoded, err := upstream.MarshalCatalog(catalog)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(encoded, []byte{'\n'}) {
		t.Fatal("catalog encoding is not newline-terminated")
	}
}

func TestGenerateCatalogRejectsDuplicateMarkersWithinScript(t *testing.T) {
	corpus := catalogFixture(t, 49, 295)
	corpus[firstCatalogScriptPath] = &fstest.MapFile{Data: []byte("it('P-1', () => {});\nit('P-1', () => {});\n")}

	_, err := upstream.GenerateCatalog(corpus)
	if err == nil || !strings.Contains(err.Error(), "duplicate case marker") {
		t.Fatalf("GenerateCatalog duplicate marker = %v", err)
	}
}

func TestGenerateCatalogUsesPinnedLexicalMarkerRule(t *testing.T) {
	corpus := catalogFixture(t, 49, 295)
	script := string(corpus[firstCatalogScriptPath].Data)
	corpus[firstCatalogScriptPath] = &fstest.MapFile{Data: []byte(strings.Replace(script, "it('P-1'", "// it('P-1'", 1))}

	catalog, err := upstream.GenerateCatalog(corpus)
	if err != nil {
		t.Fatal(err)
	}
	if catalog.Groups[0].Scripts[0].Cases[0].Marker != "P-1" {
		t.Fatalf("first lexical marker = %#v", catalog.Groups[0].Scripts[0].Cases[0])
	}
}

func TestGenerateCatalogRejectsUnresolvedReferences(t *testing.T) {
	t.Run("source", func(t *testing.T) {
		corpus := catalogFixture(t, 49, 295)
		delete(corpus, firstCatalogScriptPath)

		_, err := upstream.GenerateCatalog(corpus)
		if err == nil || !strings.Contains(err.Error(), "resolve source") {
			t.Fatalf("GenerateCatalog unresolved source = %v", err)
		}
	})

	t.Run("helper", func(t *testing.T) {
		corpus := catalogFixture(t, 49, 295)
		delete(corpus, catalogHelperPath)

		_, err := upstream.GenerateCatalog(corpus)
		if err == nil || !strings.Contains(err.Error(), "resolve helper") {
			t.Fatalf("GenerateCatalog unresolved helper = %v", err)
		}
	})
}

func TestGenerateCatalogRejectsWrongBootstrapTotals(t *testing.T) {
	tests := []struct {
		name        string
		scriptCount int
		caseCount   int
	}{
		{name: "scripts", scriptCount: 48, caseCount: 295},
		{name: "cases", scriptCount: 49, caseCount: 294},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := upstream.GenerateCatalog(catalogFixture(t, test.scriptCount, test.caseCount))
			if err == nil || !strings.Contains(err.Error(), "want 49 scripts and 295 cases") {
				t.Fatalf("GenerateCatalog totals = %v", err)
			}
		})
	}
}

func TestCurrentCatalogMatchesPinnedCorpus(t *testing.T) {
	const corpusPath = "../../reference/fido-conformance-tools-1.9.1"
	if _, err := os.Stat(corpusPath); err != nil {
		if os.IsNotExist(err) {
			t.Skip("pinned extracted corpus is not present")
		}
		t.Fatal(err)
	}

	generated, err := upstream.GenerateCatalog(os.DirFS(corpusPath))
	if err != nil {
		t.Fatal(err)
	}
	committed := upstream.CurrentCatalog()
	if !reflect.DeepEqual(generated, committed) {
		t.Fatal("committed catalog does not match the pinned extracted corpus")
	}
}

const (
	catalogListPath          = "modules/ctap2.3-conformance-module/authr-testlist.json"
	catalogHelperPath        = "modules/ctap2.3-conformance-module/js/helper.js"
	firstCatalogScriptPath   = "modules/ctap2.3-conformance-module/tests/script-01.js"
	catalogFixtureGroupSplit = 2
)

func catalogFixture(t *testing.T, scriptCount, caseCount int) fstest.MapFS {
	t.Helper()
	if scriptCount < catalogFixtureGroupSplit || caseCount < scriptCount {
		t.Fatalf("invalid fixture totals: %d scripts, %d cases", scriptCount, caseCount)
	}

	corpus := fstest.MapFS{
		catalogHelperPath: {Data: []byte("fixture helper")},
	}
	references := make([]string, 0, scriptCount)
	baseCases := caseCount / scriptCount
	extraCases := caseCount % scriptCount
	for scriptIndex := 1; scriptIndex <= scriptCount; scriptIndex++ {
		reference := fmt.Sprintf("tests/script-%02d.js", scriptIndex)
		references = append(references, reference)

		scriptCases := baseCases
		if scriptIndex <= extraCases {
			scriptCases++
		}
		var script strings.Builder
		script.WriteString("// fixture\n")
		for caseIndex := 1; caseIndex <= scriptCases; caseIndex++ {
			fmt.Fprintf(&script, "it('P-%d', () => {});\n", caseIndex)
		}
		corpus["modules/ctap2.3-conformance-module/"+reference] = &fstest.MapFile{Data: []byte(script.String())}
	}

	firstGroup, err := json.Marshal(references[:catalogFixtureGroupSplit])
	if err != nil {
		t.Fatal(err)
	}
	secondGroup, err := json.Marshal(references[catalogFixtureGroupSplit:])
	if err != nil {
		t.Fatal(err)
	}
	list := fmt.Sprintf(
		`{"tests":{"later-name":{"helpers":["/js/helper.js"],"cases":%s},"earlier-name":{"helpers":["/js/helper.js"],"cases":%s}}}`,
		firstGroup,
		secondGroup,
	)
	corpus[catalogListPath] = &fstest.MapFile{Data: []byte(list)}

	return corpus
}
