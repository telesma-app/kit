package upstream

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"strings"
)

const (
	CatalogSchemaVersion = 1

	ctap23CatalogModuleID = "ctap2.3-authenticator"
	ctap23CatalogTestList = "modules/ctap2.3-conformance-module/authr-testlist.json"
	ctap23CatalogScripts  = 49
	ctap23CatalogCases    = 295
)

var (
	mochaMarkerPattern   = regexp.MustCompile(`\bit[\t\r\n ]*\([\t\r\n ]*['"\x60][\t ]*([[:alpha:]]+-[[:digit:]]+)\b`)
	catalogMarkerPattern = regexp.MustCompile(`^[[:alpha:]]+-[[:digit:]]+$`)
)

// Catalog is the observed CTAP 2.3 authenticator source inventory. It contains
// only test-list declarations and mechanically extracted script metadata.
type Catalog struct {
	SchemaVersion int            `json:"schemaVersion"`
	ModuleID      string         `json:"moduleId"`
	TestList      string         `json:"testList"`
	Groups        []CatalogGroup `json:"groups"`
	Totals        CatalogTotals  `json:"totals"`
}

// CatalogGroup records one test-list group in declaration order.
type CatalogGroup struct {
	ID      string          `json:"id"`
	Helpers []string        `json:"helpers"`
	Scripts []CatalogScript `json:"scripts"`
}

// CatalogScript records one exact test-list-relative source reference.
type CatalogScript struct {
	Source string        `json:"source"`
	SHA256 string        `json:"sha256"`
	Cases  []CatalogCase `json:"cases"`
}

// CatalogCase records a short Mocha case marker and its one-based source line.
type CatalogCase struct {
	Marker string `json:"marker"`
	Line   int    `json:"line"`
}

// CatalogTotals summarizes the catalog bootstrap gate.
type CatalogTotals struct {
	Scripts int `json:"scripts"`
	Cases   int `json:"cases"`
}

//go:embed catalog.json
var currentCatalogJSON []byte

// CurrentCatalog parses and validates the committed CTAP 2.3 source catalog.
func CurrentCatalog() Catalog {
	var catalog Catalog
	if err := json.Unmarshal(currentCatalogJSON, &catalog); err != nil {
		panic(fmt.Errorf("conformance upstream catalog: %w", err))
	}
	if err := ValidateCatalog(catalog); err != nil {
		panic(err)
	}

	return catalog
}

// GenerateCatalog mechanically derives the CTAP 2.3 source catalog from an
// extracted fido-conformance-tools corpus. Script bodies are used only to hash
// the source and locate markers using the pinned corpus's lexical counting
// rule. The rule intentionally does not interpret JavaScript or strip comments.
func GenerateCatalog(corpus fs.FS) (Catalog, error) {
	data, err := fs.ReadFile(corpus, ctap23CatalogTestList)
	if err != nil {
		return Catalog{}, fmt.Errorf("conformance upstream catalog: read test list %q: %w", ctap23CatalogTestList, err)
	}

	groups, err := decodeCatalogGroups(data)
	if err != nil {
		return Catalog{}, fmt.Errorf("conformance upstream catalog: decode test list %q: %w", ctap23CatalogTestList, err)
	}

	catalog := Catalog{
		SchemaVersion: CatalogSchemaVersion,
		ModuleID:      ctap23CatalogModuleID,
		TestList:      ctap23CatalogTestList,
		Groups:        make([]CatalogGroup, 0, len(groups)),
	}
	sources := make(map[string]bool)

	for _, declared := range groups {
		group := CatalogGroup{
			ID:      declared.ID,
			Helpers: declared.Group.Helpers,
			Scripts: make([]CatalogScript, 0, len(declared.Group.Cases)),
		}

		for _, helper := range group.Helpers {
			helperPath, err := resolveHelperPath(catalog.TestList, helper)
			if err != nil {
				return Catalog{}, fmt.Errorf("conformance upstream catalog: group %q: %w", group.ID, err)
			}
			helperInfo, err := fs.Stat(corpus, helperPath)
			if err != nil {
				return Catalog{}, fmt.Errorf("conformance upstream catalog: group %q: resolve helper %q: %w", group.ID, helper, err)
			}
			if helperInfo.IsDir() {
				return Catalog{}, fmt.Errorf("conformance upstream catalog: group %q: helper %q is not a file", group.ID, helper)
			}
		}

		for _, source := range declared.Group.Cases {
			if sources[source] {
				return Catalog{}, fmt.Errorf("conformance upstream catalog: source %q is declared more than once", source)
			}

			scriptPath, err := resolveScriptPath(catalog.TestList, source)
			if err != nil {
				return Catalog{}, fmt.Errorf("conformance upstream catalog: group %q: %w", group.ID, err)
			}
			script, err := fs.ReadFile(corpus, scriptPath)
			if err != nil {
				return Catalog{}, fmt.Errorf("conformance upstream catalog: group %q: resolve source %q: %w", group.ID, source, err)
			}

			cases, err := scanCatalogCases(script)
			if err != nil {
				return Catalog{}, fmt.Errorf("conformance upstream catalog: source %q: %w", source, err)
			}
			digest := sha256.Sum256(script)
			group.Scripts = append(group.Scripts, CatalogScript{
				Source: source,
				SHA256: hex.EncodeToString(digest[:]),
				Cases:  cases,
			})
			catalog.Totals.Scripts++
			catalog.Totals.Cases += len(cases)
			sources[source] = true
		}

		catalog.Groups = append(catalog.Groups, group)
	}

	if err := ValidateCatalog(catalog); err != nil {
		return Catalog{}, err
	}

	return catalog, nil
}

// MarshalCatalog returns the canonical, newline-terminated catalog encoding.
func MarshalCatalog(catalog Catalog) ([]byte, error) {
	if err := ValidateCatalog(catalog); err != nil {
		return nil, err
	}

	data, err := json.MarshalIndent(catalog, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("conformance upstream catalog: encode: %w", err)
	}

	return append(data, '\n'), nil
}

// ValidateCatalog checks catalog structure, uniqueness, hashes, ordering, and
// the pinned 49-script/295-case bootstrap totals.
func ValidateCatalog(catalog Catalog) error {
	if catalog.SchemaVersion != CatalogSchemaVersion {
		return fmt.Errorf("conformance upstream catalog: schema version %d, want %d", catalog.SchemaVersion, CatalogSchemaVersion)
	}
	if catalog.ModuleID != ctap23CatalogModuleID {
		return fmt.Errorf("conformance upstream catalog: module %q, want %q", catalog.ModuleID, ctap23CatalogModuleID)
	}
	if catalog.TestList != ctap23CatalogTestList {
		return fmt.Errorf("conformance upstream catalog: test list %q, want %q", catalog.TestList, ctap23CatalogTestList)
	}
	if len(catalog.Groups) == 0 {
		return fmt.Errorf("conformance upstream catalog: no test-list groups")
	}

	groupIDs := make(map[string]bool, len(catalog.Groups))
	sources := make(map[string]bool)
	var totals CatalogTotals
	for _, group := range catalog.Groups {
		if group.ID == "" {
			return fmt.Errorf("conformance upstream catalog: empty test-list group")
		}
		if groupIDs[group.ID] {
			return fmt.Errorf("conformance upstream catalog: duplicate test-list group %q", group.ID)
		}
		groupIDs[group.ID] = true

		helpers := make(map[string]bool, len(group.Helpers))
		for _, helper := range group.Helpers {
			if _, err := resolveHelperPath(catalog.TestList, helper); err != nil {
				return fmt.Errorf("conformance upstream catalog: group %q: %w", group.ID, err)
			}
			if helpers[helper] {
				return fmt.Errorf("conformance upstream catalog: group %q has duplicate helper %q", group.ID, helper)
			}
			helpers[helper] = true
		}

		for _, script := range group.Scripts {
			if _, err := resolveScriptPath(catalog.TestList, script.Source); err != nil {
				return fmt.Errorf("conformance upstream catalog: group %q: %w", group.ID, err)
			}
			if sources[script.Source] {
				return fmt.Errorf("conformance upstream catalog: duplicate source %q", script.Source)
			}
			if len(script.SHA256) != sha256.Size*2 {
				return fmt.Errorf("conformance upstream catalog: source %q has invalid SHA-256 %q", script.Source, script.SHA256)
			}
			digest, err := hex.DecodeString(script.SHA256)
			if err != nil || hex.EncodeToString(digest) != script.SHA256 {
				return fmt.Errorf("conformance upstream catalog: source %q has invalid SHA-256 %q", script.Source, script.SHA256)
			}

			markers := make(map[string]bool, len(script.Cases))
			previousLine := 0
			for _, testCase := range script.Cases {
				if !catalogMarkerPattern.MatchString(testCase.Marker) {
					return fmt.Errorf("conformance upstream catalog: source %q has invalid case marker %q", script.Source, testCase.Marker)
				}
				if markers[testCase.Marker] {
					return fmt.Errorf("conformance upstream catalog: source %q has duplicate case marker %q", script.Source, testCase.Marker)
				}
				if testCase.Line < 1 || testCase.Line < previousLine {
					return fmt.Errorf("conformance upstream catalog: source %q case %q has out-of-order line %d", script.Source, testCase.Marker, testCase.Line)
				}
				markers[testCase.Marker] = true
				previousLine = testCase.Line
			}

			sources[script.Source] = true
			totals.Scripts++
			totals.Cases += len(script.Cases)
		}
	}

	if totals != catalog.Totals {
		return fmt.Errorf("conformance upstream catalog: observed totals %+v, declared %+v", totals, catalog.Totals)
	}
	if totals.Scripts != ctap23CatalogScripts || totals.Cases != ctap23CatalogCases {
		return fmt.Errorf("conformance upstream catalog: totals %+v, want %d scripts and %d cases", totals, ctap23CatalogScripts, ctap23CatalogCases)
	}

	return nil
}

type declaredCatalogGroup struct {
	ID    string
	Group testGroup
}

func decodeCatalogGroups(data []byte) ([]declaredCatalogGroup, error) {
	var list struct {
		Tests json.RawMessage `json:"tests"`
	}
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, err
	}
	if len(list.Tests) == 0 || bytes.Equal(list.Tests, []byte("null")) {
		return nil, fmt.Errorf("no tests object")
	}

	decoder := json.NewDecoder(bytes.NewReader(list.Tests))
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '{' {
		return nil, fmt.Errorf("tests is not an object")
	}

	var groups []declaredCatalogGroup
	seen := make(map[string]bool)
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		id, ok := token.(string)
		if !ok || id == "" {
			return nil, fmt.Errorf("invalid test-list group %v", token)
		}
		if seen[id] {
			return nil, fmt.Errorf("duplicate test-list group %q", id)
		}

		var group testGroup
		if err := decoder.Decode(&group); err != nil {
			return nil, fmt.Errorf("group %q: %w", id, err)
		}
		if group.Helpers == nil {
			return nil, fmt.Errorf("group %q has no helpers array", id)
		}
		if group.Cases == nil {
			return nil, fmt.Errorf("group %q has no cases array", id)
		}

		groups = append(groups, declaredCatalogGroup{ID: id, Group: group})
		seen[id] = true
	}
	if _, err := decoder.Token(); err != nil {
		return nil, err
	}
	if len(groups) == 0 {
		return nil, fmt.Errorf("no test-list groups")
	}

	return groups, nil
}

func scanCatalogCases(script []byte) ([]CatalogCase, error) {
	caseLocations := mochaMarkerPattern.FindAllSubmatchIndex(script, -1)
	callLocations := mochaCasePattern.FindAllIndex(script, -1)
	if len(caseLocations) != len(callLocations) {
		return nil, fmt.Errorf("found %d Mocha case calls but extracted %d short markers", len(callLocations), len(caseLocations))
	}

	cases := make([]CatalogCase, 0, len(caseLocations))
	markers := make(map[string]bool, len(caseLocations))
	for _, location := range caseLocations {
		marker := string(script[location[2]:location[3]])
		if markers[marker] {
			return nil, fmt.Errorf("duplicate case marker %q", marker)
		}

		cases = append(cases, CatalogCase{
			Marker: marker,
			Line:   bytes.Count(script[:location[0]], []byte{'\n'}) + 1,
		})
		markers[marker] = true
	}

	return cases, nil
}

func resolveHelperPath(listPath, reference string) (string, error) {
	if reference == "" {
		return "", fmt.Errorf("empty helper reference")
	}

	relative := strings.TrimPrefix(reference, "/")
	if !fs.ValidPath(relative) || (reference != relative && reference != "/"+relative) {
		return "", fmt.Errorf("invalid helper reference %q", reference)
	}

	return path.Join(path.Dir(listPath), relative), nil
}
