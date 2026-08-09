package upstream

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"slices"
)

var mochaCasePattern = regexp.MustCompile(`\bit\s*\(`)

type testList struct {
	Tests map[string]testGroup `json:"tests"`
}

type testGroup struct {
	Helpers []string `json:"helpers"`
	Cases   []string `json:"cases"`
}

// Scan reads the test lists and referenced scripts from an extracted upstream
// corpus. Cases are Mocha it markers in the unique referenced scripts, using
// the pinned corpus counting rule. The template supplies the source identity,
// module inventory, and current Go port mappings; Scan replaces only the
// observed corpus counts.
func Scan(corpus fs.FS, template Manifest) (Manifest, error) {
	observed := template
	observed.Modules = make([]Module, len(template.Modules))
	observed.Totals = Counts{}

	for index, module := range template.Modules {
		counts, err := scanModule(corpus, module)
		if err != nil {
			return Manifest{}, fmt.Errorf("conformance upstream scan: module %q: %w", module.ID, err)
		}

		module.Counts = counts
		observed.Modules[index] = module
		observed.Totals.add(counts)
	}

	if err := Validate(observed); err != nil {
		return Manifest{}, err
	}

	return observed, nil
}

func scanModule(corpus fs.FS, module Module) (Counts, error) {
	counts := Counts{TestLists: len(module.TestLists)}
	scripts := make(map[string]bool)

	for _, listPath := range module.TestLists {
		if !fs.ValidPath(listPath) {
			return Counts{}, fmt.Errorf("invalid test-list path %q", listPath)
		}

		data, err := fs.ReadFile(corpus, listPath)
		if err != nil {
			return Counts{}, fmt.Errorf("read test list %q: %w", listPath, err)
		}

		var list testList
		if err := json.Unmarshal(data, &list); err != nil {
			return Counts{}, fmt.Errorf("decode test list %q: %w", listPath, err)
		}
		if list.Tests == nil {
			return Counts{}, fmt.Errorf("test list %q has no tests object", listPath)
		}

		groupNames := make([]string, 0, len(list.Tests))
		for name := range list.Tests {
			groupNames = append(groupNames, name)
		}
		slices.Sort(groupNames)

		for _, groupName := range groupNames {
			for _, reference := range list.Tests[groupName].Cases {
				scriptPath, err := resolveScriptPath(listPath, reference)
				if err != nil {
					return Counts{}, fmt.Errorf("test list %q group %q: %w", listPath, groupName, err)
				}

				if _, seen := scripts[scriptPath]; !seen {
					script, err := fs.ReadFile(corpus, scriptPath)
					if err != nil {
						return Counts{}, fmt.Errorf("read case %q: %w", scriptPath, err)
					}
					counts.Cases += len(mochaCasePattern.FindAll(script, -1))
					scripts[scriptPath] = true
				}

				counts.References++
			}
		}
	}

	counts.Scripts = len(scripts)

	return counts, nil
}

func resolveScriptPath(listPath, reference string) (string, error) {
	if reference == "" {
		return "", fmt.Errorf("empty case reference")
	}
	if !fs.ValidPath(reference) {
		return "", fmt.Errorf("invalid case reference %q", reference)
	}

	scriptPath := path.Join(path.Dir(listPath), reference)

	return scriptPath, nil
}

func (counts *Counts) add(other Counts) {
	counts.TestLists += other.TestLists
	counts.References += other.References
	counts.Scripts += other.Scripts
	counts.Cases += other.Cases
}

// Changes describes upstream inventory drift. Go port mappings are excluded:
// they are repository-owned coverage data and Scan preserves them verbatim.
type Changes struct {
	SchemaVersionChanged bool           `json:"schemaVersionChanged,omitempty"`
	SourceChanged        bool           `json:"sourceChanged,omitempty"`
	TotalsChanged        bool           `json:"totalsChanged,omitempty"`
	Modules              []ModuleChange `json:"modules,omitempty"`
}

// ModuleChange records an added, removed, or modified upstream module.
type ModuleChange struct {
	ID       string  `json:"id"`
	Expected *Module `json:"expected,omitempty"`
	Observed *Module `json:"observed,omitempty"`
}

// Empty reports whether two manifests have the same upstream inventory.
func (changes Changes) Empty() bool {
	return !changes.SchemaVersionChanged &&
		!changes.SourceChanged &&
		!changes.TotalsChanged &&
		len(changes.Modules) == 0
}

// Diff compares source identity, aggregate counts, and module inventory.
func Diff(expected, observed Manifest) Changes {
	changes := Changes{
		SchemaVersionChanged: expected.SchemaVersion != observed.SchemaVersion,
		SourceChanged:        expected.Source != observed.Source,
		TotalsChanged:        expected.Totals != observed.Totals,
	}

	expectedModules := modulesByID(expected.Modules)
	observedModules := modulesByID(observed.Modules)
	moduleIDs := make([]string, 0, len(expectedModules)+len(observedModules))
	for id := range expectedModules {
		moduleIDs = append(moduleIDs, id)
	}
	for id := range observedModules {
		if _, exists := expectedModules[id]; !exists {
			moduleIDs = append(moduleIDs, id)
		}
	}
	slices.Sort(moduleIDs)

	for _, id := range moduleIDs {
		expectedModule, hasExpected := expectedModules[id]
		observedModule, hasObserved := observedModules[id]
		if hasExpected && hasObserved && equalModule(expectedModule, observedModule) {
			continue
		}

		change := ModuleChange{ID: id}
		if hasExpected {
			expectedCopy := expectedModule
			change.Expected = &expectedCopy
		}
		if hasObserved {
			observedCopy := observedModule
			change.Observed = &observedCopy
		}
		changes.Modules = append(changes.Modules, change)
	}

	return changes
}

func modulesByID(modules []Module) map[string]Module {
	byID := make(map[string]Module, len(modules))
	for _, module := range modules {
		byID[module.ID] = module
	}

	return byID
}

func equalModule(left, right Module) bool {
	return left.ID == right.ID &&
		left.Name == right.Name &&
		slices.Equal(left.TestLists, right.TestLists) &&
		left.Counts == right.Counts
}
