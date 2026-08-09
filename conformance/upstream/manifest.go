// Package upstream exposes the pinned source corpus and Go port coverage.
package upstream

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/telesma-app/kit/conformance"
)

const SchemaVersion = 1

// Counts summarizes declared upstream test inventory.
type Counts struct {
	TestLists  int `json:"testLists"`
	References int `json:"references"`
	Scripts    int `json:"scripts"`
	Cases      int `json:"cases"`
}

// Module identifies one independently versioned upstream test module.
type Module struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	TestLists []string `json:"testLists"`
	Counts    Counts   `json:"counts"`
}

// PortStatus records whether one upstream case has a Go implementation.
type PortStatus string

const (
	PortStatusPending PortStatus = "pending"
	PortStatusPartial PortStatus = "partial"
	PortStatusPorted  PortStatus = "ported"
)

// Port maps one stable Go test ID to its upstream case.
type Port struct {
	ModuleID string                     `json:"moduleId"`
	SuiteID  conformance.SuiteID        `json:"suiteId"`
	TestID   conformance.TestID         `json:"testId"`
	Source   conformance.SourceLocation `json:"source"`
	Status   PortStatus                 `json:"status"`
}

// Manifest is the machine-readable inventory of the pinned source artifact
// and the cases currently implemented in Go.
type Manifest struct {
	SchemaVersion int                `json:"schemaVersion"`
	Source        conformance.Source `json:"source"`
	Totals        Counts             `json:"totals"`
	Modules       []Module           `json:"modules"`
	Ports         []Port             `json:"ports"`
}

//go:embed manifest.json
var currentJSON []byte

// Current parses and validates the manifest embedded in this package.
func Current() Manifest {
	var manifest Manifest
	if err := json.Unmarshal(currentJSON, &manifest); err != nil {
		panic(fmt.Errorf("conformance upstream manifest: %w", err))
	}
	if err := Validate(manifest); err != nil {
		panic(err)
	}
	if err := ValidateCTAP23Coverage(manifest, CurrentCatalog(), CurrentWorkplan()); err != nil {
		panic(err)
	}

	return manifest
}

// Validate checks manifest structure, aggregate counts, and port mappings.
func Validate(manifest Manifest) error {
	if manifest.SchemaVersion != SchemaVersion {
		return fmt.Errorf("conformance upstream manifest: schema version %d, want %d", manifest.SchemaVersion, SchemaVersion)
	}
	if manifest.Source.Artifact == "" || manifest.Source.Version == "" || manifest.Source.Digest == "" {
		return fmt.Errorf("conformance upstream manifest: source identity is incomplete")
	}
	if len(manifest.Modules) == 0 {
		return fmt.Errorf("conformance upstream manifest: no modules declared")
	}

	moduleIDs := make(map[string]bool, len(manifest.Modules))
	var totals Counts
	for _, module := range manifest.Modules {
		if module.ID == "" || module.Name == "" {
			return fmt.Errorf("conformance upstream manifest: module identity is incomplete")
		}
		if moduleIDs[module.ID] {
			return fmt.Errorf("conformance upstream manifest: duplicate module %q", module.ID)
		}
		moduleIDs[module.ID] = true

		if module.Counts.TestLists != len(module.TestLists) {
			return fmt.Errorf("conformance upstream manifest: module %q has %d lists, count says %d", module.ID, len(module.TestLists), module.Counts.TestLists)
		}
		if slices.Contains(module.TestLists, "") {
			return fmt.Errorf("conformance upstream manifest: module %q has an empty test-list path", module.ID)
		}

		totals.TestLists += module.Counts.TestLists
		totals.References += module.Counts.References
		totals.Scripts += module.Counts.Scripts
		totals.Cases += module.Counts.Cases
	}
	if totals != manifest.Totals {
		return fmt.Errorf("conformance upstream manifest: module totals %+v, declared %+v", totals, manifest.Totals)
	}

	portIDs := make(map[conformance.TestID]bool, len(manifest.Ports))
	for _, port := range manifest.Ports {
		if !moduleIDs[port.ModuleID] {
			return fmt.Errorf("conformance upstream manifest: port %q refers to unknown module %q", port.TestID, port.ModuleID)
		}
		if port.SuiteID == "" || port.TestID == "" || port.Source.Path == "" || port.Source.Case == "" {
			return fmt.Errorf("conformance upstream manifest: port mapping is incomplete")
		}
		if portIDs[port.TestID] {
			return fmt.Errorf("conformance upstream manifest: duplicate port %q", port.TestID)
		}
		portIDs[port.TestID] = true

		switch port.Status {
		case PortStatusPending, PortStatusPartial, PortStatusPorted:
		default:
			return fmt.Errorf("conformance upstream manifest: port %q has invalid status %q", port.TestID, port.Status)
		}
	}

	return nil
}

type sourceCase struct {
	path       string
	caseMarker string
}

// ValidateCTAP23Coverage checks port mappings against the pinned CTAP 2.3
// catalog and the coordinator-owned task lifecycle.
func ValidateCTAP23Coverage(manifest Manifest, catalog Catalog, workplan Workplan) error {
	knownCases := make(map[sourceCase]bool, catalog.Totals.Cases)
	for _, group := range catalog.Groups {
		for _, script := range group.Scripts {
			for _, testCase := range script.Cases {
				knownCases[sourceCase{path: script.Source, caseMarker: testCase.Marker}] = true
			}
		}
	}

	portedCases := make(map[sourceCase]bool)
	for _, port := range manifest.Ports {
		if port.ModuleID != catalog.ModuleID {
			continue
		}

		key := sourceCase{path: port.Source.Path, caseMarker: port.Source.Case}
		if !knownCases[key] {
			return fmt.Errorf("conformance upstream manifest: port %q has unknown CTAP 2.3 source case %q %q", port.TestID, port.Source.Path, port.Source.Case)
		}
		if port.Status == PortStatusPorted {
			portedCases[key] = true
		}
	}

	for _, task := range workplan.Tasks {
		for _, marker := range task.Cases {
			key := sourceCase{path: task.Source, caseMarker: marker}
			ported := portedCases[key]
			if task.Status == TaskStatusMerged && !ported {
				return fmt.Errorf("conformance upstream manifest: merged task %q case %q has no ported manifest row", task.ID, marker)
			}
			if task.Status != TaskStatusMerged && ported {
				return fmt.Errorf("conformance upstream manifest: unmerged task %q case %q is marked ported", task.ID, marker)
			}
		}
	}

	return nil
}
