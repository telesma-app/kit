package upstream

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strings"
)

const WorkplanSchemaVersion = 1

// TaskStatus records the coordinator-owned lifecycle of one porting task.
type TaskStatus string

const (
	TaskStatusBlocked TaskStatus = "blocked"
	TaskStatusReady   TaskStatus = "ready"
	TaskStatusActive  TaskStatus = "active"
	TaskStatusReview  TaskStatus = "review"
	TaskStatusMerged  TaskStatus = "merged"
)

// Workplan is the repository-owned schedule for the CTAP 2.3 source catalog.
type Workplan struct {
	SchemaVersion    int               `json:"schemaVersion"`
	ModuleID         string            `json:"moduleId"`
	SharedPrimitives []SharedPrimitive `json:"sharedPrimitives"`
	Tasks            []WorkplanTask    `json:"tasks"`
	Totals           WorkplanTotals    `json:"totals"`
}

// SharedPrimitive names an already implemented contract that tasks may use.
type SharedPrimitive struct {
	ID    string   `json:"id"`
	Files []string `json:"files"`
}

// WorkplanTask assigns one contiguous source-case range to unique Go files.
type WorkplanTask struct {
	ID                  string     `json:"id"`
	Source              string     `json:"source"`
	Cases               []string   `json:"cases"`
	DependsOn           []string   `json:"dependsOn"`
	Helpers             []string   `json:"helpers"`
	Risk                []string   `json:"risk"`
	SharedPrimitives    []string   `json:"sharedPrimitives,omitempty"`
	ImplementationFiles []string   `json:"implementationFiles"`
	TestFiles           []string   `json:"testFiles"`
	Status              TaskStatus `json:"status"`
	BlockedReason       string     `json:"blockedReason,omitempty"`
}

// WorkplanTotals makes completeness visible without reading all tasks.
type WorkplanTotals struct {
	Tasks   int `json:"tasks"`
	Scripts int `json:"scripts"`
	Cases   int `json:"cases"`
}

//go:embed workplan.json
var currentWorkplanJSON []byte

// CurrentWorkplan parses and validates the committed CTAP 2.3 porting plan.
func CurrentWorkplan() Workplan {
	var workplan Workplan
	if err := json.Unmarshal(currentWorkplanJSON, &workplan); err != nil {
		panic(fmt.Errorf("conformance upstream workplan: %w", err))
	}
	if err := ValidateWorkplan(workplan, CurrentCatalog()); err != nil {
		panic(err)
	}

	return workplan
}

// ValidateWorkplan checks task ownership, dependencies, and exact catalog
// coverage without interpreting upstream case behavior.
func ValidateWorkplan(workplan Workplan, catalog Catalog) error {
	if workplan.SchemaVersion != WorkplanSchemaVersion {
		return fmt.Errorf("conformance upstream workplan: schema version %d, want %d", workplan.SchemaVersion, WorkplanSchemaVersion)
	}
	if workplan.ModuleID != catalog.ModuleID {
		return fmt.Errorf("conformance upstream workplan: module %q, want %q", workplan.ModuleID, catalog.ModuleID)
	}

	primitiveIDs := make(map[string]bool, len(workplan.SharedPrimitives))
	for _, primitive := range workplan.SharedPrimitives {
		if primitive.ID == "" || len(primitive.Files) == 0 {
			return fmt.Errorf("conformance upstream workplan: incomplete shared primitive")
		}
		if primitiveIDs[primitive.ID] {
			return fmt.Errorf("conformance upstream workplan: duplicate shared primitive %q", primitive.ID)
		}
		if err := validateRepositoryPaths(primitive.Files); err != nil {
			return fmt.Errorf("conformance upstream workplan: primitive %q: %w", primitive.ID, err)
		}
		primitiveIDs[primitive.ID] = true
	}

	taskIDs := make(map[string]bool, len(workplan.Tasks))
	taskStatuses := make(map[string]TaskStatus, len(workplan.Tasks))
	for _, task := range workplan.Tasks {
		if task.ID == "" {
			return fmt.Errorf("conformance upstream workplan: empty task ID")
		}
		if taskIDs[task.ID] {
			return fmt.Errorf("conformance upstream workplan: duplicate task %q", task.ID)
		}
		taskIDs[task.ID] = true
		taskStatuses[task.ID] = task.Status
	}

	scripts := catalogScripts(catalog)
	coveredCases := make(map[string]map[string]bool, len(scripts))
	ownedFiles := make(map[string]string)
	for _, task := range workplan.Tasks {
		script, ok := scripts[task.Source]
		if !ok {
			return fmt.Errorf("conformance upstream workplan: task %q has unknown source %q", task.ID, task.Source)
		}
		if len(task.Cases) == 0 {
			return fmt.Errorf("conformance upstream workplan: task %q has no cases", task.ID)
		}
		if len(task.Cases) > 15 {
			return fmt.Errorf("conformance upstream workplan: task %q has %d cases, want at most 15", task.ID, len(task.Cases))
		}
		if !contiguousCatalogCases(script.Cases, task.Cases) {
			return fmt.Errorf("conformance upstream workplan: task %q cases are not one exact contiguous source range", task.ID)
		}

		if coveredCases[task.Source] == nil {
			coveredCases[task.Source] = make(map[string]bool)
		}
		for _, marker := range task.Cases {
			if coveredCases[task.Source][marker] {
				return fmt.Errorf("conformance upstream workplan: source %q case %q is assigned more than once", task.Source, marker)
			}
			coveredCases[task.Source][marker] = true
		}

		if err := validateTaskStatus(task); err != nil {
			return err
		}
		for _, dependency := range task.DependsOn {
			if dependency == task.ID {
				return fmt.Errorf("conformance upstream workplan: task %q depends on itself", task.ID)
			}
			if !taskIDs[dependency] && !primitiveIDs[dependency] {
				return fmt.Errorf("conformance upstream workplan: task %q has unknown dependency %q", task.ID, dependency)
			}
			if task.Status != TaskStatusBlocked && taskIDs[dependency] && taskStatuses[dependency] != TaskStatusMerged {
				return fmt.Errorf("conformance upstream workplan: task %q is %q but dependency %q is %q", task.ID, task.Status, dependency, taskStatuses[dependency])
			}
		}
		for _, primitive := range task.SharedPrimitives {
			if !primitiveIDs[primitive] {
				return fmt.Errorf("conformance upstream workplan: task %q has unknown shared primitive %q", task.ID, primitive)
			}
		}
		if err := validateTaskHelpers(task, catalog); err != nil {
			return err
		}

		files := slices.Concat(task.ImplementationFiles, task.TestFiles)
		if len(task.ImplementationFiles) == 0 || len(task.TestFiles) == 0 {
			return fmt.Errorf("conformance upstream workplan: task %q has incomplete file ownership", task.ID)
		}
		if err := validateRepositoryPaths(files); err != nil {
			return fmt.Errorf("conformance upstream workplan: task %q: %w", task.ID, err)
		}
		for _, file := range files {
			if owner, exists := ownedFiles[file]; exists {
				return fmt.Errorf("conformance upstream workplan: file %q is owned by tasks %q and %q", file, owner, task.ID)
			}
			ownedFiles[file] = task.ID
		}
	}

	var observed WorkplanTotals
	observed.Tasks = len(workplan.Tasks)
	for source, script := range scripts {
		if len(coveredCases[source]) != len(script.Cases) {
			return fmt.Errorf("conformance upstream workplan: source %q covers %d of %d cases", source, len(coveredCases[source]), len(script.Cases))
		}
		observed.Scripts++
		observed.Cases += len(script.Cases)
	}
	if observed != workplan.Totals {
		return fmt.Errorf("conformance upstream workplan: observed totals %+v, declared %+v", observed, workplan.Totals)
	}

	return validateTaskDependencies(workplan.Tasks, primitiveIDs)
}

func catalogScripts(catalog Catalog) map[string]CatalogScript {
	scripts := make(map[string]CatalogScript, catalog.Totals.Scripts)
	for _, group := range catalog.Groups {
		for _, script := range group.Scripts {
			scripts[script.Source] = script
		}
	}

	return scripts
}

func contiguousCatalogCases(catalogCases []CatalogCase, markers []string) bool {
	if len(markers) > len(catalogCases) {
		return false
	}
	for start := 0; start+len(markers) <= len(catalogCases); start++ {
		matched := true
		for offset, marker := range markers {
			if catalogCases[start+offset].Marker != marker {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}

	return false
}

func validateTaskStatus(task WorkplanTask) error {
	switch task.Status {
	case TaskStatusBlocked:
		if task.BlockedReason == "" && len(task.DependsOn) == 0 {
			return fmt.Errorf("conformance upstream workplan: blocked task %q has no dependency or reason", task.ID)
		}
	case TaskStatusReady, TaskStatusActive, TaskStatusReview, TaskStatusMerged:
		if task.BlockedReason != "" {
			return fmt.Errorf("conformance upstream workplan: task %q is %q but has a blocked reason", task.ID, task.Status)
		}
	default:
		return fmt.Errorf("conformance upstream workplan: task %q has invalid status %q", task.ID, task.Status)
	}

	return nil
}

func validateTaskHelpers(task WorkplanTask, catalog Catalog) error {
	var declared []string
	for _, group := range catalog.Groups {
		if slices.ContainsFunc(group.Scripts, func(script CatalogScript) bool { return script.Source == task.Source }) {
			declared = group.Helpers
			break
		}
	}
	seen := make(map[string]bool, len(task.Helpers))
	for _, helper := range task.Helpers {
		if !fs.ValidPath(helper) {
			return fmt.Errorf("conformance upstream workplan: task %q has invalid helper %q", task.ID, helper)
		}
		if seen[helper] {
			return fmt.Errorf("conformance upstream workplan: task %q has duplicate helper %q", task.ID, helper)
		}
		seen[helper] = true

		normalized := strings.TrimPrefix(helper, "/")
		declaredByModule := slices.ContainsFunc(declared, func(candidate string) bool {
			return strings.TrimPrefix(candidate, "/") == normalized
		})
		if strings.HasPrefix(helper, "js/") && !declaredByModule {
			return fmt.Errorf("conformance upstream workplan: task %q uses undeclared helper %q", task.ID, helper)
		}
	}

	return nil
}

func validateRepositoryPaths(files []string) error {
	seen := make(map[string]bool, len(files))
	for _, file := range files {
		if file == "" || path.IsAbs(file) || path.Clean(file) != file || strings.HasPrefix(file, "../") {
			return fmt.Errorf("invalid repository path %q", file)
		}
		if seen[file] {
			return fmt.Errorf("duplicate repository path %q", file)
		}
		seen[file] = true
	}

	return nil
}

func validateTaskDependencies(tasks []WorkplanTask, primitives map[string]bool) error {
	dependencies := make(map[string][]string, len(tasks))
	for _, task := range tasks {
		for _, dependency := range task.DependsOn {
			if !primitives[dependency] {
				dependencies[task.ID] = append(dependencies[task.ID], dependency)
			}
		}
	}

	visiting := make(map[string]bool, len(tasks))
	visited := make(map[string]bool, len(tasks))
	var visit func(string) error
	visit = func(id string) error {
		if visiting[id] {
			return fmt.Errorf("conformance upstream workplan: dependency cycle at task %q", id)
		}
		if visited[id] {
			return nil
		}

		visiting[id] = true
		for _, dependency := range dependencies[id] {
			if err := visit(dependency); err != nil {
				return err
			}
		}
		visiting[id] = false
		visited[id] = true

		return nil
	}

	for _, task := range tasks {
		if err := visit(task.ID); err != nil {
			return err
		}
	}

	return nil
}
