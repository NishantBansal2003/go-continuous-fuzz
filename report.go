package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// MasterEntry represents an entry in the master index HTML file.
type MasterEntry struct {
	PkgPath  string
	Target   string
	LinkFile string
}

// TargetHistory stores the historical coverage data for a fuzzing target.
type TargetHistory struct {
	Date       string
	Coverage   string
	ReportPath string
}

// TargetState keeps track of registered fuzzing targets.
type TargetState struct {
	PkgPath string
	Target  string
}

// TargetPkgReport holds all the state and configuration needed to generate,
// render, and manage the coverage report for a single fuzzing target within
// a package. It carries the execution context, logger, project and path
// information, and the computed output file location.
type TargetPkgReport struct {
	ctx            context.Context
	logger         *slog.Logger
	projectName    string
	pkg            string
	target         string
	reportDir      string
	reportHTMLPath string
}

// loadMasterState loads the master state from a JSON file at the given path.
// If the file does not exist, it returns an empty slice.
func loadMasterState(statePath string) ([]TargetState, error) {
	if _, err := os.Stat(statePath); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("cannot stat state file %q: %w",
			statePath, err)
	}

	stateData, err := os.ReadFile(statePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read state file %q: %w",
			statePath, err)
	}

	var states []TargetState
	if err := json.Unmarshal(stateData, &states); err != nil {
		return nil, fmt.Errorf("invalid JSON in state file %q: %w",
			statePath, err)
	}

	return states, nil
}

// saveMasterState saves the master state to a JSON file at the given path.
func saveMasterState(statePath string, states []TargetState) error {
	stateData, err := json.MarshalIndent(states, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize state: %w", err)
	}

	if err := os.WriteFile(statePath, stateData, 0644); err != nil {
		return fmt.Errorf("failed to write state file %q: %w",
			statePath, err)
	}

	return nil
}

// addToMaster adds a new package and target to the master list, regenerates the
// index.html report, and persists state changes.
func (r *TargetPkgReport) addToMaster() error {
	statePath := filepath.Join(r.reportDir, "state.json")

	// Load existing state
	states, err := loadMasterState(statePath)
	if err != nil {
		return fmt.Errorf("load master state from %q: %w", statePath,
			err)
	}

	// Check for existing target - skip if already present
	for _, s := range states {
		if s.PkgPath == r.pkg && s.Target == r.target {
			return nil
		}
	}

	// Append new target
	states = append(states, TargetState{r.pkg, r.target})
	sort.Slice(states, func(i, j int) bool {
		if states[i].PkgPath == states[j].PkgPath {
			return states[i].Target < states[j].Target
		}
		return states[i].PkgPath < states[j].PkgPath
	})

	if err := saveMasterState(statePath, states); err != nil {
		return fmt.Errorf("save master state to %q: %w", statePath, err)
	}

	// Generate index entries (index.html)
	entries := make([]MasterEntry, len(states))
	for i, s := range states {
		linkFile := fmt.Sprintf("%s_%s.html", s.PkgPath, s.Target)
		entries[i] = MasterEntry{s.PkgPath, s.Target, linkFile}
	}

	// Render master index template
	tmpl, err := template.New("master").Parse(masterHTML)
	if err != nil {
		return fmt.Errorf("parse master template: %w", err)
	}

	indexFilePath := filepath.Join(r.reportDir, "index.html")
	indexFile, err := os.Create(indexFilePath)
	if err != nil {
		return err
	}
	defer func() {
		if err := indexFile.Close(); err != nil {
			r.logger.Error("Failed to close index file", "error",
				err)
		}
	}()

	return tmpl.Execute(indexFile, struct {
		ProjectName string
		Entries     []MasterEntry
	}{r.projectName, entries})
}

// updateTarget updates the HTML report and JSON history file for a given
// fuzzing target.
func (r *TargetPkgReport) updateTarget(coverage string) error {
	// Build base filenames and paths
	baseName := fmt.Sprintf("%s_%s", r.pkg, r.target)
	jsonPath := filepath.Join(r.reportDir, "targets", baseName+".json")
	htmlPath := filepath.Join(r.reportDir, "targets", baseName+".html")

	// Load existing history
	var history []TargetHistory
	if historyData, err := os.ReadFile(jsonPath); err == nil {
		if err := json.Unmarshal(historyData, &history); err != nil {
			return fmt.Errorf("parse history JSON %q: %w", jsonPath,
				err)
		}
	}

	// Create new entry if needed
	currentDate := strings.TrimSuffix(filepath.Base(r.reportHTMLPath),
		".html")

	// Prepend a new entry only if there is no existing entry for the
	// current date
	if len(history) > 0 && history[0].Date == currentDate {
		return nil
	}

	newEntry := TargetHistory{
		Date:       currentDate,
		Coverage:   coverage,
		ReportPath: r.reportHTMLPath,
	}
	history = append([]TargetHistory{newEntry}, history...)

	// Save updated JSON history
	historyData, err := json.MarshalIndent(history, "", "  ")
	if err != nil {
		return fmt.Errorf("serialize history for %q: %w", jsonPath, err)
	}
	if err := os.WriteFile(jsonPath, historyData, 0644); err != nil {
		return fmt.Errorf("write history file %q: %w", jsonPath, err)
	}

	// Render updated target HTML report from template
	tmpl, err := template.New("target").Parse(targetHTML)
	if err != nil {
		return fmt.Errorf("parse target template: %w", err)
	}

	targetFile, err := os.Create(htmlPath)
	if err != nil {
		return err
	}
	defer func() {
		if err := targetFile.Close(); err != nil {
			r.logger.Error("Failed to close target file", "error",
				err)
		}
	}()

	return tmpl.Execute(targetFile, struct {
		Target  string
		History []TargetHistory
	}{r.target, history})
}

// updateReport runs the fuzz target’s tests with coverage, generates an HTML
// coverage report, and updates both the master index and the per-target history
func updateReport(ctx context.Context, pkg, target string, cfg *Config,
	logger *slog.Logger) error {

	// Determine the package and corpus paths.
	pkgPath := filepath.Join(cfg.Project.SrcDir, pkg)
	corpusSrc := filepath.Join(cfg.Project.CorpusDir, pkg, "testdata",
		"fuzz", target)
	corpusDst := filepath.Join(pkgPath, "testdata", "fuzz", target)

	// Copy any existing corpus files into the testdata directory.
	if err := copyCorpusFiles(corpusSrc, corpusDst, logger); err != nil {
		return fmt.Errorf("corpus copy failed: %w", err)
	}

	// Run `go test` for this target with coverage profiling enabled.
	testCmd := exec.CommandContext(ctx, "go", "test",
		fmt.Sprintf("-run=^%s$", target),
		"-coverprofile=coverage.out",
		"-covermode=count",
	)
	testCmd.Dir = pkgPath
	var stdout, stderr bytes.Buffer
	testCmd.Stdout = &stdout
	testCmd.Stderr = &stderr

	if err := testCmd.Run(); err != nil && ctx.Err() == nil {
		return fmt.Errorf("go test failed: %w\nStderr: %s", err,
			stderr.String())
	}

	// Parse the coverage percentage from the test output.
	coverageRe := regexp.MustCompile(`coverage:\s+([\d.]+)%`)
	matches := coverageRe.FindStringSubmatch(stdout.String())
	if len(matches) < 2 {
		return fmt.Errorf("coverage not found in output:\n%s",
			stdout.String())
	}
	coveragePct := matches[1]

	// Generate an HTML coverage report using `go tool cover`.
	targetReportDir := filepath.Join(cfg.Project.ReportDir, "targets",
		pkg, target)
	if err := EnsureDirExists(targetReportDir); err != nil {
		return fmt.Errorf("create report directory: %w", err)
	}

	htmlFileName := time.Now().Format("2006-01-02") + ".html"
	reportPath := filepath.Join(targetReportDir, htmlFileName)

	coverCmd := exec.CommandContext(ctx, "go", "tool", "cover",
		"-html=coverage.out", "-o", reportPath,
	)
	coverCmd.Dir = pkgPath
	stdout.Reset()
	stderr.Reset()
	coverCmd.Stdout = &stdout
	coverCmd.Stderr = &stderr

	if err := coverCmd.Run(); err != nil && ctx.Err() == nil {
		return fmt.Errorf("go cover failed: %w\nStderr: %s", err,
			stderr.String())
	}

	// Extract the repository name from the source URL and use it to set the
	// project name in the coverage reports.
	repo, err := extractRepo(cfg.Project.SrcRepo)
	if err != nil {
		return fmt.Errorf("unable to extract repository name: %w", err)
	}

	covReport := &TargetPkgReport{
		ctx:            ctx,
		logger:         logger,
		projectName:    repo,
		pkg:            pkg,
		target:         target,
		reportDir:      cfg.Project.ReportDir,
		reportHTMLPath: filepath.Join(pkg, target, htmlFileName),
	}

	// Update the master index (index.html).
	if err := covReport.addToMaster(); err != nil {
		return fmt.Errorf("index update failed: %w", err)
	}

	// Record this run in the target's history and regenerate its HTML.
	if err := covReport.updateTarget(coveragePct); err != nil {
		return fmt.Errorf("target history update failed: %w", err)
	}

	return nil
}

// copyCorpusFiles copies corpus files from source to destination directory.
func copyCorpusFiles(srcDir, dstDir string, logger *slog.Logger) error {
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		return fmt.Errorf("read corpus directory %q: %w", srcDir, err)
	}

	// Ensure destination directory exists
	if err := EnsureDirExists(dstDir); err != nil {
		return fmt.Errorf("ensure destination dir %q: %w", dstDir, err)
	}

	// Copy each file entry
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		srcPath := filepath.Join(srcDir, entry.Name())
		dstPath := filepath.Join(dstDir, entry.Name())

		// Copy the individual file
		if err := copyFile(srcPath, dstPath, logger); err != nil {
			return fmt.Errorf("copy %q to %q: %w", srcPath, dstPath,
				err)
		}
	}

	return nil
}

// copyFile copies the contents of a single file from source to destination path
func copyFile(srcFile, dstFile string, logger *slog.Logger) error {
	src, err := os.Open(srcFile)
	if err != nil {
		return fmt.Errorf("open source file %q: %w", srcFile, err)
	}
	defer func() {
		if err := src.Close(); err != nil {
			logger.Error("Failed to close file", "error", err)
		}
	}()

	dst, err := os.Create(dstFile)
	if err != nil {
		return fmt.Errorf("create destination file %q: %w", dstFile,
			err)
	}
	defer func() {
		if err := dst.Close(); err != nil {
			logger.Error("Failed to close file", "error", err)
		}
	}()

	_, err = io.Copy(dst, src)
	return err
}
