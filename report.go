package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
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

// loadMasterState loads the master state from a JSON file at the given path.
// If the file does not exist, it returns an empty slice.
func loadMasterState(statePath string) ([]TargetState, error) {
	if _, err := os.Stat(statePath); os.IsNotExist(err) {
		return nil, nil
	}
	stateData, err := os.ReadFile(statePath)
	if err != nil {
		return nil, err
	}
	var states []TargetState
	if err := json.Unmarshal(stateData, &states); err != nil {
		return nil, err
	}
	return states, nil
}

// saveMasterState saves the master state to a JSON file at the given path.
func saveMasterState(statePath string, states []TargetState) error {
	stateData, err := json.MarshalIndent(states, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(statePath, stateData, 0644)
}

// addToMaster adds a new package and target to the master list, regenerates the
// index.html report, and persists state changes.
func addToMaster(pkgPath, target string, cfg *Config) error {
	statePath := filepath.Join(cfg.Project.ReportDir, "state.json")
	states, err := loadMasterState(statePath)
	if err != nil {
		return err
	}

	// Check for existing target
	for _, s := range states {
		if s.PkgPath == pkgPath && s.Target == target {
			// Already registered
			return nil
		}
	}

	// Append new target
	states = append(states, TargetState{pkgPath, target})
	sort.Slice(states, func(i, j int) bool {
		if states[i].PkgPath == states[j].PkgPath {
			return states[i].Target < states[j].Target
		}
		return states[i].PkgPath < states[j].PkgPath
	})

	if err := saveMasterState(statePath, states); err != nil {
		return err
	}

	// Generate index entries (index.html)
	entries := make([]MasterEntry, len(states))
	for i, s := range states {
		linkFile := fmt.Sprintf("%s_%s.html", s.PkgPath, s.Target)
		entries[i] = MasterEntry{s.PkgPath, s.Target, linkFile}
	}

	// Render master index
	tmpl := template.Must(template.New("master").Parse(masterHTML))
	indexFilePath := filepath.Join(cfg.Project.ReportDir, "index.html")
	indexFile, err := os.Create(indexFilePath)
	if err != nil {
		return err
	}
	defer indexFile.Close()

	return tmpl.Execute(indexFile, struct {
		ProjectName string
		Entries     []MasterEntry
	}{cfg.Project.SrcRepo, entries})
}

// updateTarget updates the HTML report and JSON history file for a given
// fuzzing target.
func updateTarget(pkgPath, target, coverage string, cfg *Config) error {
	// Generate filenames
	baseName := fmt.Sprintf("%s_%s", pkgPath, target)
	jsonPath := filepath.Join(cfg.Project.ReportDir, "targets", baseName+
		".json")
	htmlPath := filepath.Join(cfg.Project.ReportDir, "targets", baseName+
		".html")

	// Load existing history
	var history []TargetHistory
	if historyData, err := os.ReadFile(jsonPath); err == nil {
		if err := json.Unmarshal(historyData, &history); err != nil {
			return err
		}
	}

	// Create new entry if needed
	currentDate := time.Now().Format("2006-01-02")
	reportHTMLPath := filepath.Join(pkgPath, target, currentDate+".html")

	// Prepend a new entry only if there is no existing entry for the
	// current date
	if len(history) == 0 || history[0].Date != currentDate {
		newEntry := TargetHistory{
			Date:       currentDate,
			Coverage:   coverage,
			ReportPath: reportHTMLPath,
		}
		history = append([]TargetHistory{newEntry}, history...)

		// Save updated JSON history
		historyData, err := json.MarshalIndent(history, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(jsonPath, historyData, 0644); err !=
			nil {

			return err
		}
	}

	// Render target history HTML
	tmpl := template.Must(template.New("target").Parse(targetHTML))
	targetFile, err := os.Create(htmlPath)
	if err != nil {
		return err
	}
	defer targetFile.Close()

	return tmpl.Execute(targetFile, struct {
		Target  string
		History []TargetHistory
	}{target, history})
}

// updateReport runs tests, captures coverage, and updates reports for a target.
func updateReport(pkg, target string, cfg *Config) error {
	ctx := context.Background()

	// Construct the absolute path to the package directory within the
	// temporary project directory.
	pkgPath := filepath.Join(cfg.Project.SrcDir, pkg)

	// Prepare corpus directories
	corpusPath := filepath.Join(cfg.Project.CorpusDir, pkg, "testdata",
		"fuzz", target)
	pkgCorpusPath := filepath.Join(pkgPath, "testdata", "fuzz", target)

	if err := copyCorpusFiles(corpusPath, pkgCorpusPath); err != nil {
		return fmt.Errorf("corpus copy failed: %w", err)
	}

	// Run tests with coverage
	testCmd := exec.CommandContext(ctx, "go", "test",
		fmt.Sprintf("-run=^%s$", target),
		"-coverprofile=coverage.out",
		"-covermode=count",
	)
	testCmd.Dir = pkgPath

	var stdoutBuf, stderrBuf bytes.Buffer
	testCmd.Stdout = &stdoutBuf
	testCmd.Stderr = &stderrBuf

	if err := testCmd.Run(); err != nil && ctx.Err() == nil {
		return fmt.Errorf("go test failed: %w\nStderr: %s", err,
			stderrBuf.String())
	}

	// Extract coverage percentage
	output := stdoutBuf.String()
	coverageRe := regexp.MustCompile(`coverage:\s+([\d.]+)%`)
	matches := coverageRe.FindStringSubmatch(output)
	if len(matches) < 2 {
		return fmt.Errorf("coverage not found in output:\n%s", output)
	}
	coveragePct := matches[1]

	// Generate coverage report
	targetReportDir := filepath.Join(cfg.Project.ReportDir, "targets",
		pkg, target)
	if err := EnsureDirExists(targetReportDir); err != nil {
		return fmt.Errorf("report dir creation failed: %w", err)
	}

	reportPath := filepath.Join(targetReportDir,
		time.Now().Format("2006-01-02")+".html")
	coverCmd := exec.CommandContext(ctx, "go", "tool", "cover",
		"-html=coverage.out",
		"-o", reportPath,
	)
	coverCmd.Dir = pkgPath
	coverCmd.Stdout = &stdoutBuf
	coverCmd.Stderr = &stderrBuf

	if err := coverCmd.Run(); err != nil && ctx.Err() == nil {
		return fmt.Errorf("go cover failed: %w\nStderr: %s", err,
			stderrBuf.String())
	}

	// Update indexes
	if err := addToMaster(pkg, target, cfg); err != nil {
		return fmt.Errorf("index update failed: %w", err)
	}

	if err := updateTarget(pkg, target, coveragePct, cfg); err != nil {
		return fmt.Errorf("target history update failed: %w", err)
	}

	return nil
}

// copyCorpusFiles copies corpus files from source to destination directory.
func copyCorpusFiles(srcDir, dstDir string) error {
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		return err
	}

	// Ensure destination directory exists
	if err := EnsureDirExists(dstDir); err != nil {
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		srcPath := filepath.Join(srcDir, entry.Name())
		dstPath := filepath.Join(dstDir, entry.Name())

		if err := copyFile(srcPath, dstPath); err != nil {
			return err
		}
	}

	return nil
}

// copyFile copies a single file from source to destination path.
func copyFile(srcFile, dstFile string) error {
	src, err := os.Open(srcFile)
	if err != nil {
		return err
	}
	defer src.Close()

	dst, err := os.Create(dstFile)
	if err != nil {
		return err
	}
	defer dst.Close()

	_, err = io.Copy(dst, src)
	return err
}
