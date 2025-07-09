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
	"strings"
	"time"
)

type MasterEntry struct {
	PkgPath  string
	Target   string
	LinkFile string
}

type TargetHistory struct {
	Date       string
	Coverage   string
	ReportPath string
}

type TargetState struct {
	PkgPath string
	Target  string
}

// load or initialize state.json
func loadMasterState(path string) ([]TargetState, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var st []TargetState
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, err
	}
	return st, nil
}

func saveMasterState(path string, st []TargetState) error {
	b, _ := json.MarshalIndent(st, "", "  ")
	return os.WriteFile(path, b, 0644)
}

func addToMaster(pkgPath, target string, projectName string, cfg *Config) error {
	statePath := filepath.Join(cfg.Project.ReportDir, "state.json")
	state, err := loadMasterState(statePath)
	if err != nil {
		return err
	}
	// check if exists
	for _, s := range state {
		if s.PkgPath == pkgPath && s.Target == target {
			return nil // already in master
		}
	}

	// append
	state = append(state, TargetState{pkgPath, target})
	// Sort by PkgPath, then by Target
	sort.Slice(state, func(i, j int) bool {
		if state[i].PkgPath == state[j].PkgPath {
			return state[i].Target < state[j].Target
		}
		return state[i].PkgPath < state[j].PkgPath
	})
	if err := saveMasterState(statePath, state); err != nil {
		return err
	}

	// regenerate index.html
	entries := make([]MasterEntry, len(state))
	for i, s := range state {
		linkFile := fmt.Sprintf("%s_%s.html",
			filepath.Base(s.PkgPath), s.Target)
		entries[i] = MasterEntry{s.PkgPath, s.Target, linkFile}
	}
	tmpl := template.Must(template.New("master").Parse(masterHTML))
	f, err := os.Create(filepath.Join(cfg.Project.ReportDir, "index.html"))
	if err != nil {
		return err
	}
	defer f.Close()

	return tmpl.Execute(f, struct {
		ProjectName string
		Entries     []MasterEntry
	}{
		ProjectName: projectName,
		Entries:     entries,
	})
}

// update a specific target’s history and HTML
func updateTarget(pkgPath, target, coverage string, cfg *Config) error {
	// build file names
	base := fmt.Sprintf("%s_%s", filepath.Base(pkgPath), target)
	jsonPath := filepath.Join(cfg.Project.ReportDir, "targets", base+".json")
	htmlPath := filepath.Join(cfg.Project.ReportDir, "targets", base+".html")

	// load existing history
	var hist []TargetHistory
	if b, err := os.ReadFile(jsonPath); err == nil {
		json.Unmarshal(b, &hist)
	}
	today := time.Now().Format("2006-01-02_15-04")
	reportHTMLPath := filepath.Join(filepath.Base(pkgPath), target,
		today+".html")

	// only prepend if no entry for today
	// if len(hist) == 0 || hist[0].Date != today {
	newEntry := TargetHistory{
		Date:       today,
		Coverage:   coverage,
		ReportPath: reportHTMLPath,
	}
	hist = append(
		[]TargetHistory{newEntry},
		hist...,
	)
	// save JSON
	b, _ := json.MarshalIndent(hist, "", "  ")
	os.WriteFile(jsonPath, b, 0644)
	// }

	// regenerate target HTML
	tmpl := template.Must(template.New("target").Parse(targetHTML))
	f, err := os.Create(htmlPath)
	if err != nil {
		return err
	}
	defer f.Close()
	return tmpl.Execute(f, struct {
		Target  string
		History []TargetHistory
	}{target, hist})
}

func updateReport(pkg, target string, cfg *Config) error {
	ctx := context.Background()

	// Construct the absolute path to the package directory within the
	// temporary project directory.
	pkgPath := filepath.Join(cfg.Project.SrcDir, pkg)

	// Define the path to store the corpus data generated during fuzzing.
	corpusPath := filepath.Join(cfg.Project.CorpusPath, pkg, "testdata",
		"fuzz", target)

	pkgCorpusPath := filepath.Join(pkgPath, "testdata", "fuzz", target)
	EnsureDirExists(pkgCorpusPath)

	copyCorpusFiles(corpusPath, pkgCorpusPath)

	args := []string{
		"test",
		fmt.Sprintf("-run=^%s$", target),
		"-coverprofile=coverage.out",
		"-covermode=count",
	}

	// Initialize the 'go test' command with the specified arguments and
	// context.
	cmd := exec.CommandContext(ctx, "go", args...)
	// Set the working directory for the command.
	cmd.Dir = pkgPath

	// Initialize buffers to capture standard output and standard error from
	// the command execution.
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Execute the command and check for errors, when the context wasn't
	// canceled.
	if err := cmd.Run(); err != nil && ctx.Err() == nil {
		return fmt.Errorf("go test failed for %q: %w (output: %q)",
			pkg, err, strings.TrimSpace(stderr.String()))
	}

	// Extract coverage from stdout
	output := stdout.String()
	re := regexp.MustCompile(`coverage:\s+([\d.]+)%`)
	matches := re.FindStringSubmatch(output)

	if len(matches) < 2 {
		return fmt.Errorf("coverage percentage not found in output:\n%s",
			output)
	}

	coverage := matches[1]
	EnsureDirExists(filepath.Join(cfg.Project.ReportDir,
		"targets", pkg, target))

	args = []string{
		"tool",
		"cover",
		"-html=coverage.out",
		"-o",
		fmt.Sprintf("%s", filepath.Join(cfg.Project.ReportDir,
			"targets", pkg, target,
			time.Now().Format("2006-01-02_15-04")+".html")),
	}
	// Initialize the 'go test' command with the specified arguments and
	// context.
	cmd = exec.CommandContext(ctx, "go", args...)
	// Set the working directory for the command.
	cmd.Dir = pkgPath

	// Execute the command and check for errors, when the context wasn't
	// canceled.
	if err := cmd.Run(); err != nil && ctx.Err() == nil {
		return fmt.Errorf("go test failed for %q: %w (output: %q)",
			pkg, err, strings.TrimSpace(stderr.String()))
	}

	if err := addToMaster(pkg, target, "Go Fuzzing example", cfg); err != nil {
		return err
	}

	if err := updateTarget(pkg, target, coverage, cfg); err != nil {
		return err
	}

	return nil
}

func copyCorpusFiles(srcDir, dstDir string) error {
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		return err
	}

	// Ensure destination directory exists
	if err := os.MkdirAll(dstDir, 0755); err != nil {
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue // Skip subdirectories (if any accidentally exist)
		}

		srcPath := filepath.Join(srcDir, entry.Name())
		dstPath := filepath.Join(dstDir, entry.Name())

		if err := copyFile(srcPath, dstPath); err != nil {
			return err
		}
	}

	return nil
}

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
