package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
)

// MeasureCoverage runs the fuzz target once per corpus file and returns
// the best observed coverage metric.
func MeasureCoverage(ctx context.Context, logger *slog.Logger, pkgDir,
	corpusDir, target string) (int, error) {

	// Gather existing corpus files to size the fuzz run
	corpusTargetDir := filepath.Join(corpusDir, target)
	files, err := os.ReadDir(corpusTargetDir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("reading corpus dir: %w", err)
	}

	// Build and run the fuzz command
	fuzzCmd := []string{"test",
		fmt.Sprintf("-run=^%s$", target),
		fmt.Sprintf("-fuzz=^%s$", target),
		fmt.Sprintf("-fuzztime=%dx", len(files)),
		fmt.Sprintf("-test.fuzzcachedir=%s", corpusDir),
	}
	output, err := runGoCommand(ctx, pkgDir, fuzzCmd, "GODEBUG=fuzzdebug=1")
	if err != nil {
		return 0, fmt.Errorf("go test failed for %q: %w ", pkgDir, err)
	}

	// Extract coverage from output
	coverageRe := regexp.MustCompile(`initial coverage bits:\s+([0-9]+)$`)
	matches := coverageRe.FindStringSubmatch(output)
	if len(matches) < 2 {
		return 0, fmt.Errorf("coverage not found in output:\n%s",
			output)
	}

	coverage, err := strconv.Atoi(matches[1])
	if err != nil {
		return 0, fmt.Errorf("parsing coverage: %w", err)
	}

	return coverage, nil
}

// MinimizeCorpus prunes unnecessary seed inputs while preserving max coverage.
func MinimizeCorpus(ctx context.Context, cfg *Config, logger *slog.Logger,
	pkgDir, corpusDir, target string) error {

	// Clean the testdata seed directory.
	fuzzTestDataDir := filepath.Join(pkgDir, "testdata", "fuzz", target)
	if err := os.RemoveAll(fuzzTestDataDir); err != nil {
		return fmt.Errorf("removing testdata: %w", err)
	}

	cacheDir, err := os.MkdirTemp("", "go-continuous-fuzz-cache-")
	if err != nil {
		return fmt.Errorf("creating temp cache dir: %w", err)
	}
	defer func() {
		if err := os.RemoveAll(cacheDir); err != nil {
			logger.Error("Failed to remove file", "error", err)
		}
	}()

	cacheCorpusDir := filepath.Join(cacheDir, target)
	if err := os.MkdirAll(cacheCorpusDir, 0755); err != nil {
		return fmt.Errorf("creating cache corpus dir: %w", err)
	}

	// Read and sort existing corpus files by size ascending
	corpusTargetDir := filepath.Join(corpusDir, target)
	entries, err := os.ReadDir(corpusTargetDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("reading corpus dir: %w", err)
	}
	sort.Slice(entries, func(i, j int) bool {
		fi, err1 := entries[i].Info()
		fj, err2 := entries[j].Info()
		if err1 != nil || err2 != nil {
			return false
		}
		return fi.Size() < fj.Size()
	})

	bestCoverage := 0
	removedCount := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		srcPath := filepath.Join(corpusTargetDir, entry.Name())
		dstPath := filepath.Join(cacheCorpusDir, entry.Name())
		if err := copyFile(srcPath, dstPath, logger); err != nil {
			return fmt.Errorf("copy %q to cache: %w", srcPath, err)
		}

		newcoverage, err := MeasureCoverage(ctx, logger, pkgDir,
			cacheCorpusDir, target)
		if err != nil {
			return fmt.Errorf("measuring base coverage: %w", err)
		}

		if newcoverage > bestCoverage {
			bestCoverage = newcoverage
			continue
		}

		if newcoverage < bestCoverage {
			logger.Warn("nondeterministic fuzz target: coverage "+
				"decreased", "file", entry.Name(),
				"oldCoverage", bestCoverage, "newCoverage",
				newcoverage)
		}

		if err := os.Remove(srcPath); err != nil {
			return fmt.Errorf("remove %q: %w", srcPath, err)
		}
		if err := os.Remove(dstPath); err != nil {
			return fmt.Errorf("remove %q: %w", dstPath, err)
		}
		removedCount++
	}

	logger.Info("corpus minimization complete", "removedCount",
		removedCount, "finalCoverage", bestCoverage)
	return nil
}
