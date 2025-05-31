package main

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	// fuzzFailureRegex matches lines indicating a fuzzing failure or a
	// failing input, capturing the fuzz target name and the corresponding
	// input ID.
	//
	// It matches lines like:
	//   "failure while testing seed corpus entry: FuzzFoo/771e938e4458e983"
	//   "Failing input written to testdata/fuzz/FuzzFoo/771e938e4458e983"
	//
	// Captured groups:
	//   - "target": the fuzz target name (e.g., "FuzzFoo")
	//   - "id": the hexadecimal input ID (e.g., "771e938e4458e983")
	fuzzFailureRegex = regexp.MustCompile(
		`(?:failure while testing seed corpus entry:\s*|Failing ` +
			`input written to\s*testdata/fuzz/)` +
			`(?P<target>[^/]+)/(?P<id>[0-9a-f]+)`,
	)
)

// fuzzOutputProcessor handles parsing and logging of fuzzing output streams,
// detecting failures, and capturing/logging failing input data.
type fuzzOutputProcessor struct {
	// Logger for informational and error messages.
	logger *slog.Logger

	// Configuration settings provided by the user
	cfg *Config

	// Directory containing the fuzzing corpus.
	corpusDir string

	// Name of the fuzz target under test.
	targetName string

	// File handle for writing failure logs.
	logFile *os.File
}

// NewFuzzOutputProcessor constructs a fuzzOutputProcessor for the given logger,
// config, corpus directory, and fuzz target name.
func NewFuzzOutputProcessor(logger *slog.Logger, cfg *Config,
	corpusDir string, targetName string) *fuzzOutputProcessor {

	return &fuzzOutputProcessor{
		logger:     logger,
		cfg:        cfg,
		corpusDir:  corpusDir,
		targetName: targetName,
	}
}

// processFuzzStream reads each line from the fuzzing output stream, logs all
// lines, and captures failure details if a failure is detected. Returns true if
// a failure was found and processed, false otherwise.
func (fp *fuzzOutputProcessor) processFuzzStream(stream io.Reader) bool {
	scanner := bufio.NewScanner(stream)

	// Scan until a failure line is found; if not found, return false.
	if !fp.scanUntilFailure(scanner) {
		return false
	}

	// Process and log failure lines, capturing error data.
	fp.processFailureLines(scanner)

	return true
}

// scanUntilFailure scans the output until a failure indicator (--- FAIL:) is
// found. Returns true if a failure line is detected, false otherwise.
func (fp *fuzzOutputProcessor) scanUntilFailure(scanner *bufio.Scanner) bool {
	for scanner.Scan() {
		line := scanner.Text()
		fp.logger.Info("Fuzzer output", "message", line)

		// Detect the start of a failure section.
		if strings.Contains(line, "--- FAIL:") {
			return true
		}
	}
	return false
}

// processFailureLines processes lines after a failure is detected, writes them
// to a log file, and attempts to extract and log the failing input data.
func (fp *fuzzOutputProcessor) processFailureLines(scanner *bufio.Scanner) {
	// Construct the log file path for storing failure details.
	logFileName := fmt.Sprintf("%s_failure.log", fp.targetName)
	logPath := filepath.Join(fp.cfg.FuzzResultsPath, logFileName)

	// Ensure the results directory exists.
	if err := EnsureDirExists(fp.cfg.FuzzResultsPath); err != nil {
		fp.logger.Error("Failed to create fuzz results directory",
			"error", err)
		return
	}

	// Create the log file for writing.
	logFile, err := os.Create(logPath)
	if err != nil {
		fp.logger.Error("Failed to create log file", "error", err)
		return
	}
	fp.logFile = logFile

	// Ensure the log file is closed at the end.
	defer func() {
		if err := fp.logFile.Close(); err != nil {
			fp.logger.Error("Failed to close log file", "error",
				err)
		}
	}()

	fp.logger.Info("Failure log initialized", "path", logPath)

	var errorData string

	for scanner.Scan() {
		line := scanner.Text()
		fp.logger.Info("Fuzzer output", "message", line)

		// Write the current line to the failure log file.
		_, err = fp.logFile.WriteString(line + "\n")
		if err != nil {
			fp.logger.Error("Failed to write log line", "error",
				err)
			return
		}

		// If error data has already been captured, skip further
		// extraction.
		if errorData != "" {
			continue
		}

		// Parse the line to extract the fuzz target and ID (hex) of the
		// failing input.
		// When a fuzz target encounters a failure during f.Add, the
		// crash is printed, but no input is saved to testdata/fuzz.
		//
		// The log output typically appears as:
		//   failure while testing seed corpus entry: FuzzFoo/seed#0
		//
		// As a result, no error data will be printed.
		target, id := parseFailureLine(line)
		// If either target or ID is empty, skip further processing.
		if target == "" || id == "" {
			continue
		}

		// Read and store the input data associated with the failing
		// target and ID.
		errorData = fp.readFailingInput(target, id)
	}

	// Write the error data (if any) to the log file.
	if errorData != "" {
		_, err = fp.logFile.WriteString(errorData + "\n")
		if err != nil {
			fp.logger.Error("Failed to write error data", "error",
				err)
			return
		}
	}
}

// parseFailureLine attempts to extract the fuzz target name and input ID
// from a line of fuzzing output. It uses a predefined regular expression
// to match lines that indicate a failure, capturing the relevant details
// if the line conforms to the expected format.
func parseFailureLine(line string) (string, string) {
	// Apply the regular expression to the line to find matches
	matches := fuzzFailureRegex.FindStringSubmatch(line)

	// Return empty strings if no match is found
	if matches == nil {
		return "", ""
	}

	var target, id string
	// Iterate over the named subexpressions to assign values of fuzz target
	// and id.
	for i, name := range fuzzFailureRegex.SubexpNames() {
		switch name {
		case "target":
			target = matches[i]
		case "id":
			id = matches[i]
		}
	}
	return target, id
}

// readFailingInput attempts to read the failing input file from the corpus
// directory.Returns the file contents or a placeholder string if reading fails.
func (fp *fuzzOutputProcessor) readFailingInput(target, id string) string {
	// Construct the path to the failing input file.
	failingInputPath := filepath.Join(target, id)
	inputPath := filepath.Join(fp.corpusDir, failingInputPath)

	// Attempt to read the file contents.
	data, err := os.ReadFile(inputPath)
	if err != nil {
		// If reading fails, return a placeholder string indicating the
		// failure.
		return fmt.Sprintf("\n<< failed to read %s: %v >>\n",
			failingInputPath, err)
	}

	// If reading succeeds, format the content with a header indicating it's
	// a failing test case.
	return fmt.Sprintf("\n\n=== Failing testcase (%s) ===\n%s",
		failingInputPath, data)
}
