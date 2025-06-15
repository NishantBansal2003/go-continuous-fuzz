package fuzz

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/go-continuous-fuzz/go-continuous-fuzz/config"
	"github.com/go-continuous-fuzz/go-continuous-fuzz/parser"
)

// ListFuzzTargets discovers and returns a list of fuzz targets for the given
// package. It uses "go test -list=^Fuzz" to list the functions and filters
// those that start with "Fuzz".
func ListFuzzTargets(ctx context.Context, logger *slog.Logger,
	cfg *config.Config, pkg string) ([]string, error) {

	logger.Info("Discovering fuzz targets", "package", pkg)

	// Construct the absolute path to the package directory within the
	// temporary project directory.
	pkgPath := filepath.Join(cfg.Project.SrcDir, pkg)

	// Prepare the command to list all test functions matching the pattern
	// "^Fuzz". This leverages go's testing tool to identify fuzz targets.
	cmd := exec.CommandContext(ctx, "go", "test", "-list=^Fuzz", ".")

	// Set the working directory to the package path.
	cmd.Dir = pkgPath

	// Initialize buffers to capture standard output and standard error from
	// the command execution.
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Execute the command and check for errors, when the context wasn't
	// canceled.
	if err := cmd.Run(); err != nil && ctx.Err() == nil {
		return nil, fmt.Errorf("go test failed for %q: %w (output: %q)",
			pkg, err, strings.TrimSpace(stderr.String()))
	}

	// targets holds the names of discovered fuzz targets.
	var targets []string

	// Process each line of the command's output.
	for _, line := range strings.Split(stdout.String(), "\n") {
		cleanLine := strings.TrimSpace(line)
		if strings.HasPrefix(cleanLine, "Fuzz") {
			// If the line represents a fuzz target, add it to the
			// list.
			targets = append(targets, cleanLine)
		}
	}

	// If no fuzz targets are found, log a warning to inform the user.
	if len(targets) == 0 {
		logger.Warn("No valid fuzz targets found", "package", pkg)
	}

	return targets, nil
}

// ExecuteFuzzTarget runs the specified fuzz target for a package for a given
// duration using Docker. It sets up the environment, starts the container,
// streams output, and logs any failures to a log file.
func ExecuteFuzzTarget(ctx context.Context, logger *slog.Logger, pkg string,
	target string, cfg *config.Config, fuzzTime time.Duration,
	cli *client.Client) error {

	logger.Info("Executing fuzz target in Docker", "package", pkg, "target",
		target, "duration", fuzzTime)

	// Absolute path to the package directory on the host machine.
	hostPkgPath := filepath.Join(cfg.Project.SrcDir, pkg)

	// Path on the host where fuzz-generated corpus data is stored.
	hostCorpusPath := filepath.Join(cfg.Project.CorpusPath, pkg, "testdata",
		"fuzz")

	// Root directory for the project inside the container.
	containerProjectRoot := "/app"

	// Path to the package directory inside the container.
	containerPkgPath := filepath.Join(containerProjectRoot, pkg)

	// Directory inside the container used for the fuzz corpus.
	containerCorpusPath := "/corpus"

	// Path on the host where failing corpus inputs may be saved by the fuzz
	// process.
	maybeFailingCorpusPath := filepath.Join(hostPkgPath, "testdata", "fuzz")

	// Prepare the arguments for the 'go test' command to run the specific
	// fuzz target in container.
	goTestCmd := []string{
		"go", "test",
		fmt.Sprintf("-fuzz=^%s$", target),
		fmt.Sprintf("-test.fuzzcachedir=%s", containerCorpusPath),
		fmt.Sprintf("-fuzztime=%s", fuzzTime),
		"-parallel=1",
	}

	// Prepare Docker container configuration and limit resources for the
	// container.
	containerConfig := &container.Config{
		Image:        config.ContainerImage,
		Cmd:          goTestCmd,
		WorkingDir:   containerPkgPath,
		User:         fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()),
		AttachStdout: true,
		AttachStderr: true,
		Tty:          true,
		Env: []string{
			"GOCACHE=/tmp",
		},
	}
	hostConfig := &container.HostConfig{
		AutoRemove: true,
		Binds: []string{
			fmt.Sprintf("%s:%s", cfg.Project.SrcDir,
				containerProjectRoot),
			fmt.Sprintf("%s:%s", hostCorpusPath,
				containerCorpusPath),
		},
		Resources: container.Resources{
			Memory:   2 * 1024 * 1024 * 1024,
			NanoCPUs: 1_000_000_000,
		},
	}

	resp, err := cli.ContainerCreate(ctx, containerConfig, hostConfig, nil,
		nil, "")
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return fmt.Errorf("failed to create fuzz container: %w", err)
	}
	defer func() {
		if err := cli.ContainerStop(context.Background(), resp.ID,
			container.StopOptions{}); err != nil {
			logger.Error("Failed to stop container", "error", err,
				"containerID", resp.ID)
		}
	}()

	if err := cli.ContainerStart(ctx, resp.ID,
		container.StartOptions{}); err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return fmt.Errorf("failed to start fuzz container: %w", err)
	}

	// Attach to logs after starting container
	logsReader, err := cli.ContainerLogs(ctx, resp.ID,
		container.LogsOptions{
			ShowStdout: true,
			ShowStderr: true,
			Follow:     true,
			Timestamps: false,
		})
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return fmt.Errorf("failed to attach to container logs: %w", err)
	}
	defer func() {
		_ = logsReader.Close()
	}()

	// Stream and process the standard output, which may include both stdout
	// and stderr content.
	processor := parser.NewFuzzOutputProcessor(
		logger.With("target", target).With("package", pkg),
		cfg, maybeFailingCorpusPath, target,
	)
	isFailing := processor.ProcessFuzzStream(logsReader)

	// Wait for the container to finish.
	statusCh, errCh := cli.ContainerWait(ctx, resp.ID,
		container.WaitConditionNotRunning)

	// Proceed to return an error only if the fuzz target did not fail
	// (i.e., no failure was detected during fuzzing), and the command
	// execution resulted in an error, and the error is not due to a
	// cancellation of the context.
	select {
	case err := <-errCh:
		if ctx.Err() != nil {
			return nil
		}
		return fmt.Errorf("error waiting for fuzz container: %w", err)
	case status := <-statusCh:
		if status.StatusCode != 0 && !isFailing {
			return fmt.Errorf("fuzz container exited with "+
				"status %d", status.StatusCode)
		}
	}

	// If the fuzz target fails, 'go test' saves the failing input in the
	// package's testdata/fuzz/<FuzzTestName> directory. To prevent these
	// saved inputs from causing subsequent test runs to fail (especially
	// when running other fuzz targets), we remove the testdata directory to
	// clean up the failing inputs.
	if isFailing {
		failingInputPath := filepath.Join(hostPkgPath, "testdata",
			"fuzz", target)
		if err := os.RemoveAll(failingInputPath); err != nil {
			return fmt.Errorf("failing input cleanup failed: %w",
				err)
		}
	}

	logger.Info("Fuzzing in Docker completed successfully", "package", pkg,
		"target", target)

	return nil
}
