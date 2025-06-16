package container

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/go-continuous-fuzz/go-continuous-fuzz/config"
)

// ContainerCreateAndStart creates a Docker container with the specified
// configuration, starts it, and attaches to its logs. It returns the container
// ID and a reader for the container's combined stdout and stderr output.
func ContainerCreateAndStart(ctx context.Context, cli *client.Client,
	logger *slog.Logger, workDir, hostProjectPath, hostCorpusPath string,
	cmd []string) (string, io.ReadCloser, error) {

	// Prepare Docker container configuration and limit resources for the
	// container.
	containerConfig := &container.Config{
		Image:        config.ContainerImage,
		Cmd:          cmd,
		WorkingDir:   workDir,
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
			fmt.Sprintf("%s:%s", hostProjectPath,
				config.ContainerProjectPath),
			fmt.Sprintf("%s:%s", hostCorpusPath,
				config.ContainerCorpusPath),
		},
		Resources: container.Resources{
			Memory:   2 * 1024 * 1024 * 1024,
			NanoCPUs: 1_000_000_000,
		},
	}

	resp, err := cli.ContainerCreate(ctx, containerConfig, hostConfig, nil,
		nil, "")
	if err != nil {
		return "", nil,
			fmt.Errorf("failed to create fuzz container: %w", err)
	}

	if err := cli.ContainerStart(ctx, resp.ID,
		container.StartOptions{}); err != nil {
		return "", nil,
			fmt.Errorf("failed to start fuzz container: %w", err)
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
		return resp.ID, nil,
			fmt.Errorf("failed to attach to container logs: %w",
				err)
	}

	return resp.ID, logsReader, nil
}

// WaitForFuzzContainer waits for the specified Docker container to finish
// execution. It returns an error if the container exits with a non-zero status
// or if there is an error waiting for the container to finish.
func WaitForFuzzContainer(ctx context.Context, cli *client.Client,
	ID string) error {

	// Wait for the container to finish.
	statusCh, errCh := cli.ContainerWait(ctx, ID,
		container.WaitConditionNotRunning)

	select {
	case err := <-errCh:
		return fmt.Errorf("error waiting for fuzz container: %w", err)
	case status := <-statusCh:
		if status.StatusCode != 0 {
			return fmt.Errorf("fuzz container exited with "+
				"status %d", status.StatusCode)
		}
	}

	return nil
}

// StopContainer attempts to gracefully stop the specified Docker container by
// its ID.
func StopContainer(cli *client.Client, logger *slog.Logger, ID string) {
	if err := cli.ContainerStop(context.Background(), ID,
		container.StopOptions{}); err != nil {
		logger.Error("Failed to stop container", "error", err,
			"containerID", ID)
	}
}
