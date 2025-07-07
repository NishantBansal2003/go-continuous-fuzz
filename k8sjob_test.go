package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// TestKubernetesRace verifies that the k8s client is safe for concurrent use
// by launching two jobs in parallel. It ensures that concurrent operations on a
// shared k8s client do not cause data races or unexpected errors.
func TestKubernetesRace(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// Create a temporary workspace for container mounts.
	tmpDir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Set up Kubernetes client for spawning fuzzing jobs.
	config, err := rest.InClusterConfig()
	assert.NoError(t, err)
	clientset, err := kubernetes.NewForConfig(config)
	assert.NoError(t, err)

	const timeout = 15 * time.Second

	// Run two containers concurrently to test for races.
	for i := 1; i <= 2; i++ {
		t.Run(fmt.Sprintf("container-%d", i), func(t *testing.T) {
			t.Parallel()

			taskCtx, taskCancel := context.WithTimeout(ctx, timeout)
			defer taskCancel()

			k8sJob := &K8sJob{
				ctx:       taskCtx,
				logger:    logger,
				clientset: clientset,
				cfg: &Config{
					Project: Project{
						SrcDir: tmpDir,
					},
				},
				workDir:        tmpDir,
				cmd:            []string{"sleep", "infinity"},
			}

			id, err := k8sJob.Start()
			assert.NoError(t, err)
			defer k8sJob.Stop(id)

			errorChan := make(chan error, 1)

			// Start processing logs and wait for completion/failure
			// signal in a goroutine.
			go k8sJob.WaitAndGetLogs(id, "", "", nil, errorChan)

			select {
			case <-taskCtx.Done():
				// This is the expected path: the context
				// timeout.

			case err := <-errorChan:
				assert.NoError(t, err)
			}
		})
	}
}
