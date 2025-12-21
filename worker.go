package main

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/docker/docker/client"
	"golang.org/x/sync/errgroup"
	"k8s.io/client-go/kubernetes"
)

// FuzzRunner abstracts Kubernetes or Docker fuzz execution
type FuzzRunner interface {
	Start() (string, error)
	Stop(ID string) error
	WaitAndGetLogs(ID string, pkg string, target string,
		fuzzCrashChan chan fuzzCrash, errChan chan error)
}

// Task represents a single fuzz target job, containing the package path and the
// specific target name to execute.
type Task struct {
	PackagePath string
	Target      string
}

// TaskQueue is a simple FIFO queue for scheduling Task items.
type TaskQueue struct {
	mu    sync.Mutex
	tasks []Task
}

// NewTaskQueue returns an empty, initialized TaskQueue.
func NewTaskQueue() *TaskQueue {
	return &TaskQueue{
		tasks: make([]Task, 0),
	}
}

// Enqueue adds a new Task to the back of the queue.
func (q *TaskQueue) Enqueue(t Task) {
	q.mu.Lock()
	defer q.mu.Unlock()

	q.tasks = append(q.tasks, t)
}

// Length returns the current number of tasks in the queue.
func (q *TaskQueue) Length() int {
	q.mu.Lock()
	defer q.mu.Unlock()

	return len(q.tasks)
}

// Dequeue removes and returns the next Task from the queue. If the queue is
// empty, it returns false for the second return value.
func (q *TaskQueue) Dequeue() (Task, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()

	if len(q.tasks) == 0 {
		return Task{}, false
	}
	t := q.tasks[0]
	q.tasks = q.tasks[1:]
	return t, true
}

// WorkerGroup manages a group of fuzzing workers, their context, logger, Docker
// or Kubernetes client, configuration, shared task queue, per-task timeout, and
// if corpus should be minimized or not.
type WorkerGroup struct {
	ctx                  context.Context
	logger               *slog.Logger
	goGroup              *errgroup.Group
	dockerClient         *client.Client
	k8sClientSet         *kubernetes.Clientset
	cfg                  *Config
	taskQueue            *TaskQueue
	taskTimeout          time.Duration
	shouldMinimizeCorpus bool
}

// WorkersStartAndWait starts the specified number of workers and waits for all
// to finish or for the first error/cancellation. Returns an error if any worker
// fails.
func (wg *WorkerGroup) WorkersStartAndWait(numWorkers int) error {
	for workerID := 1; workerID <= numWorkers; workerID++ {
		wg.goGroup.Go(func() error {
			return wg.runWorker(workerID)
		})
	}

	// Wait for all workers to finish or for the first error/cancellation.
	if err := wg.goGroup.Wait(); err != nil {
		return fmt.Errorf("one or more workers failed: %w", err)
	}

	return nil
}

// runWorker pulls tasks from the taskQueue until it is empty or the worker
// context is canceled:
//   - Verifies and close any resolved GitHub issues related to the fuzz target.
//   - Executes the fuzz target with a timeout.
func (wg *WorkerGroup) runWorker(workerID int) error {
	for {
		task, ok := wg.taskQueue.Dequeue()
		if !ok {
			wg.logger.Info("No more tasks in queue; stopping "+
				"worker", "workerID", workerID)
			return nil
		}

		wg.logger.Info(
			"Worker starting issue verification", "workerID",
			workerID, "package", task.PackagePath, "target",
			task.Target,
		)

		// Initialize a GitHub client for issue verification.
		//
		// For issue verification, even in in-cluster mode, a Docker
		// container will be spun up to verify issue reproducibility.
		gh, err := NewGitHubRepo(wg.ctx, wg.logger.With("target",
			task.Target).With("package", task.PackagePath),
			wg.dockerClient, wg.cfg)
		if err != nil {
			return fmt.Errorf("error initializing GitHub client: "+
				"%w", err)
		}

		// The worker will verify and close any open GitHub issues
		// related to the fuzz target.
		err = gh.verifyAndCloseResolvedIssues(task.PackagePath,
			task.Target)
		if err != nil {
			if wg.ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("failed to verify and close open "+
				"issues: %w", err)
		}

		wg.logger.Info(
			"Worker starting fuzzing", "workerID", workerID,
			"package", task.PackagePath, "target", task.Target,
			"timeout", wg.taskTimeout,
		)

		err = wg.executeFuzzTarget(task.PackagePath, task.Target, gh)
		if err != nil {
			if wg.ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("worker %d: fuzz target %q/%q "+
				"failed: %w", workerID, task.PackagePath,
				task.Target, err)
		}

		wg.logger.Info(
			"Worker completed fuzz target", "workerID", workerID,
			"package", task.PackagePath, "target", task.Target,
		)
	}
}

// executeFuzzTarget runs the specified fuzz target for a package using either
// Kubernetes (in-cluster) or Docker. It performs the following steps:
//   - Starts the fuzzing runner and streams its output.
//   - Reports any fuzz crashes by creating a GitHub issue.
//   - Updates the coverage report.
//   - Optionally minimizes the corpus if configured.
func (wg *WorkerGroup) executeFuzzTarget(pkg string, target string,
	gh *GitHubRepo) error {

	// Determine execution environment
	mode := "Docker"
	if wg.cfg.Fuzz.InCluster {
		mode = "Kubernetes"
	}
	wg.logger.Info("Executing fuzz target", "mode", mode, "package", pkg,
		"target", target, "duration", wg.taskTimeout)

	// Construct the absolute path to the package directory within the
	// temporary project directory.
	pkgPath := filepath.Join(wg.cfg.Project.SrcDir, pkg)

	// Define the path to store the corpus data generated during fuzzing.
	corpusPath := filepath.Join(wg.cfg.Project.CorpusDir, pkg, "testdata",
		"fuzz")

	// Ensure that the corpus directory exists to avoid permission errors
	// when running the container/pod as a non-root user.
	if err := EnsureDirExists(corpusPath); err != nil {
		return err
	}

	// Define the path to the fuzz target binary that will be executed
	// inside the fuzz runner.
	fuzzBinaryPath := filepath.Join(wg.cfg.Project.BinaryDir, pkg, target)

	// Create a subcontext with timeout for this individual fuzz target.
	fuzzCtx, cancel := context.WithTimeout(wg.ctx, wg.taskTimeout+
		FuzzGracePeriod)
	defer cancel()

	// Prepare runner configuration.
	runner := wg.createFuzzRunner(fuzzCtx, pkg, target, fuzzBinaryPath,
		corpusPath)

	// Start the fuzzing runner.
	fuzzID, err := runner.Start()
	if err != nil {
		if fuzzCtx.Err() != nil {
			return nil
		}
		return fmt.Errorf("failed to start fuzz runner: %w", err)
	}

	// Stopping the fuzz runner here is both safe and necessary. In case of
	// any error, we can ensure that the fuzzing runner is stopped. If
	// there is no error, it means the fuzz timed out and the runner has
	// already stopped, so this call won't cause any issues anyway.
	defer func() {
		if err := runner.Stop(fuzzID); err != nil {
			wg.logger.Error("Failed to fuzz runner", "error", err,
				"fuzzID", fuzzID)
		}
	}()

	// Channels to receive either a fuzz failure or a container/pod error.
	fuzzCrashChan := make(chan fuzzCrash, 1)
	errorChan := make(chan error, 1)

	// Begin processing logs and wait for completion/failure signal in a
	// goroutine.
	go runner.WaitAndGetLogs(fuzzID, pkg, target, fuzzCrashChan, errorChan)

	select {
	case <-fuzzCtx.Done():
		// Context timeout or cancellation occurred.

	case err := <-errorChan:
		if err != nil {
			// Fuzz runner exited with an error (non-fuzz crash).
			return fmt.Errorf("fuzz execution failed: %w", err)
		}

	case fuzzCrash := <-fuzzCrashChan:
		// Report the fuzz crash.
		if err := gh.handleCrash(pkg, target, fuzzCrash); err != nil {
			return fmt.Errorf("handling fuzz crash: %w", err)
		}
	}

	// Now stop the fuzz runner.
	if err := runner.Stop(fuzzID); err != nil {
		return fmt.Errorf("failed to stop runner %s after fuzzing: "+
			"%w", fuzzID, err)
	}

	wg.logger.Info("Fuzzing completed successfully", "mode", mode,
		"package", pkg, "target", target)

	err = updateReport(wg.ctx, pkg, target, wg.cfg, wg.logger)
	if err != nil {
		return fmt.Errorf("failed to add coverage report for package "+
			"%s, target %s: %w", pkg, target, err)
	}

	wg.logger.Info("Successfully added/updated coverage report", "package",
		pkg, "target", target)

	// Minimize the corpus if needed.
	if wg.shouldMinimizeCorpus {
		err := MinimizeCorpus(wg.ctx, wg.logger.With("target", target).
			With("package", pkg), pkgPath, corpusPath,
			target)
		if err != nil {
			return fmt.Errorf("minimizing corpus for target %q: %w",
				target, err)
		}
	}

	return nil
}

// createFuzzRunner initializes the appropriate fuzzing runner (either
// Kubernetes job or Docker container) based on the execution mode.
func (wg *WorkerGroup) createFuzzRunner(ctx context.Context, pkg, target,
	fuzzBinaryPath, corpusPath string) FuzzRunner {

	// Prepare the base arguments for the test command to run the specific
	// fuzz target in container/pod.
	cmd := []string{
		fmt.Sprintf("./%s.test", target),
		fmt.Sprintf("-test.fuzz=^%s$", target),
		"-test.parallel=1",
	}

	// Append fuzz cache directory path depending on the mode
	if wg.cfg.Fuzz.InCluster {
		cmd = append(cmd, fmt.Sprintf("-test.fuzzcachedir=%s",
			corpusPath))
		jobName := strings.ToLower(fmt.Sprintf("fuzz-job-%s-%s", pkg,
			target))

		return &Cluster{
			ctx:            ctx,
			logger:         wg.logger,
			jobName:        jobName,
			clientset:      wg.k8sClientSet,
			cfg:            wg.cfg,
			fuzzBinaryPath: fuzzBinaryPath,
			cmd:            cmd,
		}
	}

	cmd = append(cmd, fmt.Sprintf("-test.fuzzcachedir=%s",
		ContainerCorpusPath))

	return &Container{
		ctx:            ctx,
		logger:         wg.logger,
		cli:            wg.dockerClient,
		fuzzBinaryPath: fuzzBinaryPath,
		hostCorpusPath: corpusPath,
		cmd:            cmd,
	}
}
