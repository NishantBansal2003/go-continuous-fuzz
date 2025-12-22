package main

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/docker/docker/client"
	"k8s.io/client-go/kubernetes"
)

// FuzzRunner abstracts Kubernetes or Docker fuzz execution
type FuzzRunner interface {
	Start() (string, error)
	Stop(ID string) error
	WaitAndGetLogs(ID string, pkg string, target string,
		fuzzCrashChan chan fuzzCrash, errChan chan error)
	Wait(ID string) error
}

// FuzzRunnerConfig holds configuration for creating a fuzz runner.
type FuzzRunnerConfig struct {
	ctx            context.Context
	logger         *slog.Logger
	clientset      *kubernetes.Clientset
	cli            *client.Client
	cfg            *Config
	pkg            string
	target         string
	fuzzBinaryPath string
	corpusPath     string
	cmd            []string
}

// CreateFuzzRunner initializes the appropriate fuzzing runner (either
// Kubernetes job or Docker container) based on the execution mode.
func (fr *FuzzRunnerConfig) CreateFuzzRunner() FuzzRunner {
	// Prepare the base arguments for the test command to run the specific
	// fuzz target in container/pod, if the cmd is not already provided.
	testCmd := fr.cmd
	if testCmd == nil {
		testCmd = fr.buildDefaultTestCommand()
	}

	// Append fuzz cache directory path depending on the mode
	if fr.cfg.Fuzz.InCluster {
		jobName := strings.ToLower(fmt.Sprintf("fuzz-job-%s-%s", fr.pkg,
			fr.target))

		return &Cluster{
			ctx:            fr.ctx,
			logger:         fr.logger,
			jobName:        jobName,
			clientset:      fr.clientset,
			cfg:            fr.cfg,
			fuzzBinaryPath: fr.fuzzBinaryPath,
			cmd:            testCmd,
		}
	}

	return &Container{
		ctx:            fr.ctx,
		logger:         fr.logger,
		cli:            fr.cli,
		fuzzBinaryPath: fr.fuzzBinaryPath,
		hostCorpusPath: fr.corpusPath,
		cmd:            testCmd,
	}
}

// buildDefaultTestCommand constructs the default test command with appropriate
// cache directory based on execution mode.
func (fr *FuzzRunnerConfig) buildDefaultTestCommand() []string {
	corpusPath := ContainerCorpusPath
	if fr.cfg.Fuzz.InCluster {
		corpusPath = fr.corpusPath
	}

	return []string{
		fmt.Sprintf("./%s.test", fr.target),
		fmt.Sprintf("-test.fuzz=^%s$", fr.target),
		"-test.parallel=1",
		fmt.Sprintf("-test.fuzzcachedir=%s", corpusPath),
	}
}
