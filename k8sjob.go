package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// K8sJob encapsulates the configuration and state needed to manage a Kubernetes
// Job for running fuzzing tasks, including context, logger, Kubernetes client,
// configuration, working directories, and command.
type K8sJob struct {
	ctx       context.Context
	logger    *slog.Logger
	clientset *kubernetes.Clientset
	cfg       *Config
	workDir   string
	cmd       []string
}

// Start creates a Kubernetes Job with the specified configuration.
// It returns the job name if successful, or an error if job creation fails.
//
//nolint:lll
func (k *K8sJob) Start() (string, error) {
	// Generate unique job name
	jobName := fmt.Sprintf("fuzz-job-%d", time.Now().Unix())

	// Create job definition
	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name: jobName,
		},
		Spec: batchv1.JobSpec{
			BackoffLimit:            int32Ptr(0),
			TTLSecondsAfterFinished: int32Ptr(int32(60)),
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					ServiceAccountName: "go-continuous-fuzz-sa",
					SecurityContext: &corev1.PodSecurityContext{
						RunAsUser:  int64Ptr(int64(os.Getuid())),
						RunAsGroup: int64Ptr(int64(os.Getgid())),
					},
					RestartPolicy: corev1.RestartPolicyNever,
					Containers: []corev1.Container{
						{
							Name:       "fuzz-container",
							Image:      ContainerImage,
							Command:    k.cmd,
							WorkingDir: k.workDir,
							Env: []corev1.EnvVar{
								{
									Name:  "GOCACHE",
									Value: "/tmp",
								},
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "go-continuous-fuzz-src",
									MountPath: TmpWorkspacePath,
								},
							},
							Resources: corev1.ResourceRequirements{
								Requests: corev1.ResourceList{
									corev1.ResourceMemory: resource.MustParse("2Gi"),
									corev1.ResourceCPU:    resource.MustParse("1"),
								},
								Limits: corev1.ResourceList{
									corev1.ResourceMemory: resource.MustParse("2Gi"),
									corev1.ResourceCPU:    resource.MustParse("1"),
								},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "go-continuous-fuzz-src",
							VolumeSource: corev1.VolumeSource{
								PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
									ClaimName: "go-continuous-fuzz-pvc",
								},
							},
						},
					},
				},
			},
		},
	}

	// Create job in Kubernetes
	_, err := k.clientset.BatchV1().Jobs("default").Create(k.ctx, job,
		metav1.CreateOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to create job: %w", err)
	}

	return jobName, nil
}

// WaitAndGetLogs watches the job's pod, processes its logs, and reports either
// a fuzz crash or the container's exit status. This MUST be run as a goroutine.
func (k *K8sJob) WaitAndGetLogs(jobName, pkg, target string,
	failingChan chan bool, errChan chan error) {

	// Wait for pod to be created
	pod, err := k.waitForPod(jobName)
	if err != nil {
		errChan <- fmt.Errorf("error waiting for pod: %w", err)
		return
	}

	// Get logs stream
	logsReq := k.clientset.CoreV1().Pods("default").GetLogs(pod.Name,
		&corev1.PodLogOptions{
			Follow: true,
		})

	logsStream, err := logsReq.Stream(k.ctx)
	if err != nil {
		errChan <- fmt.Errorf("failed to get logs stream: %w", err)
		return
	}
	defer func() {
		if err := logsStream.Close(); err != nil {
			k.logger.Error("error closing logs stream", "jobName",
				jobName, "error", err)
		}
	}()

	// Process logs
	maybeFailingCorpusPath := filepath.Join(k.cfg.Project.SrcDir, pkg,
		"testdata", "fuzz")
	processor := NewFuzzOutputProcessor(k.logger.With("target", target).
		With("package", pkg), k.cfg, maybeFailingCorpusPath, target)
	crashed := processor.processFuzzStream(logsStream)

	// Fuzz target crashed: notify via failingChan.
	if crashed {
		failingChan <- true
		return
	}

	// Retrieve the job status and send error (if any) on errChan.
	errChan <- k.waitForJobCompletion(jobName)
}

// waitForPod waits for the pod associated with a job to be created and ready
func (k *K8sJob) waitForPod(jobName string) (*corev1.Pod, error) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	labelSelector := fmt.Sprintf("job-name=%s", jobName)

	for {
		select {
		case <-k.ctx.Done():
			return nil, k.ctx.Err()
		case <-ticker.C:
			pods, err := k.clientset.CoreV1().Pods("default").List(
				k.ctx, metav1.ListOptions{
					LabelSelector: labelSelector,
				})
			if err != nil {
				return nil, fmt.Errorf("failed to list pods: "+
					"%w", err)
			}

			if len(pods.Items) > 0 {
				pod := pods.Items[0]
				if pod.Status.Phase == corev1.PodRunning ||
					pod.Status.Phase ==
						corev1.PodSucceeded ||
					pod.Status.Phase == corev1.PodFailed {

					return &pod, nil
				}
			}
		}
	}
}

// waitForJobCompletion waits for a job to complete and returns its status
func (k *K8sJob) waitForJobCompletion(jobName string) error {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-k.ctx.Done():
			return k.ctx.Err()
		case <-ticker.C:
			job, err := k.clientset.BatchV1().Jobs("default").Get(
				k.ctx, jobName, metav1.GetOptions{})
			if err != nil {
				return fmt.Errorf("failed to get job status: "+
					"%w", err)
			}

			if job.Status.Succeeded > 0 {
				return nil
			}
			if job.Status.Failed > 0 {
				return fmt.Errorf("job failed")
			}
		}
	}
}

// Stop deletes a Kubernetes job and its associated pods
func (k *K8sJob) Stop(jobName string) {
	propagationPolicy := metav1.DeletePropagationBackground
	err := k.clientset.BatchV1().Jobs("default").Delete(
		context.Background(), jobName, metav1.DeleteOptions{
			PropagationPolicy: &propagationPolicy,
		})
	if err != nil {
		k.logger.Error("Failed to delete job", "error", err, "jobName",
			jobName)
	}
}

// Helper function for int32 pointer
func int32Ptr(i int32) *int32 { return &i }

// Helper function for int64 pointer
func int64Ptr(i int64) *int64 { return &i }
