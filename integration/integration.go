package integration

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	apiv1 "k8s.io/api/core/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	yaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/kind/pkg/cluster"
)

func runWithKind(clientset *kubernetes.Clientset, jobName, kubebenchYAML, kubebenchImg string, timeout time.Duration) (string, error) {
	err := deployJob(clientset, kubebenchYAML, kubebenchImg)
	if err != nil {
		return "", err
	}

	p, err := findPodForJob(clientset, jobName, timeout)
	if err != nil {
		return "", err
	}

	output := getPodLogs(clientset, p)

	err = clientset.BatchV1().Jobs(apiv1.NamespaceDefault).Delete(context.Background(), jobName, metav1.DeleteOptions{})
	if err != nil {
		return "", err
	}

	return output, nil
}

func setupCluster(clusterName, kindCfg string, duration time.Duration, kubeDefaultPath string) (*cluster.Provider, error) {
	options := cluster.CreateWithConfigFile(kindCfg)
	durationOptions := cluster.CreateWithWaitForReady(duration)
	provider := cluster.NewProvider()

	// Check if the cluster exists
	clusters, err := provider.List()

	if err != nil {
		return nil, fmt.Errorf("failed to list clusters: %v", err)
	}

	// If the cluster exists, delete it
	for _, existingCluster := range clusters {
		if existingCluster == clusterName {
			fmt.Printf("Cluster %s already exists, deleting it...\n", clusterName)
			err := provider.Delete(clusterName, kubeDefaultPath)
			if err != nil {
				return nil, fmt.Errorf("failed to delete existing cluster %s: %v", clusterName, err)
			}
			break
		}
	}

	if err := provider.Create(clusterName, options, durationOptions); err != nil {
		return nil, err
	}

	return provider, nil
}

func getClientSet(configPath string) (*kubernetes.Clientset, error) {
	config, err := clientcmd.BuildConfigFromFlags("", configPath)
	if err != nil {
		return nil, err
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	return clientset, nil
}

func deployJob(clientset *kubernetes.Clientset, kubebenchYAML, kubebenchImg string) error {
	jobYAML, err := os.ReadFile(kubebenchYAML)
	if err != nil {
		return err
	}

	decoder := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(jobYAML), len(jobYAML))
	job := &batchv1.Job{}
	if err := decoder.Decode(job); err != nil {
		return err
	}
	job.Spec.Template.Spec.Containers[0].Image = kubebenchImg

	_, err = clientset.BatchV1().Jobs(apiv1.NamespaceDefault).Create(context.Background(), job, metav1.CreateOptions{})

	return err
}

func findPodForJob(clientset *kubernetes.Clientset, jobName string, duration time.Duration) (*apiv1.Pod, error) {
	failedPods := make(map[string]struct{})
	selector := fmt.Sprintf("job-name=%s", jobName)
	timeout := time.After(duration)
	for {
		time.Sleep(3 * time.Second)
	podfailed:
		select {
		case <-timeout:
			return nil, fmt.Errorf("podList - timed out: no Pod found for Job %s", jobName)
		default:
			pods, err := clientset.CoreV1().Pods(apiv1.NamespaceDefault).List(context.Background(), metav1.ListOptions{
				LabelSelector: selector,
			})
			if err != nil {
				return nil, err
			}
			fmt.Printf("Found (%d) pods\n", len(pods.Items))
			for _, cp := range pods.Items {
				if _, found := failedPods[cp.Name]; found {
					continue
				}

				if strings.HasPrefix(cp.Name, jobName) {
					fmt.Printf("pod (%s) - %#v\n", cp.Name, cp.Status.Phase)
					if cp.Status.Phase == apiv1.PodSucceeded {
						return &cp, nil
					}

					if cp.Status.Phase == apiv1.PodFailed {
						fmt.Printf("pod (%s) - %s - retrying...\n", cp.Name, cp.Status.Phase)
						fmt.Print(getPodLogs(clientset, &cp))
						failedPods[cp.Name] = struct{}{}
						break podfailed
					}
				}
			}
		}
	}
}

func getPodLogs(clientset *kubernetes.Clientset, pod *apiv1.Pod) string {
	podLogOpts := corev1.PodLogOptions{}
	req := clientset.CoreV1().Pods(pod.Namespace).GetLogs(pod.Name, &podLogOpts)
	podLogs, err := req.Stream(context.Background())
	if err != nil {
		return "getPodLogs - error in opening stream"
	}
	defer podLogs.Close()

	buf := new(bytes.Buffer)
	_, err = io.Copy(buf, podLogs)
	if err != nil {
		return "getPodLogs - error in copy information from podLogs to buf"
	}

	return buf.String()
}
