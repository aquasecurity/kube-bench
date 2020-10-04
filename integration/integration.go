package integration

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
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
	"sigs.k8s.io/kind/pkg/cluster/create"
)

func runWithKind(ctx *cluster.Context, clientset *kubernetes.Clientset, jobName, kubebenchYAML, kubebenchImg string, timeout time.Duration) (string, error) {
	err := deployJob(clientset, kubebenchYAML, kubebenchImg)
	if err != nil {
		return "", err
	}

	p, err := findPodForJob(clientset, jobName, timeout)
	if err != nil {
		return "", err
	}

	output := getPodLogs(clientset, p)

	err = clientset.BatchV1().Jobs(apiv1.NamespaceDefault).Delete(jobName, nil)
	if err != nil {
		return "", err
	}

	return output, nil
}

func setupCluster(clusterName, kindCfg string, duration time.Duration) (*cluster.Context, error) {
	options := create.WithConfigFile(kindCfg)
	toptions := create.WaitForReady(duration)
	ctx := cluster.NewContext(clusterName)
	if err := ctx.Create(options, toptions); err != nil {
		return nil, err
	}

	return ctx, nil
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
	jobYAML, err := ioutil.ReadFile(kubebenchYAML)
	if err != nil {
		return err
	}

	decoder := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(jobYAML), len(jobYAML))
	job := &batchv1.Job{}
	if err := decoder.Decode(job); err != nil {
		return err
	}
	job.Spec.Template.Spec.Containers[0].Image = kubebenchImg

	_, err = clientset.BatchV1().Jobs(apiv1.NamespaceDefault).Create(job)

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
			pods, err := clientset.CoreV1().Pods(apiv1.NamespaceDefault).List(metav1.ListOptions{
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
	podLogs, err := req.Stream()
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
