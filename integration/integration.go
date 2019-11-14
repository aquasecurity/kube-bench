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

func runWithKind(clusterName, kindCfg, kubebenchYAML string) (string, error) {
	options := create.WithConfigFile(kindCfg)
	ctx := cluster.NewContext(clusterName)
	if err := ctx.Create(options); err != nil {
		return "", err
	}
	defer func() {
		ctx.Delete()
	}()

	clientset, err := getClientSet(ctx.KubeConfigPath())
	if err != nil {
		return "", err
	}

	jobYAML, err := ioutil.ReadFile(kubebenchYAML)
	if err != nil {
		return "", err
	}

	decoder := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(jobYAML), len(jobYAML))
	if err != nil {
		return "", err
	}

	job := &batchv1.Job{}
	if err := decoder.Decode(job); err != nil {
		return "", err
	}

	_, err = clientset.BatchV1().Jobs(apiv1.NamespaceDefault).Create(job)
	if err != nil {
		return "", err
	}

	clientset, err = getClientSet(ctx.KubeConfigPath())
	if err != nil {
		return "", err
	}

	p, err := findPodForJob(clientset, "kube-bench")
	if err != nil {
		return "", err
	}

	output := getPodLogs(clientset, p)
	return output, nil
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

func int32Ptr(i int32) *int32 { return &i }

func findPodForJob(clientset *kubernetes.Clientset, name string) (*apiv1.Pod, error) {
	for {
		pods, err := clientset.CoreV1().Pods(apiv1.NamespaceDefault).List(metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		for _, pod := range pods.Items {
			if strings.HasPrefix(pod.Name, name) {
				if pod.Status.Phase == apiv1.PodSucceeded {
					return &pod, nil
				}
				time.Sleep(5 * time.Second)
			}
		}
	}

	return nil, fmt.Errorf("no Pod with %s", name)
}

func getPodLogs(clientset *kubernetes.Clientset, pod *apiv1.Pod) string {
	podLogOpts := corev1.PodLogOptions{}
	req := clientset.CoreV1().Pods(pod.Namespace).GetLogs(pod.Name, &podLogOpts)
	podLogs, err := req.Stream()
	if err != nil {
		return "error in opening stream"
	}
	defer podLogs.Close()

	buf := new(bytes.Buffer)
	_, err = io.Copy(buf, podLogs)
	if err != nil {
		return "error in copy information from podLogs to buf"
	}
	str := buf.String()

	return str
}
