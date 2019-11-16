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

func runWithKind(clusterName, kindCfg, kubebenchYAML, kubebenchImg string, timeout, ticker time.Duration) (string, error) {
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
	job.Spec.Template.Spec.Containers[0].Image = kubebenchImg

	if err := loadImageFromDocker(kubebenchImg, ctx); err != nil {
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

	p, err := findPodForJob(clientset, "kube-bench", timeout, ticker)
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

func findPodForJob(clientset *kubernetes.Clientset, name string, tout, timer time.Duration) (*apiv1.Pod, error) {
	timeout := time.After(tout)
	failedPods := make(map[string]struct{})
	for {
	podfailed:
		select {
		case <-timeout:
			return nil, fmt.Errorf("podList - time out: no Pod with %s", name)
		default:
			pods, err := clientset.CoreV1().Pods(apiv1.NamespaceDefault).List(metav1.ListOptions{})
			if err != nil {
				return nil, err
			}
			fmt.Printf("Found (%d) pods\n", len(pods.Items))
			for _, cp := range pods.Items {
				if _, found := failedPods[cp.Name]; found {
					continue
				}

				if strings.HasPrefix(cp.Name, name) {
					fmt.Printf("pod (%s) - %#v\n", cp.Name, cp.Status.Phase)
					if cp.Status.Phase == apiv1.PodSucceeded {
						return &cp, nil
					}

					if cp.Status.Phase == apiv1.PodFailed {
						fmt.Printf("pod (%s) - %s - retrying...\n", cp.Name, cp.Status.Phase)
						failedPods[cp.Name] = struct{}{}
						break podfailed
					}

					// Pod still working
					// Wait and try again...
					ticker := time.NewTicker(timer)
					for {
						fmt.Println("using ticker and an timer...")
						select {
						case <-ticker.C:
							thePod, err := clientset.CoreV1().Pods(apiv1.NamespaceDefault).Get(cp.Name, metav1.GetOptions{})
							if err != nil {
								return nil, err
							}
							fmt.Printf("thePod (%s) - status:%#v \n", thePod.Name, thePod.Status.Phase)
							if thePod.Status.Phase == apiv1.PodSucceeded {
								return thePod, nil
							}

							if thePod.Status.Phase == apiv1.PodFailed {
								fmt.Printf("thePod (%s) - %s - retrying...\n", thePod.Name, thePod.Status.Phase)
								failedPods[thePod.Name] = struct{}{}
								ticker.Stop()
								break podfailed
							}

							if thePod.Status.Phase == apiv1.PodPending && strings.Contains(thePod.Status.Reason, "Failed") {
								fmt.Printf("thePod (%s) - %s - retrying...\n", thePod.Name, thePod.Status.Reason)
								failedPods[thePod.Name] = struct{}{}
								ticker.Stop()
								break podfailed
							}

						case <-timeout:
							ticker.Stop()
							return nil, fmt.Errorf("getPod time out: no Pod with %s", name)
						}
					}
				}
			}
		}
		time.Sleep(1 * time.Second)
	}

	return nil, fmt.Errorf("no Pod with %s", name)
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
