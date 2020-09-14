package cmd

import (
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang/glog"
)

func getKubeVersionFromRESTAPI() (string, error) {
	k8sVersionURL := getKubernetesURL()
	serviceaccount := "/var/run/secrets/kubernetes.io/serviceaccount"
	cacertfile := fmt.Sprintf("%s/ca.crt", serviceaccount)
	tokenfile := fmt.Sprintf("%s/token", serviceaccount)

	tlsCert, err := loadCertficate(cacertfile)
	if err != nil {
		return "", err
	}

	tb, err := ioutil.ReadFile(tokenfile)
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(tb))

	data, err := getWebDataWithRetry(k8sVersionURL, token, tlsCert)
	if err != nil {
		return "", err
	}

	k8sVersion, err := extractVersion(data)
	if err != nil {
		return "", err
	}
	return k8sVersion, nil
}

// The idea of this function is so if Kubernetes DNS is not completely seetup and the
// Container where kube-bench is running needs time for DNS configure.
// Basically try 10 times, waiting 1 second until either it is successful or it fails.
func getWebDataWithRetry(k8sVersionURL, token string, cacert *tls.Certificate) (data []byte, err error) {
	tries := 0
	// We retry a few times in case the DNS service has not had time to come up
	for tries < 10 {
		data, err = getWebData(k8sVersionURL, token, cacert)
		if err == nil {
			return
		}
		tries++
		time.Sleep(1 * time.Second)
	}

	return
}

func extractVersion(data []byte) (string, error) {
	type versionResponse struct {
		Major        string
		Minor        string
		GitVersion   string
		GitCommit    string
		GitTreeState string
		BuildDate    string
		GoVersion    string
		Compiler     string
		Platform     string
	}

	vrObj := &versionResponse{}
	glog.V(2).Info(fmt.Sprintf("vd: %s\n", string(data)))
	err := json.Unmarshal(data, vrObj)
	if err != nil {
		return "", err
	}
	glog.V(2).Info(fmt.Sprintf("vrObj: %#v\n", vrObj))

	// Some provides return the minor version like "15+"
	minor := strings.Replace(vrObj.Minor, "+", "", -1)
	ver := fmt.Sprintf("%s.%s", vrObj.Major, minor)
	return ver, nil
}

func getWebData(srvURL, token string, cacert *tls.Certificate) ([]byte, error) {
	glog.V(2).Info(fmt.Sprintf("getWebData srvURL: %s\n", srvURL))

	tlsConf := &tls.Config{
		Certificates:       []tls.Certificate{*cacert},
		InsecureSkipVerify: true,
	}
	tr := &http.Transport{
		TLSClientConfig: tlsConf,
	}
	client := &http.Client{Transport: tr}
	req, err := http.NewRequest(http.MethodGet, srvURL, nil)
	if err != nil {
		return nil, err
	}

	authToken := fmt.Sprintf("Bearer %s", token)
	glog.V(2).Info(fmt.Sprintf("getWebData AUTH TOKEN --[%q]--\n", authToken))
	req.Header.Set("Authorization", authToken)

	resp, err := client.Do(req)
	if err != nil {
		glog.V(2).Info(fmt.Sprintf("HTTP ERROR: %v\n", err))
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		glog.V(2).Info(fmt.Sprintf("URL:[%s], StatusCode:[%d] \n Headers: %#v\n", srvURL, resp.StatusCode, resp.Header))
		err = fmt.Errorf("URL:[%s], StatusCode:[%d]", srvURL, resp.StatusCode)
		return nil, err
	}

	return ioutil.ReadAll(resp.Body)
}

func loadCertficate(certFile string) (*tls.Certificate, error) {
	cacert, err := ioutil.ReadFile(certFile)
	if err != nil {
		return nil, err
	}

	var tlsCert tls.Certificate
	block, _ := pem.Decode(cacert)
	if block == nil {
		return nil, fmt.Errorf("unable to Decode certificate")
	}

	glog.V(2).Info(fmt.Sprintf("Loading CA certificate"))
	tlsCert.Certificate = append(tlsCert.Certificate, block.Bytes)
	return &tlsCert, nil
}

func getKubernetesURL() string {
	k8sVersionURL := "https://kubernetes.default.svc/version"

	// The following provides flexibility to use
	// K8S provided variables is situations where
	// hostNetwork: true
	if !isEmpty(os.Getenv("KUBE_BENCH_K8S_ENV")) {
		k8sHost := os.Getenv("KUBERNETES_SERVICE_HOST")
		k8sPort := os.Getenv("KUBERNETES_SERVICE_PORT_HTTPS")
		if !isEmpty(k8sHost) && !isEmpty(k8sPort) {
			return fmt.Sprintf("https://%s:%s/version", k8sHost, k8sPort)
		}

		glog.V(2).Info(fmt.Sprintf("KUBE_BENCH_K8S_ENV is set, but environment variables KUBERNETES_SERVICE_HOST or KUBERNETES_SERVICE_PORT_HTTPS are not set"))
	}

	return k8sVersionURL
}
