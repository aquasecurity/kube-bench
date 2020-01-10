package cmd

import (
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang/glog"
)

func getKubeVersionFromRESTAPI() (string, error) {
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

	timeDuration := 30 * time.Second
	waitDuration := 1 * time.Second
	data, err := getWebDataRetry(getKubernetesURLs(), token, tlsCert, timeDuration, waitDuration)
	if err != nil {
		return "", err
	}

	k8sVersion, err := extractVersion(data)
	if err != nil {
		return "", err
	}
	return k8sVersion, nil
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

func getWebDataRetry(srvURLs []string, token string, cacert *tls.Certificate, timeoutDuration, waitDuration time.Duration) (data []byte, err error) {
	timeout := time.After(timeoutDuration)
	wait := time.Duration(waitDuration)
	for {
		select {
		case <-timeout:
			err = errors.New("timeout - getting Kubernetes version using REST API")
			return
		default:
			for _, srvURL := range srvURLs {
				data, err = getWebData(srvURL, token, cacert)
				if err == nil {
					return
				}
				glog.V(2).Info(fmt.Sprintf("HTTP ERROR: %v\n", err))
				continue
			}
			glog.V(2).Info(fmt.Sprintf("Waiting (%s) to retry getting Kubernetes version using REST API", wait))
			time.Sleep(wait)
			continue
		}
	}
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

func getKubernetesURLs() []string {
	return []string{
		"https://kubernetes.default.svc/version",
		fmt.Sprintf("https://%s:%s/version", os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT_HTTPS")),
	}
}
