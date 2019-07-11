// Copyright © 2017 Aqua Security Software Ltd. <info@aquasec.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package check

import (
	"io/ioutil"
	"os"
	"strings"
	"testing"
)

var (
	in       []byte
	controls *Controls
)

func init() {
	var err error
	in, err = ioutil.ReadFile("data")
	if err != nil {
		panic("Failed reading test data: " + err.Error())
	}

	// substitute variables in data file
	user := os.Getenv("USER")
	s := strings.Replace(string(in), "$user", user, -1)

	controls, err = NewControls(MASTER, []byte(s))
	// controls, err = NewControls(MASTER, in)
	if err != nil {
		panic("Failed creating test controls: " + err.Error())
	}
}

func TestTestExecute(t *testing.T) {

	cases := []struct {
		*Check
		str string
	}{
		{
			controls.Groups[0].Checks[0],
			"2:45 ../kubernetes/kube-apiserver --allow-privileged=false --option1=20,30,40",
		},
		{
			controls.Groups[0].Checks[1],
			"2:45 ../kubernetes/kube-apiserver --allow-privileged=false",
		},
		{
			controls.Groups[0].Checks[2],
			"niinai   13617  2635 99 19:26 pts/20   00:03:08 ./kube-apiserver --insecure-port=0 --anonymous-auth",
		},
		{
			controls.Groups[0].Checks[3],
			"2:45 ../kubernetes/kube-apiserver --secure-port=0 --audit-log-maxage=40 --option",
		},
		{
			controls.Groups[0].Checks[4],
			"2:45 ../kubernetes/kube-apiserver --max-backlog=20 --secure-port=0 --audit-log-maxage=40 --option",
		},
		{
			controls.Groups[0].Checks[5],
			"2:45 ../kubernetes/kube-apiserver --option --admission-control=WebHook,RBAC ---audit-log-maxage=40",
		},
		{
			controls.Groups[0].Checks[6],
			"2:45 .. --kubelet-clientkey=foo --kubelet-client-certificate=bar --admission-control=Webhook,RBAC",
		},
		{
			controls.Groups[0].Checks[7],
			"2:45 ..  --secure-port=0 --kubelet-client-certificate=bar --admission-control=Webhook,RBAC",
		},
		{
			controls.Groups[0].Checks[8],
			"644",
		},
		{
			controls.Groups[0].Checks[9],
			"640",
		},
		{
			controls.Groups[0].Checks[9],
			"600",
		},
		{
			controls.Groups[0].Checks[10],
			"2:45 ../kubernetes/kube-apiserver --option --admission-control=WebHook,RBAC ---audit-log-maxage=40",
		},
		{
			controls.Groups[0].Checks[11],
			"2:45 ../kubernetes/kube-apiserver --option --admission-control=WebHook,RBAC ---audit-log-maxage=40",
		},
		{
			controls.Groups[0].Checks[12],
			"2:45 ../kubernetes/kube-apiserver --option --admission-control=WebHook,Something,RBAC ---audit-log-maxage=40",
		},
		{
			controls.Groups[0].Checks[13],
			"2:45 ../kubernetes/kube-apiserver --option --admission-control=Something ---audit-log-maxage=40",
		},
		{
			// check for ':' as argument-value separator, with space between arg and val
			controls.Groups[0].Checks[14],
			"2:45 kube-apiserver some-arg: some-val --admission-control=Something ---audit-log-maxage=40",
		},
		{
			// check for ':' as argument-value separator, with no space between arg and val
			controls.Groups[0].Checks[14],
			"2:45 kube-apiserver some-arg:some-val --admission-control=Something ---audit-log-maxage=40",
		},
		{
			controls.Groups[0].Checks[15],
			"{\"readOnlyPort\": 15000}",
		},
		{
			controls.Groups[0].Checks[16],
			"{\"stringValue\": \"WebHook,Something,RBAC\"}",
		},
		{
			controls.Groups[0].Checks[17],
			"{\"trueValue\": true}",
		},
		{
			controls.Groups[0].Checks[18],
			"{\"readOnlyPort\": 15000}",
		},
		{
			controls.Groups[0].Checks[19],
			"{\"authentication\": { \"anonymous\": {\"enabled\": false}}}",
		},
		{
			controls.Groups[0].Checks[20],
			"readOnlyPort: 15000",
		},
		{
			controls.Groups[0].Checks[21],
			"readOnlyPort: 15000",
		},
		{
			controls.Groups[0].Checks[22],
			"authentication:\n  anonymous:\n    enabled: false",
		},
		{
			controls.Groups[0].Checks[26],
			"currentMasterVersion: 1.12.7",
		},
	}

	for _, c := range cases {
		res := c.Tests.execute(c.str).testResult
		if !res {
			t.Errorf("%s, expected:%v, got:%v\n", c.Text, true, res)
		}
	}
}

func TestTestExecuteExceptions(t *testing.T) {

	cases := []struct {
		*Check
		str string
	}{
		{
			controls.Groups[0].Checks[23],
			"this is not valid json {} at all",
		},
		{
			controls.Groups[0].Checks[24],
			"{\"key\": \"value\"}",
		},
		{
			controls.Groups[0].Checks[25],
			"broken } yaml\nenabled: true",
		},
		{
			controls.Groups[0].Checks[26],
			"currentMasterVersion: 1.11",
		},
		{
			controls.Groups[0].Checks[26],
			"currentMasterVersion: ",
		},
	}

	for _, c := range cases {
		res := c.Tests.execute(c.str).testResult
		if res {
			t.Errorf("%s, expected:%v, got:%v\n", c.Text, false, res)
		}
	}
}

func TestTestUnmarshal(t *testing.T) {
	type kubeletConfig struct {
		Kind       string
		ApiVersion string
		Address    string
	}
	cases := []struct {
		content        string
		jsonInterface  interface{}
		expectedToFail bool
	}{
		{
			`{
			"kind": "KubeletConfiguration",
			"apiVersion": "kubelet.config.k8s.io/v1beta1",
			"address": "0.0.0.0"
			}
			`,
			kubeletConfig{},
			false,
		}, {
			`
kind: KubeletConfiguration
address: 0.0.0.0
apiVersion: kubelet.config.k8s.io/v1beta1
authentication:
  anonymous:
    enabled: false
  webhook:
    cacheTTL: 2m0s
  enabled: true
  x509:
    clientCAFile: /etc/kubernetes/pki/ca.crt
tlsCipherSuites:
  - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
  - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
`,
			kubeletConfig{},
			false,
		},
		{
			`
kind: ddress: 0.0.0.0
apiVersion: kubelet.config.k8s.io/v1beta
`,
			kubeletConfig{},
			true,
		},
	}

	for _, c := range cases {
		err := unmarshal(c.content, &c.jsonInterface)
		if err != nil {
			if !c.expectedToFail {
				t.Errorf("%s, expectedToFail:%v, got:%v\n", c.content, c.expectedToFail, err)
			}
		} else {
			if c.expectedToFail {
				t.Errorf("%s, expectedToFail:%v, got:Did not fail\n", c.content, c.expectedToFail)
			}
		}
	}
}

func TestExecuteJSONPath(t *testing.T) {
	type kubeletConfig struct {
		Kind       string
		ApiVersion string
		Address    string
	}
	cases := []struct {
		jsonPath       string
		jsonInterface  kubeletConfig
		expectedResult string
		expectedToFail bool
	}{
		{
			// JSONPath parse works, results don't match
			"{.Kind}",
			kubeletConfig{
				Kind:       "KubeletConfiguration",
				ApiVersion: "kubelet.config.k8s.io/v1beta1",
				Address:    "127.0.0.0",
			},
			"blah",
			true,
		},
		{
			// JSONPath parse works, results match
			"{.Kind}",
			kubeletConfig{
				Kind:       "KubeletConfiguration",
				ApiVersion: "kubelet.config.k8s.io/v1beta1",
				Address:    "127.0.0.0",
			},
			"KubeletConfiguration",
			false,
		},
		{
			// JSONPath parse fails
			"{.ApiVersion",
			kubeletConfig{
				Kind:       "KubeletConfiguration",
				ApiVersion: "kubelet.config.k8s.io/v1beta1",
				Address:    "127.0.0.0",
			},
			"",
			true,
		},
	}
	for _, c := range cases {
		result, err := executeJSONPath(c.jsonPath, c.jsonInterface)
		if err != nil && !c.expectedToFail {
			t.Fatalf("jsonPath:%q, expectedResult:%q got:%v\n", c.jsonPath, c.expectedResult, err)
		}
		if c.expectedResult != result && !c.expectedToFail {
			t.Errorf("jsonPath:%q, expectedResult:%q got:%q\n", c.jsonPath, c.expectedResult, result)
		}
	}
}
