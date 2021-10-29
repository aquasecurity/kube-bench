// Copyright © 2017-2020 Aqua Security Software Ltd. <info@aquasec.com>
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
	"fmt"
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

	controls, err = NewControls(MASTER, []byte(s), "")
	// controls, err = NewControls(MASTER, in)
	if err != nil {
		panic("Failed creating test controls: " + err.Error())
	}
}

func TestTestExecute(t *testing.T) {
	cases := []struct {
		check              *Check
		str                string
		strConfig          string
		expectedTestResult string
		strEnv             string
	}{
		{
			check:              controls.Groups[0].Checks[0],
			str:                "2:45 ../kubernetes/kube-apiserver --allow-privileged=false --option1=20,30,40",
			strConfig:          "",
			expectedTestResult: "'--allow-privileged' is present",
		},
		{
			check:              controls.Groups[0].Checks[1],
			str:                "2:45 ../kubernetes/kube-apiserver --allow-privileged=false",
			strConfig:          "",
			expectedTestResult: "'--basic-auth' is not present",
		},
		{
			check:              controls.Groups[0].Checks[2],
			str:                "niinai   13617  2635 99 19:26 pts/20   00:03:08 ./kube-apiserver --insecure-port=0 --anonymous-auth",
			strConfig:          "",
			expectedTestResult: "'--insecure-port' is equal to '0'",
		},
		{
			check:              controls.Groups[0].Checks[3],
			str:                "2:45 ../kubernetes/kube-apiserver --secure-port=0 --audit-log-maxage=40 --option",
			strConfig:          "",
			expectedTestResult: "'--audit-log-maxage' is greater or equal to 30",
		},
		{
			check:              controls.Groups[0].Checks[4],
			str:                "2:45 ../kubernetes/kube-apiserver --max-backlog=20 --secure-port=0 --audit-log-maxage=40 --option",
			strConfig:          "",
			expectedTestResult: "'--max-backlog' is lower than 30",
		},
		{
			check:              controls.Groups[0].Checks[5],
			str:                "2:45 ../kubernetes/kube-apiserver --option --admission-control=WebHook,RBAC ---audit-log-maxage=40",
			strConfig:          "",
			expectedTestResult: "'--admission-control' does not have 'AlwaysAdmit'",
		},
		{
			check:              controls.Groups[0].Checks[6],
			str:                "2:45 .. --kubelet-clientkey=foo --kubelet-client-certificate=bar --admission-control=Webhook,RBAC",
			strConfig:          "",
			expectedTestResult: "'--kubelet-client-certificate' is present AND '--kubelet-clientkey' is present",
		},
		{
			check:              controls.Groups[0].Checks[7],
			str:                "2:45 ..  --secure-port=0 --kubelet-client-certificate=bar --admission-control=Webhook,RBAC",
			strConfig:          "",
			expectedTestResult: "'--secure-port' is equal to '0' OR '--secure-port' is not present",
		},
		{
			check:              controls.Groups[0].Checks[8],
			str:                "permissions=SomeValue",
			strConfig:          "",
			expectedTestResult: "'permissions' is equal to 'SomeValue'",
		},
		{
			check:              controls.Groups[0].Checks[9],
			str:                "permissions=640",
			strConfig:          "",
			expectedTestResult: "permissions has permissions 640, expected 644 or more restrictive",
		},
		{
			check:              controls.Groups[0].Checks[9],
			str:                "permissions=600",
			strConfig:          "",
			expectedTestResult: "permissions has permissions 600, expected 644 or more restrictive",
		},
		{
			check:              controls.Groups[0].Checks[10],
			str:                "2:45 ../kubernetes/kube-apiserver --option --admission-control=WebHook,RBAC ---audit-log-maxage=40",
			strConfig:          "",
			expectedTestResult: "'--admission-control' has 'RBAC'",
		},
		{
			check:              controls.Groups[0].Checks[11],
			str:                "2:45 ../kubernetes/kube-apiserver --option --admission-control=WebHook,RBAC ---audit-log-maxage=40",
			strConfig:          "",
			expectedTestResult: "'--admission-control' has 'WebHook'",
		},
		{
			check:              controls.Groups[0].Checks[12],
			str:                "2:45 ../kubernetes/kube-apiserver --option --admission-control=WebHook,Something,RBAC ---audit-log-maxage=40",
			strConfig:          "",
			expectedTestResult: "'--admission-control' has 'Something'",
		},
		{
			check:              controls.Groups[0].Checks[13],
			str:                "2:45 ../kubernetes/kube-apiserver --option --admission-control=Something ---audit-log-maxage=40",
			strConfig:          "",
			expectedTestResult: "'--admission-control' has 'Something'",
		},
		{
			// check for ':' as argument-value separator, with space between arg and val
			check:              controls.Groups[0].Checks[14],
			str:                "2:45 kube-apiserver some-arg: some-val --admission-control=Something ---audit-log-maxage=40",
			strConfig:          "",
			expectedTestResult: "'some-arg' is equal to 'some-val'",
		},
		{
			// check for ':' as argument-value separator, with no space between arg and val
			check:              controls.Groups[0].Checks[14],
			str:                "2:45 kube-apiserver some-arg:some-val --admission-control=Something ---audit-log-maxage=40",
			strConfig:          "",
			expectedTestResult: "'some-arg' is equal to 'some-val'",
		},
		{
			check:              controls.Groups[0].Checks[15],
			str:                "",
			strConfig:          "{\"readOnlyPort\": 15000}",
			expectedTestResult: "'{.readOnlyPort}' is equal to '15000' OR '{.readOnlyPort}' is greater or equal to 15000 OR '{.readOnlyPort}' is lower or equal to 15000",
		},
		{
			check:              controls.Groups[0].Checks[16],
			str:                "",
			strConfig:          "{\"stringValue\": \"WebHook,Something,RBAC\"}",
			expectedTestResult: "'{.stringValue}' is not equal to 'None' AND '{.stringValue}' is not equal to 'webhook,Something,RBAC' AND '{.stringValue}' is equal to 'WebHook,Something,RBAC'",
		},
		{
			check:              controls.Groups[0].Checks[17],
			str:                "",
			strConfig:          "{\"trueValue\": true}",
			expectedTestResult: "'{.trueValue}' is not equal to 'somethingElse' AND '{.trueValue}' is not equal to 'false' AND '{.trueValue}' is equal to 'true'",
		},
		{
			check:              controls.Groups[0].Checks[18],
			str:                "",
			strConfig:          "{\"readOnlyPort\": 15000}",
			expectedTestResult: "'{.notARealField}' is not present",
		},
		{
			check:              controls.Groups[0].Checks[19],
			str:                "",
			strConfig:          "{\"authentication\": { \"anonymous\": {\"enabled\": false}}}",
			expectedTestResult: "'{.authentication.anonymous.enabled}' is equal to 'false'",
		},
		{
			check:              controls.Groups[0].Checks[20],
			str:                "",
			strConfig:          "readOnlyPort: 15000",
			expectedTestResult: "'{.readOnlyPort}' is greater than 14999",
		},
		{
			check:              controls.Groups[0].Checks[21],
			str:                "",
			strConfig:          "readOnlyPort: 15000",
			expectedTestResult: "'{.fieldThatIsUnset}' is not present",
		},
		{
			check:              controls.Groups[0].Checks[22],
			str:                "",
			strConfig:          "authentication:\n  anonymous:\n    enabled: false",
			expectedTestResult: "'{.authentication.anonymous.enabled}' is equal to 'false'",
		},
		{
			check:              controls.Groups[0].Checks[26],
			str:                "",
			strConfig:          "currentMasterVersion: 1.12.7",
			expectedTestResult: "'{.currentMasterVersion}' matched by regex expression '^1\\.12.*$'",
		},
		{
			check:              controls.Groups[0].Checks[27],
			str:                "--peer-client-cert-auth",
			strConfig:          "",
			expectedTestResult: "'--peer-client-cert-auth' is equal to 'true'",
		},
		{
			check:              controls.Groups[0].Checks[27],
			str:                "--abc=true --peer-client-cert-auth --efg=false",
			strConfig:          "",
			expectedTestResult: "'--peer-client-cert-auth' is equal to 'true'",
		},
		{
			check:              controls.Groups[0].Checks[27],
			str:                "--abc --peer-client-cert-auth --efg",
			strConfig:          "",
			expectedTestResult: "'--peer-client-cert-auth' is equal to 'true'",
		},
		{
			check:              controls.Groups[0].Checks[27],
			str:                "--peer-client-cert-auth=true",
			strConfig:          "",
			expectedTestResult: "'--peer-client-cert-auth' is equal to 'true'",
		},
		{
			check:              controls.Groups[0].Checks[27],
			str:                "--abc --peer-client-cert-auth=true --efg",
			strConfig:          "",
			expectedTestResult: "'--peer-client-cert-auth' is equal to 'true'",
		},
		{
			check:              controls.Groups[0].Checks[28],
			str:                "--abc --peer-client-cert-auth=false --efg",
			strConfig:          "",
			expectedTestResult: "'--peer-client-cert-auth' is equal to 'false'",
		},
		{
			check:              controls.Groups[0].Checks[29],
			str:                "2:45 ../kubernetes/kube-apiserver --option1=20,30,40",
			strConfig:          "",
			expectedTestResult: "'ALLOW_PRIVILEGED' is present",
			strEnv:             "SOME_OTHER_ENV=true\nALLOW_PRIVILEGED=false",
		},
		{
			check:              controls.Groups[0].Checks[30],
			str:                "2:45 ../kubernetes/kube-apiserver --option1=20,30,40",
			strConfig:          "",
			expectedTestResult: "'BASIC_AUTH' is not present",
			strEnv:             "",
		},
		{
			check:              controls.Groups[0].Checks[31],
			str:                "2:45 ../kubernetes/kube-apiserver --option1=20,30,40",
			strConfig:          "",
			expectedTestResult: "'INSECURE_PORT' is equal to '0'",
			strEnv:             "INSECURE_PORT=0",
		},
		{
			check:              controls.Groups[0].Checks[32],
			str:                "2:45 ../kubernetes/kube-apiserver --option1=20,30,40",
			strConfig:          "",
			expectedTestResult: "'AUDIT_LOG_MAXAGE' is greater or equal to 30",
			strEnv:             "AUDIT_LOG_MAXAGE=40",
		},
		{
			check:              controls.Groups[0].Checks[33],
			str:                "2:45 ../kubernetes/kube-apiserver --option1=20,30,40",
			strConfig:          "",
			expectedTestResult: "'MAX_BACKLOG' is lower than 30",
			strEnv:             "MAX_BACKLOG=20",
		},
	}

	for _, c := range cases {
		t.Run(c.check.Text, func(t *testing.T) {
			c.check.AuditOutput = c.str
			c.check.AuditConfigOutput = c.strConfig
			c.check.AuditEnvOutput = c.strEnv
			res, err := c.check.execute()
			if err != nil {
				t.Errorf(err.Error())
			}
			if !res.testResult {
				t.Errorf("Test ID %v - expected:%v, got:%v", c.check.ID, true, res)
			}
			if res.ExpectedResult != c.expectedTestResult {
				t.Errorf("Test ID %v - \nexpected:%v, \ngot:     %v", c.check.ID, c.expectedTestResult, res.ExpectedResult)
			}
		})
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
		t.Run(c.Text, func(t *testing.T) {
			c.Check.AuditConfigOutput = c.str
			res, err := c.Check.execute()
			if err != nil {
				t.Errorf(err.Error())
			}
			if res.testResult {
				t.Errorf("expected:%v, got:%v", false, res)
			}
		})
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
		},
		{
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

	for id, c := range cases {
		t.Run(fmt.Sprintf("%d", id), func(t *testing.T) {
			err := unmarshal(c.content, &c.jsonInterface)
			if err != nil {
				if !c.expectedToFail {
					t.Errorf("should pass, got error:%v", err)
				}
			} else {
				if c.expectedToFail {
					t.Errorf("should fail, but passed")
				}
			}
		})
	}
}

func TestExecuteJSONPath(t *testing.T) {
	type kubeletConfig struct {
		Kind       string
		ApiVersion string
		Address    string
	}
	cases := []struct {
		name           string
		jsonPath       string
		jsonInterface  kubeletConfig
		expectedResult string
		expectedToFail bool
	}{
		{
			"JSONPath parse works, results don't match",
			"{.resourcesproviders.aescbc}",
			kubeletConfig{
				Kind:       "KubeletConfiguration",
				ApiVersion: "kubelet.config.k8s.io/v1beta1",
				Address:    "127.0.0.0",
			},
			"blah",
			true,
		},
		{
			"JSONPath parse works, results match",
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
			"JSONPath parse fails",
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
		t.Run(c.name, func(t *testing.T) {
			result, err := executeJSONPath(c.jsonPath, c.jsonInterface)
			if err != nil && !c.expectedToFail {
				t.Fatalf("jsonPath:%q, expectedResult:%q got:%v", c.jsonPath, c.expectedResult, err)
			}
			if c.expectedResult != result && !c.expectedToFail {
				t.Errorf("jsonPath:%q, expectedResult:%q got:%q", c.jsonPath, c.expectedResult, result)
			}
		})
	}
}

func TestAllElementsValid(t *testing.T) {
	cases := []struct {
		source []string
		target []string
		valid  bool
	}{
		{
			source: []string{},
			target: []string{},
			valid:  true,
		},
		{
			source: []string{"blah"},
			target: []string{},
			valid:  false,
		},
		{
			source: []string{},
			target: []string{
				"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
				"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
				"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305", "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
				"TLS_RSA_WITH_AES_256_GCM_SHA384", "TLS_RSA_WITH_AES_128_GCM_SHA256",
			},
			valid: false,
		},
		{
			source: []string{"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
			target: []string{
				"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
				"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
				"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305", "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
				"TLS_RSA_WITH_AES_256_GCM_SHA384", "TLS_RSA_WITH_AES_128_GCM_SHA256",
			},
			valid: true,
		},
		{
			source: []string{"blah"},
			target: []string{
				"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
				"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
				"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305", "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
				"TLS_RSA_WITH_AES_256_GCM_SHA384", "TLS_RSA_WITH_AES_128_GCM_SHA256",
			},
			valid: false,
		},
		{
			source: []string{"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "blah"},
			target: []string{
				"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
				"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
				"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305", "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
				"TLS_RSA_WITH_AES_256_GCM_SHA384", "TLS_RSA_WITH_AES_128_GCM_SHA256",
			},
			valid: false,
		},
	}
	for id, c := range cases {
		t.Run(fmt.Sprintf("%d", id), func(t *testing.T) {
			if !allElementsValid(c.source, c.target) && c.valid {
				t.Errorf("Not All Elements in %q are found in %q", c.source, c.target)
			}
		})
	}
}

func TestSplitAndRemoveLastSeparator(t *testing.T) {
	cases := []struct {
		source     string
		valid      bool
		elementCnt int
	}{
		{
			source:     "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_GCM_SHA256",
			valid:      true,
			elementCnt: 8,
		},
		{
			source:     "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,",
			valid:      true,
			elementCnt: 2,
		},
		{
			source:     "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,",
			valid:      true,
			elementCnt: 2,
		},
		{
			source:     "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, ",
			valid:      true,
			elementCnt: 2,
		},
		{
			source:     " TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,",
			valid:      true,
			elementCnt: 2,
		},
	}

	for id, c := range cases {
		t.Run(fmt.Sprintf("%d", id), func(t *testing.T) {
			as := splitAndRemoveLastSeparator(c.source, defaultArraySeparator)
			if len(as) == 0 && c.valid {
				t.Errorf("Split did not work with %q", c.source)
			}

			if c.elementCnt != len(as) {
				t.Errorf("Split did not work with %q expected: %d got: %d", c.source, c.elementCnt, len(as))
			}
		})
	}
}

func TestCompareOp(t *testing.T) {
	cases := []struct {
		label                 string
		op                    string
		flagVal               string // Test output.
		compareValue          string // Flag value to compare with.
		expectedResultPattern string
		flagName              string // Compared flag name.
		testResult            bool
	}{
		// Test Op not matching
		{label: "empty - op", op: "", flagVal: "", compareValue: "", expectedResultPattern: "", testResult: false, flagName: ""},
		{label: "op=blah", op: "blah", flagVal: "foo", compareValue: "bar", expectedResultPattern: "", testResult: false, flagName: ""},

		// Test Op "eq"
		{label: "op=eq, both empty", op: "eq", flagVal: "", compareValue: "", expectedResultPattern: "'' is equal to ''", testResult: true, flagName: ""},

		{
			label: "op=eq, true==true", op: "eq", flagVal: "true",
			compareValue:          "true",
			expectedResultPattern: "'parameterTrue' is equal to 'true'",
			testResult:            true,
			flagName:              "parameterTrue",
		},

		{
			label: "op=eq, false==false", op: "eq", flagVal: "false",
			compareValue:          "false",
			expectedResultPattern: "'parameterFalse' is equal to 'false'",
			testResult:            true,
			flagName:              "parameterFalse",
		},

		{
			label: "op=eq, false==true", op: "eq", flagVal: "false",
			compareValue:          "true",
			expectedResultPattern: "'parameterFalse' is equal to 'true'",
			testResult:            false,
			flagName:              "parameterFalse",
		},

		{
			label: "op=eq, strings match", op: "eq", flagVal: "KubeletConfiguration",
			compareValue:          "KubeletConfiguration",
			expectedResultPattern: "'--FlagNameKubeletConf' is equal to 'KubeletConfiguration'",
			testResult:            true,
			flagName:              "--FlagNameKubeletConf",
		},

		{
			label: "op=eq, flagVal=empty", op: "eq", flagVal: "",
			compareValue:          "KubeletConfiguration",
			expectedResultPattern: "'--FlagNameKubeletConf' is equal to 'KubeletConfiguration'",
			testResult:            false,
			flagName:              "--FlagNameKubeletConf",
		},

		{
			label:                 "op=eq, compareValue=empty",
			op:                    "eq",
			flagVal:               "KubeletConfiguration",
			compareValue:          "",
			expectedResultPattern: "'--FlagNameKubeletConf' is equal to ''",
			testResult:            false,
			flagName:              "--FlagNameKubeletConf",
		},

		// Test Op "noteq"
		{
			label:                 "op=noteq, both empty",
			op:                    "noteq",
			flagVal:               "",
			compareValue:          "",
			expectedResultPattern: "'parameter' is not equal to ''",
			testResult:            false,
			flagName:              "parameter",
		},

		{
			label:                 "op=noteq, true!=true",
			op:                    "noteq",
			flagVal:               "true",
			compareValue:          "true",
			expectedResultPattern: "'parameterTrue' is not equal to 'true'",
			testResult:            false,
			flagName:              "parameterTrue",
		},

		{
			label:                 "op=noteq, false!=false",
			op:                    "noteq",
			flagVal:               "false",
			compareValue:          "false",
			expectedResultPattern: "'parameterFalse' is not equal to 'false'",
			testResult:            false,
			flagName:              "parameterFalse",
		},

		{
			label:                 "op=noteq, false!=true",
			op:                    "noteq",
			flagVal:               "false",
			compareValue:          "true",
			expectedResultPattern: "'parameterFalse' is not equal to 'true'",
			testResult:            true,
			flagName:              "parameterFalse",
		},

		{
			label:                 "op=noteq, strings match",
			op:                    "noteq",
			flagVal:               "KubeletConfiguration",
			compareValue:          "KubeletConfiguration",
			expectedResultPattern: "'--FlagNameKubeletConf' is not equal to 'KubeletConfiguration'",
			testResult:            false,
			flagName:              "--FlagNameKubeletConf",
		},

		{
			label:                 "op=noteq, flagVal=empty",
			op:                    "noteq",
			flagVal:               "",
			compareValue:          "KubeletConfiguration",
			expectedResultPattern: "'--FlagNameKubeletConf' is not equal to 'KubeletConfiguration'",
			testResult:            true,
			flagName:              "--FlagNameKubeletConf",
		},

		{
			label:                 "op=noteq, compareValue=empty",
			op:                    "noteq",
			flagVal:               "KubeletConfiguration",
			compareValue:          "",
			expectedResultPattern: "'--FlagNameKubeletConf' is not equal to ''",
			testResult:            true,
			flagName:              "--FlagNameKubeletConf",
		},

		// Test Op "gt"
		{
			label:                 "op=gt, both empty",
			op:                    "gt",
			flagVal:               "",
			compareValue:          "",
			expectedResultPattern: "Invalid Number(s) used for comparison: '' ''",
			testResult:            false,
			flagName:              "flagName",
		},
		{
			label:        "op=gt, 0 > 0",
			op:           "gt",
			flagVal:      "0",
			compareValue: "0", expectedResultPattern: "'flagName' is greater than 0",
			testResult: false,
			flagName:   "flagName",
		},
		{
			label:                 "op=gt, 4 > 5",
			op:                    "gt",
			flagVal:               "4",
			compareValue:          "5",
			expectedResultPattern: "'flagName' is greater than 5",
			testResult:            false,
			flagName:              "flagName",
		},
		{
			label:                 "op=gt, 5 > 4",
			op:                    "gt",
			flagVal:               "5",
			compareValue:          "4",
			expectedResultPattern: "'flagName' is greater than 4",
			testResult:            true,
			flagName:              "flagName",
		},
		{
			label:                 "op=gt, 5 > 5",
			op:                    "gt",
			flagVal:               "5",
			compareValue:          "5",
			expectedResultPattern: "'flagName' is greater than 5",
			testResult:            false,
			flagName:              "flagName",
		},
		{
			label:                 "op=gt, Pikachu > 5",
			op:                    "gt",
			flagVal:               "Pikachu",
			compareValue:          "5",
			expectedResultPattern: "Invalid Number(s) used for comparison: 'Pikachu' '5'",
			testResult:            false,
			flagName:              "flagName",
		},
		{
			label:                 "op=gt, 5 > Bulbasaur",
			op:                    "gt",
			flagVal:               "5",
			compareValue:          "Bulbasaur",
			expectedResultPattern: "Invalid Number(s) used for comparison: '5' 'Bulbasaur'",
			testResult:            false,
			flagName:              "flagName",
		},
		// Test Op "lt"
		{
			label:                 "op=lt, both empty",
			op:                    "lt",
			flagVal:               "",
			compareValue:          "",
			expectedResultPattern: "Invalid Number(s) used for comparison: '' ''",
			testResult:            false,
			flagName:              "flagName",
		},
		{
			label:                 "op=lt, 0 < 0",
			op:                    "lt",
			flagVal:               "0",
			compareValue:          "0",
			expectedResultPattern: "'flagName' is lower than 0",
			testResult:            false,
			flagName:              "flagName",
		},
		{
			label:                 "op=lt, 4 < 5",
			op:                    "lt",
			flagVal:               "4",
			compareValue:          "5",
			expectedResultPattern: "'flagName' is lower than 5",
			testResult:            true,
			flagName:              "flagName",
		},
		{
			label:                 "op=lt, 5 < 4",
			op:                    "lt",
			flagVal:               "5",
			compareValue:          "4",
			expectedResultPattern: "'flagName' is lower than 4",
			testResult:            false,
			flagName:              "flagName",
		},
		{
			label:                 "op=lt, 5 < 5",
			op:                    "lt",
			flagVal:               "5",
			compareValue:          "5",
			expectedResultPattern: "'flagName' is lower than 5",
			testResult:            false,
			flagName:              "flagName",
		},
		{
			label:                 "op=lt, Charmander < 5",
			op:                    "lt",
			flagVal:               "Charmander",
			compareValue:          "5",
			expectedResultPattern: "Invalid Number(s) used for comparison: 'Charmander' '5'",
			testResult:            false,
			flagName:              "flagName",
		},
		{
			label:                 "op=lt, 5 < Charmeleon",
			op:                    "lt",
			flagVal:               "5",
			compareValue:          "Charmeleon",
			expectedResultPattern: "Invalid Number(s) used for comparison: '5' 'Charmeleon'",
			testResult:            false,
			flagName:              "flagName",
		},
		// Test Op "gte"
		{
			label:                 "op=gte, both empty",
			op:                    "gte",
			flagVal:               "",
			compareValue:          "",
			expectedResultPattern: "Invalid Number(s) used for comparison: '' ''",
			testResult:            false,
			flagName:              "flagName",
		},
		{
			label:                 "op=gte, 0 >= 0",
			op:                    "gte",
			flagVal:               "0",
			compareValue:          "0",
			expectedResultPattern: "'flagName' is greater or equal to 0",
			testResult:            true,
			flagName:              "flagName",
		},
		{
			label:                 "op=gte, 4 >= 5",
			op:                    "gte",
			flagVal:               "4",
			compareValue:          "5",
			expectedResultPattern: "'flagName' is greater or equal to 5",
			testResult:            false,
			flagName:              "flagName",
		},
		{
			label:                 "op=gte, 5 >= 4",
			op:                    "gte",
			flagVal:               "5",
			compareValue:          "4",
			expectedResultPattern: "'flagName' is greater or equal to 4",
			testResult:            true,
			flagName:              "flagName",
		},
		{
			label:                 "op=gte, 5 >= 5",
			op:                    "gte",
			flagVal:               "5",
			compareValue:          "5",
			expectedResultPattern: "'flagName' is greater or equal to 5",
			testResult:            true,
			flagName:              "flagName",
		},
		{
			label:                 "op=gte, Ekans >= 5",
			op:                    "gte",
			flagVal:               "Ekans",
			compareValue:          "5",
			expectedResultPattern: "Invalid Number(s) used for comparison: 'Ekans' '5'",
			testResult:            false,
			flagName:              "flagName",
		},
		{
			label:                 "op=gte, 4 >= Zubat",
			op:                    "gte",
			flagVal:               "4",
			compareValue:          "Zubat",
			expectedResultPattern: "Invalid Number(s) used for comparison: '4' 'Zubat'",
			testResult:            false,
			flagName:              "flagName",
		},
		// Test Op "lte"
		{
			label:                 "op=lte, both empty",
			op:                    "lte",
			flagVal:               "",
			compareValue:          "",
			expectedResultPattern: "Invalid Number(s) used for comparison: '' ''",
			testResult:            false,
			flagName:              "flagName",
		},
		{
			label:                 "op=lte, 0 <= 0",
			op:                    "lte",
			flagVal:               "0",
			compareValue:          "0",
			expectedResultPattern: "'flagName' is lower or equal to 0",
			testResult:            true,
			flagName:              "flagName",
		},
		{
			label:                 "op=lte, 4 <= 5",
			op:                    "lte",
			flagVal:               "4",
			compareValue:          "5",
			expectedResultPattern: "'flagName' is lower or equal to 5",
			testResult:            true,
			flagName:              "flagName",
		},
		{
			label:                 "op=lte, 5 <= 4",
			op:                    "lte",
			flagVal:               "5",
			compareValue:          "4",
			expectedResultPattern: "'flagName' is lower or equal to 4",
			testResult:            false,
			flagName:              "flagName",
		},
		{
			label:                 "op=lte, 5 <= 5",
			op:                    "lte",
			flagVal:               "5",
			compareValue:          "5",
			expectedResultPattern: "'flagName' is lower or equal to 5",
			testResult:            true,
			flagName:              "flagName",
		},
		{
			label:                 "op=lte, Venomoth <= 4",
			op:                    "lte",
			flagVal:               "Venomoth",
			compareValue:          "4",
			expectedResultPattern: "Invalid Number(s) used for comparison: 'Venomoth' '4'",
			testResult:            false,
			flagName:              "flagName",
		},
		{
			label:                 "op=lte, 5 <= Meowth",
			op:                    "lte",
			flagVal:               "5",
			compareValue:          "Meowth",
			expectedResultPattern: "Invalid Number(s) used for comparison: '5' 'Meowth'",
			testResult:            false,
			flagName:              "flagName",
		},

		// Test Op "has"
		{
			label:                 "op=has, both empty",
			op:                    "has",
			flagVal:               "",
			compareValue:          "",
			expectedResultPattern: "'flagName' has ''",
			testResult:            true,
			flagName:              "flagName",
		},
		{
			label:                 "op=has, flagVal=empty",
			op:                    "has",
			flagVal:               "",
			compareValue:          "blah",
			expectedResultPattern: "'flagName' has 'blah'",
			testResult:            false,
			flagName:              "flagName",
		},
		{
			label:                 "op=has, compareValue=empty",
			op:                    "has",
			flagVal:               "blah",
			compareValue:          "",
			expectedResultPattern: "'flagName-blah' has ''",
			testResult:            true,
			flagName:              "flagName-blah",
		},
		{
			label:                 "op=has, 'blah' has 'la'",
			op:                    "has",
			flagVal:               "blah",
			compareValue:          "la",
			expectedResultPattern: "'flagName-blah' has 'la'",
			testResult:            true,
			flagName:              "flagName-blah",
		},
		{
			label:                 "op=has, 'blah' has 'LA'",
			op:                    "has",
			flagVal:               "blah",
			compareValue:          "LA",
			expectedResultPattern: "'flagName-blah' has 'LA'",
			testResult:            false,
			flagName:              "flagName-blah",
		},
		{
			label:                 "op=has, 'blah' has 'lo'",
			op:                    "has",
			flagVal:               "blah",
			compareValue:          "lo",
			expectedResultPattern: "'flagName-blah' has 'lo'",
			testResult:            false,
			flagName:              "flagName-blah",
		},

		// Test Op "nothave"
		{
			label:                 "op=nothave, both empty",
			op:                    "nothave",
			flagVal:               "",
			compareValue:          "",
			expectedResultPattern: "'flagName' does not have ''",
			testResult:            false,
			flagName:              "flagName",
		},
		{
			label:                 "op=nothave, flagVal=empty",
			op:                    "nothave",
			flagVal:               "",
			compareValue:          "blah",
			expectedResultPattern: "'flagName' does not have 'blah'",
			testResult:            true,
			flagName:              "flagName",
		},
		{
			label:                 "op=nothave, compareValue=empty",
			op:                    "nothave",
			flagVal:               "blah",
			compareValue:          "",
			expectedResultPattern: "'flagName-blah' does not have ''",
			testResult:            false,
			flagName:              "flagName-blah",
		},
		{
			label:                 "op=nothave, 'blah' not have 'la'",
			op:                    "nothave",
			flagVal:               "blah",
			compareValue:          "la",
			expectedResultPattern: "'flagName-blah' does not have 'la'",
			testResult:            false,
			flagName:              "flagName-blah",
		},
		{
			label:                 "op=nothave, 'blah' not have 'LA'",
			op:                    "nothave",
			flagVal:               "blah",
			compareValue:          "LA",
			expectedResultPattern: "'flagName-blah' does not have 'LA'",
			testResult:            true,
			flagName:              "flagName-blah",
		},
		{
			label:                 "op=nothave, 'blah' not have 'lo'",
			op:                    "nothave",
			flagVal:               "blah",
			compareValue:          "lo",
			expectedResultPattern: "'flagName-blah' does not have 'lo'",
			testResult:            true,
			flagName:              "flagName-blah",
		},

		// Test Op "regex"
		{
			label:                 "op=regex, both empty",
			op:                    "regex",
			flagVal:               "",
			compareValue:          "",
			expectedResultPattern: "'flagName' matched by regex expression ''",
			testResult:            true,
			flagName:              "flagName",
		},
		{
			label:                 "op=regex, flagVal=empty",
			op:                    "regex",
			flagVal:               "",
			compareValue:          "blah",
			expectedResultPattern: "'flagName' matched by regex expression 'blah'",
			testResult:            false,
			flagName:              "flagName",
		},

		// Test Op "valid_elements"
		{
			label:                 "op=valid_elements, valid_elements both empty",
			op:                    "valid_elements",
			flagVal:               "",
			compareValue:          "",
			expectedResultPattern: "'flagWithMultipleElements' contains valid elements from ''",
			testResult:            true,
			flagName:              "flagWithMultipleElements",
		},

		{
			label:                 "op=valid_elements, valid_elements flagVal empty",
			op:                    "valid_elements",
			flagVal:               "",
			compareValue:          "a,b",
			expectedResultPattern: "'flagWithMultipleElements' contains valid elements from 'a,b'",
			testResult:            false,
			flagName:              "flagWithMultipleElements",
		},

		{
			label:                 "op=valid_elements, valid_elements compareValue empty",
			op:                    "valid_elements",
			flagVal:               "a,b",
			compareValue:          "",
			expectedResultPattern: "'flagWithMultipleElements' contains valid elements from ''",
			testResult:            false,
			flagName:              "flagWithMultipleElements",
		},
		{
			label:                 "op=valid_elements, valid_elements two list equals",
			op:                    "valid_elements",
			flagVal:               "a,b,c",
			compareValue:          "a,b,c",
			expectedResultPattern: "'flagWithMultipleElements' contains valid elements from 'a,b,c'",
			testResult:            true,
			flagName:              "flagWithMultipleElements",
		},
		{
			label:                 "op=valid_elements, valid_elements partial flagVal valid",
			op:                    "valid_elements",
			flagVal:               "a,c",
			compareValue:          "a,b,c",
			expectedResultPattern: "'flagWithMultipleElements' contains valid elements from 'a,b,c'",
			testResult:            true,
			flagName:              "flagWithMultipleElements",
		},
		{
			label:                 "op=valid_elements, valid_elements partial compareValue valid",
			op:                    "valid_elements",
			flagVal:               "a,b,c",
			compareValue:          "a,c",
			expectedResultPattern: "'flagWithMultipleElements' contains valid elements from 'a,c'",
			testResult:            false,
			flagName:              "flagWithMultipleElements",
		},

		// Test Op "bitmask"
		{
			label:                 "op=bitmask, 644 AND 640",
			op:                    "bitmask",
			flagVal:               "640",
			compareValue:          "644",
			expectedResultPattern: "etc/fileExamplePermission640 has permissions 640, expected 644 or more restrictive",
			testResult:            true,
			flagName:              "etc/fileExamplePermission640",
		},
		{
			label:                 "op=bitmask, 644 AND 777",
			op:                    "bitmask",
			flagVal:               "777",
			compareValue:          "644",
			expectedResultPattern: "etc/fileExamplePermission777 has permissions 777, expected 644 or more restrictive",
			testResult:            false,
			flagName:              "etc/fileExamplePermission777",
		},
		{
			label:                 "op=bitmask, 644 AND 444",
			op:                    "bitmask",
			flagVal:               "444",
			compareValue:          "644",
			expectedResultPattern: "etc/fileExamplePermission444 has permissions 444, expected 644 or more restrictive",
			testResult:            true,
			flagName:              "etc/fileExamplePermission444",
		},
		{
			label:                 "op=bitmask, 644 AND 211",
			op:                    "bitmask",
			flagVal:               "211",
			compareValue:          "644",
			expectedResultPattern: "etc/fileExamplePermission211 has permissions 211, expected 644 or more restrictive",
			testResult:            false,
			flagName:              "etc/fileExamplePermission211",
		},
		{
			label:                 "op=bitmask, Harry AND 211",
			op:                    "bitmask",
			flagVal:               "Harry",
			compareValue:          "644",
			expectedResultPattern: "Not numeric value - flag: Harry",
			testResult:            false,
			flagName:              "etc/fileExample",
		},
		{
			label:                 "op=bitmask, 644 AND Potter",
			op:                    "bitmask",
			flagVal:               "211",
			compareValue:          "Potter",
			expectedResultPattern: "Not numeric value - flag: Potter",
			testResult:            false,
			flagName:              "etc/fileExample",
		},
	}

	for _, c := range cases {
		t.Run(c.label, func(t *testing.T) {
			expectedResultPattern, testResult := compareOp(c.op, c.flagVal, c.compareValue, c.flagName)
			if expectedResultPattern != c.expectedResultPattern {
				t.Errorf("'expectedResultPattern' did not match - op: %q expected:%q  got:%q", c.op, c.expectedResultPattern, expectedResultPattern)
			}

			if testResult != c.testResult {
				t.Errorf("'testResult' did not match - lop: %q expected:%t  got:%t", c.op, c.testResult, testResult)
			}
		})
	}
}

func TestToNumeric(t *testing.T) {
	cases := []struct {
		firstValue     string
		secondValue    string
		expectedToFail bool
	}{
		{
			firstValue:     "a",
			secondValue:    "b",
			expectedToFail: true,
		},
		{
			firstValue:     "5",
			secondValue:    "b",
			expectedToFail: true,
		},
		{
			firstValue:     "5",
			secondValue:    "6",
			expectedToFail: false,
		},
	}

	for id, c := range cases {
		t.Run(fmt.Sprintf("%d", id), func(t *testing.T) {
			f, s, err := toNumeric(c.firstValue, c.secondValue)
			if c.expectedToFail && err == nil {
				t.Errorf("Expected error while converting %s and %s", c.firstValue, c.secondValue)
			}

			if !c.expectedToFail && (f != 5 || s != 6) {
				t.Errorf("Expected to return %d,%d - got %d,%d", 5, 6, f, s)
			}
		})
	}
}

func TestExecuteJSONPathOnEncryptionConfig(t *testing.T) {
	type Resources struct {
		Resources []string                 `json:"resources"`
		Providers []map[string]interface{} `json:"providers"`
	}

	type EncryptionConfig struct {
		Kind       string      `json:"kind"`
		ApiVersion string      `json:"apiVersion"`
		Resources  []Resources `json:"resources"`
	}

	type Key struct {
		Secret string `json:"secret"`
		Name   string `json:"name"`
	}

	type Aescbc struct {
		Keys []Key `json:"keys"`
	}

	type SecretBox struct {
		Keys []Key `json:"keys"`
	}

	type Aesgcm struct {
		Keys []Key `json:"keys"`
	}

	// identity disable encryption when set as the first parameter
	type Identity struct{}

	cases := []struct {
		name           string
		jsonPath       string
		jsonInterface  EncryptionConfig
		expectedResult string
		expectedToFail bool
	}{
		{
			"JSONPath parse works, results match",
			"{.resources[*].providers[*].aescbc.keys[*].secret}",
			EncryptionConfig{
				Kind:       "EncryptionConfig",
				ApiVersion: "v1",
				Resources: []Resources{{Resources: []string{"secrets"}, Providers: []map[string]interface{}{
					{"aescbc": Aescbc{Keys: []Key{{Secret: "secret1", Name: "name1"}}}},
				}}},
			},
			"secret1",
			false,
		},
		{
			"JSONPath parse works, results match",
			"{.resources[*].providers[*].aescbc.keys[*].name}",
			EncryptionConfig{
				Kind:       "EncryptionConfig",
				ApiVersion: "v1",
				Resources: []Resources{{Resources: []string{"secrets"}, Providers: []map[string]interface{}{
					{"aescbc": Aescbc{Keys: []Key{{Secret: "secret1", Name: "name1"}}}},
				}}},
			},
			"name1",
			false,
		},
		{
			"JSONPath parse works, results don't match",
			"{.resources[*].providers[*].aescbc.keys[*].secret}",
			EncryptionConfig{
				Kind:       "EncryptionConfig",
				ApiVersion: "v1",
				Resources: []Resources{{Resources: []string{"secrets"}, Providers: []map[string]interface{}{
					{"aesgcm": Aesgcm{Keys: []Key{{Secret: "secret1", Name: "name1"}}}},
				}}},
			},
			"secret1",
			true,
		},
		{
			"JSONPath parse works, results match",
			"{.resources[*].providers[*].aesgcm.keys[*].secret}",
			EncryptionConfig{
				Kind:       "EncryptionConfig",
				ApiVersion: "v1",
				Resources: []Resources{{Resources: []string{"secrets"}, Providers: []map[string]interface{}{
					{"aesgcm": Aesgcm{Keys: []Key{{Secret: "secret1", Name: "name1"}}}},
				}}},
			},
			"secret1",
			false,
		},
		{
			"JSONPath parse works, results match",
			"{.resources[*].providers[*].secretbox.keys[*].secret}",
			EncryptionConfig{
				Kind:       "EncryptionConfig",
				ApiVersion: "v1",
				Resources: []Resources{{Resources: []string{"secrets"}, Providers: []map[string]interface{}{
					{"secretbox": SecretBox{Keys: []Key{{Secret: "secret1", Name: "name1"}}}},
				}}},
			},
			"secret1",
			false,
		},
		{
			"JSONPath parse works, results match",
			"{.resources[*].providers[*].aescbc.keys[*].secret}",
			EncryptionConfig{
				Kind:       "EncryptionConfig",
				ApiVersion: "v1",
				Resources: []Resources{{Resources: []string{"secrets"}, Providers: []map[string]interface{}{
					{"aescbc": Aescbc{Keys: []Key{{Secret: "secret1", Name: "name1"}, {Secret: "secret2", Name: "name2"}}}},
				}}},
			},
			"secret1 secret2",
			false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			result, err := executeJSONPath(c.jsonPath, c.jsonInterface)
			if err != nil && !c.expectedToFail {
				t.Fatalf("jsonPath:%q, expectedResult:%q got:%v", c.jsonPath, c.expectedResult, err)
			}
			if c.expectedResult != result && !c.expectedToFail {
				t.Errorf("jsonPath:%q, expectedResult:%q got:%q", c.jsonPath, c.expectedResult, result)
			}
		})
	}
}
