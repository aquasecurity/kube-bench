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
	controls, err = NewControls(MASTER, in)
	if err != nil {
		panic("Failed creating test controls: " + err.Error())
	}
}

func TestTestExecute(t *testing.T) {
	cases := []struct {
		*tests
		testfor string
		str     string
	}{
		{
			controls.Groups[0].Checks[0].Tests,
			"flag set",
			"2:45 ../kubernetes/kube-apiserver --allow-privileged=false --option1=20,30,40",
		},
		{
			controls.Groups[0].Checks[1].Tests,
			"flag not set",
			"2:45 ../kubernetes/kube-apiserver --allow-privileged=false",
		},
		{
			controls.Groups[0].Checks[2].Tests,
			"flag and value set",
			"niinai   13617  2635 99 19:26 pts/20   00:03:08 ./kube-apiserver --insecure-port=0 --anonymous-auth",
		},
		{
			controls.Groups[0].Checks[3].Tests,
			"flag value greater than value",
			"2:45 ../kubernetes/kube-apiserver --secure-port=0 --audit-log-maxage=40 --option",
		},
		{
			controls.Groups[0].Checks[4].Tests,
			"flag value less than value",
			"2:45 ../kubernetes/kube-apiserver --max-backlog=20 --secure-port=0 --audit-log-maxage=40 --option",
		},
		{
			controls.Groups[0].Checks[5].Tests,
			"flag value does not have",
			"2:45 ../kubernetes/kube-apiserver --option --admission-control=WebHook,RBAC ---audit-log-maxage=40",
		},
		{
			controls.Groups[0].Checks[6].Tests,
			"AND multiple tests, all testitems pass",
			"2:45 .. --kubelet-clientkey=foo --kubelet-client-certificate=bar --admission-control=Webhook,RBAC",
		},
		{
			controls.Groups[0].Checks[7].Tests,
			"OR multiple tests",
			"2:45 ..  --secure-port=0 --kubelet-client-certificate=bar --admission-control=Webhook,RBAC",
		},
		{
			controls.Groups[0].Checks[8].Tests,
			"text",
			"644",
		},
		{
			controls.Groups[0].Checks[9].Tests,
			"flag value is comma-separated",
			"2:35 ../kubelet --features-gates=KubeletClient=true,KubeletServer=true",
		},
		{
			controls.Groups[0].Checks[9].Tests,
			"flag value is comma-separated",
			"2:35 ../kubelet --features-gates=KubeletServer=true,KubeletClient=true",
		},
	}

	for _, c := range cases {
		res := c.tests.execute(c.str)
		if !res {
			t.Errorf("%s, expected:%v, got:%v\n", c.testfor, true, res)
		}
	}
}
