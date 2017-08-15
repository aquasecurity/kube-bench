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

package cmd

import (
	"regexp"
	"strconv"
	"testing"
)

func TestCheckVersion(t *testing.T) {
	kubeoutput := `Client Version: version.Info{Major:"1", Minor:"7", GitVersion:"v1.7.0", GitCommit:"d3ada0119e776222f11ec7945e6d860061339aad", GitTreeState:"clean", BuildDate:"2017-06-30T09:51:01Z", GoVersion:"go1.8.3", Compiler:"gc", Platform:"darwin/amd64"}
	Server Version: version.Info{Major:"1", Minor:"7", GitVersion:"v1.7.0", GitCommit:"d3ada0119e776222f11ec7945e6d860061339aad", GitTreeState:"clean", BuildDate:"2017-07-26T00:12:31Z", GoVersion:"go1.8.3", Compiler:"gc", Platform:"linux/amd64"}`
	cases := []struct {
		t     string
		s     string
		major string
		minor string
		exp   string
	}{
		{t: "Client", s: kubeoutput, major: "1", minor: "7"},
		{t: "Server", s: kubeoutput, major: "1", minor: "7"},
		{t: "Client", s: kubeoutput, major: "1", minor: "6", exp: "Unexpected Client version 1.7"},
		{t: "Client", s: kubeoutput, major: "2", minor: "0", exp: "Unexpected Client version 1.7"},
		{t: "Server", s: "something unexpected", major: "2", minor: "0", exp: "Couldn't find Server version from kubectl output 'something unexpected'"},
	}

	for id, c := range cases {
		t.Run(strconv.Itoa(id), func(t *testing.T) {
			m := checkVersion(c.t, c.s, c.major, c.minor)
			if m != c.exp {
				t.Fatalf("Got: %s, expected: %s", m, c.exp)
			}
		})
	}

}

func TestVersionMatch(t *testing.T) {
	minor := regexVersionMinor
	major := regexVersionMajor
	client := `Client Version: version.Info{Major:"1", Minor:"7", GitVersion:"v1.7.0", GitCommit:"d3ada0119e776222f11ec7945e6d860061339aad", GitTreeState:"clean", BuildDate:"2017-06-30T09:51:01Z", GoVersion:"go1.8.3", Compiler:"gc", Platform:"darwin/amd64"}`
	server := `Server Version: version.Info{Major:"1", Minor:"7", GitVersion:"v1.7.0", GitCommit:"d3ada0119e776222f11ec7945e6d860061339aad", GitTreeState:"clean", BuildDate:"2017-07-26T00:12:31Z", GoVersion:"go1.8.3", Compiler:"gc", Platform:"linux/amd64"}`

	cases := []struct {
		r   *regexp.Regexp
		s   string
		exp string
	}{
		{r: major, s: server, exp: "1"},
		{r: minor, s: server, exp: "7"},
		{r: major, s: client, exp: "1"},
		{r: minor, s: client, exp: "7"},
		{r: major, s: "Some unexpected string"},
		{r: minor}, // Checking that we don't fall over if the string is empty
	}

	for id, c := range cases {
		t.Run(strconv.Itoa(id), func(t *testing.T) {
			m := versionMatch(c.r, c.s)
			if m != c.exp {
				t.Fatalf("Got %s expected %s", m, c.exp)
			}
		})
	}
}

var g string

func fakeps(proc string) string {
	return g
}
func TestVerifyBin(t *testing.T) {
	cases := []struct {
		proc  string
		psOut string
		exp   bool
	}{
		{proc: "single", psOut: "single", exp: true},
		{proc: "single", psOut: "", exp: false},
		{proc: "two words", psOut: "two words", exp: true},
		{proc: "two words", psOut: "", exp: false},
		{proc: "cmd", psOut: "cmd param1 param2", exp: true},
		{proc: "cmd param", psOut: "cmd param1 param2", exp: true},
		{proc: "cmd param", psOut: "cmd", exp: false},
	}

	for id, c := range cases {
		t.Run(strconv.Itoa(id), func(t *testing.T) {
			g = c.psOut
			v := verifyBin(c.proc, fakeps)
			if v != c.exp {
				t.Fatalf("Expected %v got %v", c.exp, v)
			}
		})
	}
}

func TestMultiWordReplace(t *testing.T) {
	cases := []struct {
		input   string
		sub     string
		subname string
		output  string
	}{
		{input: "Here's a file with no substitutions", sub: "blah", subname: "blah", output: "Here's a file with no substitutions"},
		{input: "Here's a file with a substitution", sub: "blah", subname: "substitution", output: "Here's a file with a blah"},
		{input: "Here's a file with multi-word substitutions", sub: "multi word", subname: "multi-word", output: "Here's a file with 'multi word' substitutions"},
		{input: "Here's a file with several several substitutions several", sub: "blah", subname: "several", output: "Here's a file with blah blah substitutions blah"},
	}
	for id, c := range cases {
		t.Run(strconv.Itoa(id), func(t *testing.T) {
			s := multiWordReplace(c.input, c.subname, c.sub)
			if s != c.output {
				t.Fatalf("Expected %s got %s", c.output, s)
			}
		})
	}
}
