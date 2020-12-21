// Copyright © 2017-2019 Aqua Security Software Ltd. <info@aquasec.com>
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
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"testing"
	"time"

	"github.com/aquasecurity/kube-bench/check"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

type JsonOutputFormat struct {
	Controls     []*check.Controls `json:"Controls"`
	TotalSummary map[string]int    `json:"Totals"`
}

type JsonOutputFormatNoTotals struct {
	Controls []*check.Controls `json:"Controls"`
}

func TestParseSkipIds(t *testing.T) {
	skipMap := parseSkipIds("4.12,4.13,5")
	_, fourTwelveExists := skipMap["4.12"]
	_, fourThirteenExists := skipMap["4.13"]
	_, fiveExists := skipMap["5"]
	_, other := skipMap["G1"]
	assert.True(t, fourThirteenExists)
	assert.True(t, fourTwelveExists)
	assert.True(t, fiveExists)
	assert.False(t, other)
}

func TestNewRunFilter(t *testing.T) {

	type TestCase struct {
		Name       string
		FilterOpts FilterOpts
		Group      *check.Group
		Check      *check.Check

		Expected bool
	}

	testCases := []TestCase{
		{
			Name:       "Should return true when scored flag is enabled and check is scored",
			FilterOpts: FilterOpts{Scored: true, Unscored: false},
			Group:      &check.Group{},
			Check:      &check.Check{Scored: true},
			Expected:   true,
		},
		{
			Name:       "Should return false when scored flag is enabled and check is not scored",
			FilterOpts: FilterOpts{Scored: true, Unscored: false},
			Group:      &check.Group{},
			Check:      &check.Check{Scored: false},
			Expected:   false,
		},

		{
			Name:       "Should return true when unscored flag is enabled and check is not scored",
			FilterOpts: FilterOpts{Scored: false, Unscored: true},
			Group:      &check.Group{},
			Check:      &check.Check{Scored: false},
			Expected:   true,
		},
		{
			Name:       "Should return false when unscored flag is enabled and check is scored",
			FilterOpts: FilterOpts{Scored: false, Unscored: true},
			Group:      &check.Group{},
			Check:      &check.Check{Scored: true},
			Expected:   false,
		},

		{
			Name:       "Should return true when group flag contains group's ID",
			FilterOpts: FilterOpts{Scored: true, Unscored: true, GroupList: "G1,G2,G3"},
			Group:      &check.Group{ID: "G2"},
			Check:      &check.Check{},
			Expected:   true,
		},
		{
			Name:       "Should return false when group flag doesn't contain group's ID",
			FilterOpts: FilterOpts{GroupList: "G1,G3"},
			Group:      &check.Group{ID: "G2"},
			Check:      &check.Check{},
			Expected:   false,
		},

		{
			Name:       "Should return true when check flag contains check's ID",
			FilterOpts: FilterOpts{Scored: true, Unscored: true, CheckList: "C1,C2,C3"},
			Group:      &check.Group{},
			Check:      &check.Check{ID: "C2"},
			Expected:   true,
		},
		{
			Name:       "Should return false when check flag doesn't contain check's ID",
			FilterOpts: FilterOpts{CheckList: "C1,C3"},
			Group:      &check.Group{},
			Check:      &check.Check{ID: "C2"},
			Expected:   false,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Name, func(t *testing.T) {
			filter, _ := NewRunFilter(testCase.FilterOpts)
			assert.Equal(t, testCase.Expected, filter(testCase.Group, testCase.Check))
		})
	}

	t.Run("Should return error when both group and check flags are used", func(t *testing.T) {
		// given
		opts := FilterOpts{GroupList: "G1", CheckList: "C1"}
		// when
		_, err := NewRunFilter(opts)
		// then
		assert.EqualError(t, err, "group option and check option can't be used together")
	})

}

func TestIsMaster(t *testing.T) {
	testCases := []struct {
		name            string
		cfgFile         string
		getBinariesFunc func(*viper.Viper, check.NodeType) (map[string]string, error)
		isMaster        bool
	}{
		{
			name:    "valid config, is master and all components are running",
			cfgFile: "../cfg/config.yaml",
			getBinariesFunc: func(viper *viper.Viper, nt check.NodeType) (strings map[string]string, i error) {
				return map[string]string{"apiserver": "kube-apiserver"}, nil
			},
			isMaster: true,
		},
		{
			name:    "valid config, is master and but not all components are running",
			cfgFile: "../cfg/config.yaml",
			getBinariesFunc: func(viper *viper.Viper, nt check.NodeType) (strings map[string]string, i error) {
				return map[string]string{}, nil
			},
			isMaster: false,
		},
		{
			name:    "valid config, is master, not all components are running and fails to find all binaries",
			cfgFile: "../cfg/config.yaml",
			getBinariesFunc: func(viper *viper.Viper, nt check.NodeType) (strings map[string]string, i error) {
				return map[string]string{}, errors.New("failed to find binaries")
			},
			isMaster: false,
		},
		{
			name:     "valid config, does not include master",
			cfgFile:  "../hack/node_only.yaml",
			isMaster: false,
		},
	}
	cfgDirOld := cfgDir
	cfgDir = "../cfg"
	defer func() {
		cfgDir = cfgDirOld
	}()

	execCode := `#!/bin/sh
	echo "Server Version: v1.13.10"
	`
	restore, err := fakeExecutableInPath("kubectl", execCode)
	if err != nil {
		t.Fatal("Failed when calling fakeExecutableInPath ", err)
	}
	defer restore()

	for _, tc := range testCases {
		cfgFile = tc.cfgFile
		initConfig()

		oldGetBinariesFunc := getBinariesFunc
		getBinariesFunc = tc.getBinariesFunc
		defer func() {
			getBinariesFunc = oldGetBinariesFunc
			cfgFile = ""
		}()

		assert.Equal(t, tc.isMaster, isMaster(), tc.name)
	}
}

func TestMapToCISVersion(t *testing.T) {

	viperWithData, err := loadConfigForTest()
	if err != nil {
		t.Fatalf("Unable to load config file %v", err)
	}
	kubeToBenchmarkMap, err := loadVersionMapping(viperWithData)
	if err != nil {
		t.Fatalf("Unable to load config file %v", err)
	}

	cases := []struct {
		kubeVersion string
		succeed     bool
		exp         string
		expErr      string
	}{
		{kubeVersion: "1.9", succeed: false, exp: "", expErr: "unable to find a matching Benchmark Version match for kubernetes version: 1.9"},
		{kubeVersion: "1.11", succeed: false, exp: "", expErr: "unable to find a matching Benchmark Version match for kubernetes version: 1.11"},
		{kubeVersion: "1.12", succeed: false, exp: "", expErr: "unable to find a matching Benchmark Version match for kubernetes version: 1.12"},
		{kubeVersion: "1.13", succeed: false, exp: "", expErr: "unable to find a matching Benchmark Version match for kubernetes version: 1.13"},
		{kubeVersion: "1.14", succeed: false, exp: "", expErr: "unable to find a matching Benchmark Version match for kubernetes version: 1.14"},
		{kubeVersion: "1.15", succeed: true, exp: "cis-1.5"},
		{kubeVersion: "1.16", succeed: true, exp: "cis-1.6"},
		{kubeVersion: "1.17", succeed: true, exp: "cis-1.6"},
		{kubeVersion: "1.18", succeed: true, exp: "cis-1.6"},
		{kubeVersion: "1.19", succeed: true, exp: "cis-1.6"},
		{kubeVersion: "gke-1.0", succeed: true, exp: "gke-1.0"},
		{kubeVersion: "ocp-3.10", succeed: true, exp: "rh-0.7"},
		{kubeVersion: "ocp-3.11", succeed: true, exp: "rh-0.7"},
		{kubeVersion: "unknown", succeed: false, exp: "", expErr: "unable to find a matching Benchmark Version match for kubernetes version: unknown"},
	}
	for _, c := range cases {
		rv, err := mapToBenchmarkVersion(kubeToBenchmarkMap, c.kubeVersion)
		if c.succeed {
			if err != nil {
				t.Errorf("[%q]-Unexpected error: %v", c.kubeVersion, err)
			}

			if len(rv) == 0 {
				t.Errorf("[%q]-missing return value", c.kubeVersion)
			}

			if c.exp != rv {
				t.Errorf("[%q]- expected %q but Got %q", c.kubeVersion, c.exp, rv)
			}

		} else {
			if c.exp != rv {
				t.Errorf("[%q]-mapToBenchmarkVersion kubeversion: %q Got %q expected %s", c.kubeVersion, c.kubeVersion, rv, c.exp)
			}

			if c.expErr != err.Error() {
				t.Errorf("[%q]-mapToBenchmarkVersion expected Error: %q instead Got %q", c.kubeVersion, c.expErr, err.Error())
			}
		}
	}
}

func TestLoadVersionMapping(t *testing.T) {
	setDefault := func(v *viper.Viper, key string, value interface{}) *viper.Viper {
		v.SetDefault(key, value)
		return v
	}

	viperWithData, err := loadConfigForTest()
	if err != nil {
		t.Fatalf("Unable to load config file %v", err)
	}

	cases := []struct {
		n       string
		v       *viper.Viper
		succeed bool
	}{
		{n: "empty", v: viper.New(), succeed: false},
		{
			n:       "novals",
			v:       setDefault(viper.New(), "version_mapping", "novals"),
			succeed: false,
		},
		{
			n:       "good",
			v:       viperWithData,
			succeed: true,
		},
	}
	for _, c := range cases {
		rv, err := loadVersionMapping(c.v)
		if c.succeed {
			if err != nil {
				t.Errorf("[%q]-Unexpected error: %v", c.n, err)
			}

			if len(rv) == 0 {
				t.Errorf("[%q]-missing mapping value", c.n)
			}
		} else {
			if err == nil {
				t.Errorf("[%q]-Expected error but got none", c.n)
			}
		}
	}
}

func TestGetBenchmarkVersion(t *testing.T) {
	viperWithData, err := loadConfigForTest()
	if err != nil {
		t.Fatalf("Unable to load config file %v", err)
	}

	type getBenchmarkVersionFnToTest func(kubeVersion, benchmarkVersion string, v *viper.Viper) (string, error)

	withFakeKubectl := func(kubeVersion, benchmarkVersion string, v *viper.Viper, fn getBenchmarkVersionFnToTest) (string, error) {
		execCode := `#!/bin/sh
		echo '{"serverVersion": {"major": "1", "minor": "15", "gitVersion": "v1.15.10"}}'
		`
		restore, err := fakeExecutableInPath("kubectl", execCode)
		if err != nil {
			t.Fatal("Failed when calling fakeExecutableInPath ", err)
		}
		defer restore()

		return fn(kubeVersion, benchmarkVersion, v)
	}

	withNoPath := func(kubeVersion, benchmarkVersion string, v *viper.Viper, fn getBenchmarkVersionFnToTest) (string, error) {
		restore, err := prunePath()
		if err != nil {
			t.Fatal("Failed when calling prunePath ", err)
		}
		defer restore()

		return fn(kubeVersion, benchmarkVersion, v)
	}

	type getBenchmarkVersionFn func(string, string, *viper.Viper, getBenchmarkVersionFnToTest) (string, error)
	cases := []struct {
		n                string
		kubeVersion      string
		benchmarkVersion string
		v                *viper.Viper
		callFn           getBenchmarkVersionFn
		exp              string
		succeed          bool
	}{
		{n: "both versions", kubeVersion: "1.11", benchmarkVersion: "cis-1.3", exp: "cis-1.3", callFn: withNoPath, v: viper.New(), succeed: false},
		{n: "no version-missing-kubectl", kubeVersion: "", benchmarkVersion: "", v: viperWithData, exp: "", callFn: withNoPath, succeed: false},
		{n: "no version-fakeKubectl", kubeVersion: "", benchmarkVersion: "", v: viperWithData, exp: "cis-1.5", callFn: withFakeKubectl, succeed: true},
		{n: "kubeVersion", kubeVersion: "1.15", benchmarkVersion: "", v: viperWithData, exp: "cis-1.5", callFn: withNoPath, succeed: true},
		{n: "ocpVersion310", kubeVersion: "ocp-3.10", benchmarkVersion: "", v: viperWithData, exp: "rh-0.7", callFn: withNoPath, succeed: true},
		{n: "ocpVersion311", kubeVersion: "ocp-3.11", benchmarkVersion: "", v: viperWithData, exp: "rh-0.7", callFn: withNoPath, succeed: true},
		{n: "gke10", kubeVersion: "gke-1.0", benchmarkVersion: "", v: viperWithData, exp: "gke-1.0", callFn: withNoPath, succeed: true},
	}
	for _, c := range cases {
		rv, err := c.callFn(c.kubeVersion, c.benchmarkVersion, c.v, getBenchmarkVersion)
		if c.succeed {
			if err != nil {
				t.Errorf("[%q]-Unexpected error: %v", c.n, err)
			}

			if len(rv) == 0 {
				t.Errorf("[%q]-missing return value", c.n)
			}

			if c.exp != rv {
				t.Errorf("[%q]- expected %q but Got %q", c.n, c.exp, rv)
			}
		} else {
			if err == nil {
				t.Errorf("[%q]-Expected error but got none", c.n)
			}
		}
	}
}

func TestValidTargets(t *testing.T) {
	viperWithData, err := loadConfigForTest()
	if err != nil {
		t.Fatalf("Unable to load config file %v", err)
	}
	cases := []struct {
		name      string
		benchmark string
		targets   []string
		expected  bool
	}{
		{
			name:      "cis-1.5 no dummy",
			benchmark: "cis-1.5",
			targets:   []string{"master", "node", "controlplane", "etcd", "dummy"},
			expected:  false,
		},
		{
			name:      "cis-1.5 valid",
			benchmark: "cis-1.5",
			targets:   []string{"master", "node", "controlplane", "etcd", "policies"},
			expected:  true,
		},
		{
			name:      "cis-1.6 no Pikachu",
			benchmark: "cis-1.6",
			targets:   []string{"master", "node", "controlplane", "etcd", "Pikachu"},
			expected:  false,
		},
		{
			name:      "cis-1.6 valid",
			benchmark: "cis-1.6",
			targets:   []string{"master", "node", "controlplane", "etcd", "policies"},
			expected:  true,
		},
		{
			name:      "gke-1.0 valid",
			benchmark: "gke-1.0",
			targets:   []string{"master", "node", "controlplane", "etcd", "policies", "managedservices"},
			expected:  true,
		},
		{
			name:      "aks-1.0 valid",
			benchmark: "aks-1.0",
			targets:   []string{"node", "policies", "controlplane", "managedservices"},
			expected:  true,
		},
		{
			name:      "eks-1.0 valid",
			benchmark: "eks-1.0",
			targets:   []string{"node", "policies", "controlplane", "managedservices"},
			expected:  true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ret, err := validTargets(c.benchmark, c.targets, viperWithData)
			if err != nil {
				t.Fatalf("Expected nil error, got: %v", err)
			}
			if ret != c.expected {
				t.Fatalf("Expected %t, got %t", c.expected, ret)
			}
		})
	}
}

func TestIsEtcd(t *testing.T) {
	testCases := []struct {
		name            string
		cfgFile         string
		getBinariesFunc func(*viper.Viper, check.NodeType) (map[string]string, error)
		isEtcd          bool
	}{
		{
			name:    "valid config, is etcd and all components are running",
			cfgFile: "../cfg/config.yaml",
			getBinariesFunc: func(viper *viper.Viper, nt check.NodeType) (strings map[string]string, i error) {
				return map[string]string{"etcd": "etcd"}, nil
			},
			isEtcd: true,
		},
		{
			name:    "valid config, is etcd and but not all components are running",
			cfgFile: "../cfg/config.yaml",
			getBinariesFunc: func(viper *viper.Viper, nt check.NodeType) (strings map[string]string, i error) {
				return map[string]string{}, nil
			},
			isEtcd: false,
		},
		{
			name:    "valid config, is etcd, not all components are running and fails to find all binaries",
			cfgFile: "../cfg/config.yaml",
			getBinariesFunc: func(viper *viper.Viper, nt check.NodeType) (strings map[string]string, i error) {
				return map[string]string{}, errors.New("failed to find binaries")
			},
			isEtcd: false,
		},
		{
			name:    "valid config, does not include etcd",
			cfgFile: "../hack/node_only.yaml",
			isEtcd:  false,
		},
	}
	cfgDirOld := cfgDir
	cfgDir = "../cfg"
	defer func() {
		cfgDir = cfgDirOld
	}()

	execCode := `#!/bin/sh
	echo "Server Version: v1.15.03"
	`
	restore, err := fakeExecutableInPath("kubectl", execCode)
	if err != nil {
		t.Fatal("Failed when calling fakeExecutableInPath ", err)
	}
	defer restore()

	for _, tc := range testCases {
		cfgFile = tc.cfgFile
		initConfig()

		oldGetBinariesFunc := getBinariesFunc
		getBinariesFunc = tc.getBinariesFunc
		defer func() {
			getBinariesFunc = oldGetBinariesFunc
			cfgFile = ""
		}()

		assert.Equal(t, tc.isEtcd, isEtcd(), tc.name)
	}
}

func TestWriteResultToJsonFile(t *testing.T) {
	defer func() {
		controlsCollection = []*check.Controls{}
		jsonFmt = false
		outputFile = ""
	}()
	var err error
	jsonFmt = true
	outputFile = path.Join(os.TempDir(), fmt.Sprintf("%d", time.Now().UnixNano()))

	controlsCollection, err = parseControlsJsonFile("./testdata/controlsCollection.json")
	if err != nil {
		t.Error(err)
	}
	writeOutput(controlsCollection)

	var expect JsonOutputFormat
	var result JsonOutputFormat
	result, err = parseResultJsonFile(outputFile)
	if err != nil {
		t.Error(err)
	}
	expect, err = parseResultJsonFile("./testdata/result.json")
	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, expect, result)
}

func TestWriteResultNoTotalsToJsonFile(t *testing.T) {
	defer func() {
		controlsCollection = []*check.Controls{}
		jsonFmt = false
		outputFile = ""
	}()
	var err error
	jsonFmt = true
	outputFile = path.Join(os.TempDir(), fmt.Sprintf("%d", time.Now().UnixNano()))

	noTotals = true

	controlsCollection, err = parseControlsJsonFile("./testdata/controlsCollection.json")
	if err != nil {
		t.Error(err)
	}
	writeOutput(controlsCollection)

	var expect []*check.Controls
	var result []*check.Controls
	result, err = parseResultNoTotalsJsonFile(outputFile)
	if err != nil {
		t.Error(err)
	}
	expect, err = parseResultNoTotalsJsonFile("./testdata/result_no_totals.json")
	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, expect, result)
}

func TestExitCodeSelection(t *testing.T) {
	exitCode = 10
	controlsCollectionAllPassed, errPassed := parseControlsJsonFile("./testdata/passedControlsCollection.json")
	if errPassed != nil {
		t.Error(errPassed)
	}
	controlsCollectionWithFailures, errFailure := parseControlsJsonFile("./testdata/controlsCollection.json")
	if errFailure != nil {
		t.Error(errFailure)
	}

	exitCodePassed := exitCodeSelection(controlsCollectionAllPassed)
	assert.Equal(t, 0, exitCodePassed)

	exitCodeFailure := exitCodeSelection(controlsCollectionWithFailures)
	assert.Equal(t, 10, exitCodeFailure)
}

func TestGenerationDefaultEnvAudit(t *testing.T) {
	input := []byte(`
---
type: "master"
groups:
- id: G1
  checks:
  - id: G1/C1
- id: G2
  checks:
  - id: G2/C1
    text: "Verify that the SomeSampleFlag argument is set to true"
    audit: "grep -B1 SomeSampleFlag=true /this/is/a/file/path"
    tests:
      test_items:
      - flag: "SomeSampleFlag=true"
        env: "SOME_SAMPLE_FLAG"
        compare:
          op: has
          value: "true"
        set: true
    remediation: |
      Edit the config file /this/is/a/file/path and set SomeSampleFlag to true.
    scored: true
`)
	controls, err := check.NewControls(check.MASTER, input)
	assert.NoError(t, err)

	binSubs := []string{"TestBinPath"}
	generateDefaultEnvAudit(controls, binSubs)

	expectedAuditEnv := fmt.Sprintf("cat \"/proc/$(/bin/ps -C %s -o pid= | tr -d ' ')/environ\" | tr '\\0' '\\n'", binSubs[0])
	assert.Equal(t, expectedAuditEnv, controls.Groups[1].Checks[0].AuditEnv)
}

func TestGetSummaryTotals(t *testing.T) {
	controlsCollection, err := parseControlsJsonFile("./testdata/controlsCollection.json")
	if err != nil {
		t.Error(err)
	}

	resultTotals := getSummaryTotals(controlsCollection)
	assert.Equal(t, 12, resultTotals.Fail)
	assert.Equal(t, 14, resultTotals.Warn)
	assert.Equal(t, 0, resultTotals.Info)
	assert.Equal(t, 49, resultTotals.Pass)
}

func TestPrintSummary(t *testing.T) {
	controlsCollection, err := parseControlsJsonFile("./testdata/controlsCollection.json")
	if err != nil {
		t.Error(err)
	}

	resultTotals := getSummaryTotals(controlsCollection)
	rescueStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	printSummary(resultTotals, "totals")
	w.Close()
	out, _ := ioutil.ReadAll(r)
	os.Stdout = rescueStdout

	assert.Contains(t, string(out), "49 checks PASS\n12 checks FAIL\n14 checks WARN\n0 checks INFO\n\n")
}

func TestPrettyPrintNoSummary(t *testing.T) {
	controlsCollection, err := parseControlsJsonFile("./testdata/controlsCollection.json")
	if err != nil {
		t.Error(err)
	}

	resultTotals := getSummaryTotals(controlsCollection)
	rescueStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	noSummary = true
	prettyPrint(controlsCollection[0], resultTotals)
	w.Close()
	out, _ := ioutil.ReadAll(r)
	os.Stdout = rescueStdout

	assert.NotContains(t, string(out), "49 checks PASS")
}

func TestPrettyPrintSummary(t *testing.T) {
	controlsCollection, err := parseControlsJsonFile("./testdata/controlsCollection.json")
	if err != nil {
		t.Error(err)
	}

	resultTotals := getSummaryTotals(controlsCollection)
	rescueStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	noSummary = false
	prettyPrint(controlsCollection[0], resultTotals)
	w.Close()
	out, _ := ioutil.ReadAll(r)
	os.Stdout = rescueStdout

	assert.Contains(t, string(out), "49 checks PASS")
}

func TestWriteStdoutOutputNoTotal(t *testing.T) {
	controlsCollection, err := parseControlsJsonFile("./testdata/controlsCollection.json")
	if err != nil {
		t.Error(err)
	}

	rescueStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	noTotals = true
	writeStdoutOutput(controlsCollection)
	w.Close()
	out, _ := ioutil.ReadAll(r)
	os.Stdout = rescueStdout

	assert.NotContains(t, string(out), "49 checks PASS")
}

func TestWriteStdoutOutputTotal(t *testing.T) {
	controlsCollection, err := parseControlsJsonFile("./testdata/controlsCollection.json")
	if err != nil {
		t.Error(err)
	}

	rescueStdout := os.Stdout

	r, w, _ := os.Pipe()

	os.Stdout = w
	noTotals = false
	writeStdoutOutput(controlsCollection)
	w.Close()
	out, _ := ioutil.ReadAll(r)

	os.Stdout = rescueStdout

	assert.Contains(t, string(out), "49 checks PASS")
}

func parseControlsJsonFile(filepath string) ([]*check.Controls, error) {
	var result []*check.Controls

	d, err := ioutil.ReadFile(filepath)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(d, &result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func parseResultJsonFile(filepath string) (JsonOutputFormat, error) {
	var result JsonOutputFormat

	d, err := ioutil.ReadFile(filepath)
	if err != nil {
		return result, err
	}
	err = json.Unmarshal(d, &result)
	if err != nil {
		return result, err
	}

	return result, nil
}

func parseResultNoTotalsJsonFile(filepath string) ([]*check.Controls, error) {
	var result []*check.Controls

	d, err := ioutil.ReadFile(filepath)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(d, &result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func loadConfigForTest() (*viper.Viper, error) {
	viperWithData := viper.New()
	viperWithData.SetConfigFile("../cfg/config.yaml")
	if err := viperWithData.ReadInConfig(); err != nil {
		return nil, err
	}
	return viperWithData, nil
}

type restoreFn func()

func fakeExecutableInPath(execFile, execCode string) (restoreFn, error) {
	pathenv := os.Getenv("PATH")
	tmp, err := ioutil.TempDir("", "TestfakeExecutableInPath")
	if err != nil {
		return nil, err
	}

	wd, err := os.Getwd()
	if err != nil {
		return nil, err
	}

	if len(execCode) > 0 {
		ioutil.WriteFile(filepath.Join(tmp, execFile), []byte(execCode), 0700)
	} else {
		f, err := os.OpenFile(execFile, os.O_CREATE|os.O_EXCL, 0700)
		if err != nil {
			return nil, err
		}
		err = f.Close()
		if err != nil {
			return nil, err
		}
	}

	err = os.Setenv("PATH", fmt.Sprintf("%s:%s", tmp, pathenv))
	if err != nil {
		return nil, err
	}

	restorePath := func() {
		os.RemoveAll(tmp)
		os.Chdir(wd)
		os.Setenv("PATH", pathenv)
	}

	return restorePath, nil
}

func prunePath() (restoreFn, error) {
	pathenv := os.Getenv("PATH")
	err := os.Setenv("PATH", "")
	if err != nil {
		return nil, err
	}
	restorePath := func() {
		os.Setenv("PATH", pathenv)
	}
	return restorePath, nil
}
