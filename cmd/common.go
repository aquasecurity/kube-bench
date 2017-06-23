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
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/aquasecurity/kube-bench/check"
	"github.com/fatih/color"
	"github.com/spf13/viper"
)

var (
	kubeMasterBin  = []string{"kube-apiserver", "kube-scheduler", "kube-controller-manager"}
	kubeMasterConf = []string{}

	kubeNodeBin  = []string{"kubelet"}
	kubeNodeConf = []string{}

	kubeFederatedBin  = []string{"federation-apiserver", "federation-controller-manager"}
	kubeFederatedConf = []string{}

	// TODO: Consider specifying this in config file.
	kubeVersion = "Kubernetes v1.6"

	// Used for variable substitution
	symbols = map[string]string{}

	// Print colors
	colors = map[check.State]*color.Color{
		check.PASS: color.New(color.FgGreen),
		check.FAIL: color.New(color.FgRed),
		check.WARN: color.New(color.FgYellow),
		check.INFO: color.New(color.FgBlue),
	}
)

func runChecks(t check.NodeType) {
	var summary check.Summary
	var warnings []string
	var file string

	// Set up for config file check.
	kubeMasterConf = append(kubeMasterConf, viper.Get("kubeConfDir").(string)+"/apiserver")
	kubeMasterConf = append(kubeMasterConf, viper.Get("kubeConfDir").(string)+"/scheduler")
	kubeMasterConf = append(kubeMasterConf, viper.Get("kubeConfDir").(string)+"/controller-manager")
	kubeMasterConf = append(kubeMasterConf, viper.Get("kubeConfDir").(string)+"/config")
	kubeMasterConf = append(kubeMasterConf, viper.Get("etcdConfDir").(string)+"/etcd.conf")
	kubeMasterConf = append(kubeMasterConf, viper.Get("flanneldConfDir").(string)+"/flanneld")
	kubeNodeConf = append(kubeNodeConf, viper.Get("kubeConfDir").(string)+"/kubelet")
	kubeNodeConf = append(kubeNodeConf, viper.Get("kubeConfDir").(string)+"/proxy")

	warnings, err := verifyNodeType(t, warnings)
	if err != nil {
		for _, w := range warnings {
			colorPrint(check.WARN, w)
		}

		fmt.Fprintf(os.Stderr, "failed to verify node type: %v\n", err)
		os.Exit(1)
	}

	switch t {
	case check.MASTER:
		file = masterFile
	case check.NODE:
		file = nodeFile
	case check.FEDERATED:
		file = federatedFile
	}

	in, err := ioutil.ReadFile(file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error opening %s controls file: %s\n", t, err)
		os.Exit(1)
	}

	// Variable substitutions. Replace all occurrences of variables in controls file.
	s := strings.Replace(string(in), "$kubeConfDir", viper.Get("kubeConfDir").(string), -1)
	s = strings.Replace(s, "$etcdConfDir", viper.Get("etcdConfDir").(string), -1)
	s = strings.Replace(s, "$flanneldConfDir", viper.Get("flanneldConfDir").(string), -1)

	controls := check.NewControls(t, []byte(s))

	if groupList != "" && checkList == "" {
		ids := cleanIDs(groupList)
		summary = controls.RunGroup(ids...)

	} else if checkList != "" && groupList == "" {
		ids := cleanIDs(checkList)
		summary = controls.RunChecks(ids...)

	} else if checkList != "" && groupList != "" {
		fmt.Fprintf(os.Stderr, "group option and check option can't be used together\n")
		os.Exit(1)

	} else {
		summary = controls.RunGroup()
	}

	// if we successfully ran some tests and it's json format, ignore the warnings
	if (summary.Fail > 0 || summary.Warn > 0 || summary.Pass > 0) && jsonFmt {
		out, err := controls.JSON()
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to output in JSON format: %v\n", err)
			os.Exit(1)
		}

		fmt.Println(string(out))
	} else {
		prettyPrint(warnings, controls, summary)
	}
}

func cleanIDs(list string) []string {
	list = strings.Trim(list, ",")
	ids := strings.Split(list, ",")

	for _, id := range ids {
		id = strings.Trim(id, " ")
	}

	return ids
}

// verifyNodeType checks the executables and config files are as expected for the specified tests (master, node or federated)
func verifyNodeType(t check.NodeType, w []string) ([]string, error) {
	var binPath []string
	var confPath []string
	var out []byte

	switch t {
	case check.MASTER:
		binPath = kubeMasterBin
		confPath = kubeMasterConf
	case check.NODE:
		binPath = kubeNodeBin
		confPath = kubeNodeConf
	case check.FEDERATED:
		binPath = kubeFederatedBin
		confPath = kubeFederatedConf
	}

	// These executables might not be on the user's path.
	// TODO! Check the version number using kubectl, which is more likely to be on the path.
	for _, b := range binPath {
		_, err := exec.LookPath(b)
		if err != nil {
			w = append(w, fmt.Sprintf("%s: command not found on path - version check skipped\n", b))
			continue
		}

		// Check version
		cmd := exec.Command(b, "--version")
		out, err = cmd.Output()
		if err != nil {
			return w, fmt.Errorf("failed executing %s --version: %v", b, err)
		}

		matched, err := regexp.MatchString(kubeVersion, string(out))
		if err != nil {
			return w, fmt.Errorf("regexp match for version failed: %v", err)
		}

		if !matched {
			return w, fmt.Errorf(
				"%s unsupported version, expected %s, got %s",
				b,
				kubeVersion,
				string(out),
			)
		}
	}

	// Check if the executables for this type of node are running.
	for _, b := range binPath {
		cmd := exec.Command("ps", "-ef")
		out, err := cmd.Output()
		if err != nil {
			return w, fmt.Errorf("failed executing ps -ef: %v", err)
		}

		matched, err := regexp.MatchString(".*"+b, string(out))
		if err != nil {
			return w, fmt.Errorf("regexp match for ps output failed: %v", err)
		}

		if !matched {
			return w, fmt.Errorf("%s is not running", b)
		}
	}

	// Check whether the config files for this type of node are in the expected location
	for _, c := range confPath {
		if _, err := os.Stat(c); os.IsNotExist(err) {
			w = append(w, fmt.Sprintf("config file %s does not exist\n", c))
		}
	}

	return w, nil
}

// colorPrint outputs the state in a specific colour, along with a message string
func colorPrint(state check.State, s string) {
	colors[state].Printf("[%s] ", state)
	fmt.Printf("%s", s)
}

// prettyPrint outputs the results to stdout in human-readable format
func prettyPrint(warnings []string, r *check.Controls, summary check.Summary) {
	colorPrint(check.INFO, fmt.Sprintf("Using config file: %s\n", viper.ConfigFileUsed()))

	for _, w := range warnings {
		colorPrint(check.WARN, w)
	}

	colorPrint(check.INFO, fmt.Sprintf("%s %s\n", r.ID, r.Text))
	for _, g := range r.Groups {
		colorPrint(check.INFO, fmt.Sprintf("%s %s\n", g.ID, g.Text))
		for _, c := range g.Checks {
			colorPrint(c.State, fmt.Sprintf("%s %s\n", c.ID, c.Text))
		}
	}

	fmt.Println()

	// Print remediations.
	if summary.Fail > 0 || summary.Warn > 0 {
		colors[check.WARN].Printf("== Remediations ==\n")
		for _, g := range r.Groups {
			for _, c := range g.Checks {
				if c.State != check.PASS {
					fmt.Printf("%s %s\n", c.ID, c.Remediation)
				}
			}
		}
		fmt.Println()
	}

	// Print summary setting output color to highest severity.
	var res check.State
	if summary.Fail > 0 {
		res = check.FAIL
	} else if summary.Warn > 0 {
		res = check.WARN
	} else {
		res = check.PASS
	}

	colors[res].Printf("== Summary ==\n")
	fmt.Printf("%d checks PASS\n%d checks FAIL\n%d checks WARN\n",
		summary.Pass, summary.Fail, summary.Warn,
	)
}
