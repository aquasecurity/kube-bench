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
	"strings"

	"github.com/aquasecurity/kube-bench/check"
	"github.com/fatih/color"
	"github.com/spf13/viper"
)

var (
	errmsgs string

	kubeMasterBin  = []string{"kube-apiserver", "kube-scheduler", "kube-controller-manager"}
	xMasterBin     = []string{"etcd", "flanneld"}
	kubeMasterConf = []string{}

	kubeNodeBin  = []string{"kubelet"}
	kubeNodeConf = []string{}

	kubeFederatedBin = []string{"federation-apiserver", "federation-controller-manager"}

	// TODO: Consider specifying this in config file.
	kubeVersion = "1.6"

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

func handleError(err error, context string) (errmsg string) {
	if err != nil {
		errmsg = fmt.Sprintf("%s, error: %s\n", context, err)
	}
	return
}

func runChecks(t check.NodeType) {
	var summary check.Summary
	var file string

	warns := verifyNodeType(t)

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
		fmt.Fprintf(os.Stderr, "error opening %s controls file: %v\n", t, err)
		os.Exit(1)
	}

	// Variable substitutions. Replace all occurrences of variables in controls file.
	s := strings.Replace(string(in), "$kubeConfDir", viper.Get("kubeConfDir").(string), -1)
	s = strings.Replace(s, "$etcdConfDir", viper.Get("etcdConfDir").(string), -1)
	s = strings.Replace(s, "$flanneldConfDir", viper.Get("flanneldConfDir").(string), -1)

	controls, err := check.NewControls(t, []byte(s))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error setting up %s controls: %v\n", t, err)
		os.Exit(1)
	}

	if groupList != "" && checkList == "" {
		ids := cleanIDs(groupList)
		summary = controls.RunGroup(verbose, ids...)

	} else if checkList != "" && groupList == "" {
		ids := cleanIDs(checkList)
		summary = controls.RunChecks(verbose, ids...)

	} else if checkList != "" && groupList != "" {
		fmt.Fprintf(os.Stderr, "group option and check option can't be used together\n")
		os.Exit(1)

	} else {
		summary = controls.RunGroup(verbose)
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
		prettyPrint(warns, controls, summary)
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

// verifyNodeType checks the executables and config files are as expected
// for the specified tests (master, node or federated).
// Any check failing here is a show stopper.
func verifyNodeType(t check.NodeType) []string {
	var w []string
	// Always clear out error messages.
	errmsgs = ""

	// Set up and check for config files.
	kubeConfDir = viper.Get("kubeConfDir").(string)
	etcdConfDir = viper.Get("etcdConfDir").(string)
	flanneldConfDir = viper.Get("flanneldConfDir").(string)

	kubeMasterConf = append(kubeMasterConf, kubeConfDir+"/apiserver")
	kubeMasterConf = append(kubeMasterConf, kubeConfDir+"/scheduler")
	kubeMasterConf = append(kubeMasterConf, kubeConfDir+"/controller-manager")
	kubeMasterConf = append(kubeMasterConf, kubeConfDir+"/config")
	kubeMasterConf = append(kubeMasterConf, etcdConfDir+"/etcd.conf")
	kubeMasterConf = append(kubeMasterConf, flanneldConfDir+"/flanneld")

	kubeNodeConf = append(kubeNodeConf, kubeConfDir+"/kubelet")
	kubeNodeConf = append(kubeNodeConf, kubeConfDir+"/proxy")

	switch t {
	case check.MASTER:
		w = append(w, verifyBin(kubeMasterBin)...)
		w = append(w, verifyBin(xMasterBin)...)
		w = append(w, verifyConf(kubeMasterConf)...)
		w = append(w, verifyKubeVersion(kubeMasterBin[0])...)
	case check.NODE:
		w = append(w, verifyBin(kubeNodeBin)...)
		w = append(w, verifyConf(kubeNodeConf)...)
		w = append(w, verifyKubeVersion(kubeNodeBin[0])...)
	case check.FEDERATED:
		w = append(w, verifyBin(kubeFederatedBin)...)
		w = append(w, verifyKubeVersion(kubeFederatedBin[0])...)
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "%s\n", errmsgs)
	}

	return w
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

func verifyConf(confPath []string) []string {
	var w []string
	for _, c := range confPath {
		if _, err := os.Stat(c); err != nil && os.IsNotExist(err) {
			w = append(w, fmt.Sprintf("config file %s does not exist\n", c))
		}
	}

	return w
}

func verifyBin(binPath []string) []string {
	var w []string
	var binList string

	// Construct proc name for ps(1)
	for _, b := range binPath {
		binList += b + ","
	}
	binList = strings.Trim(binList, ",")

	// Run ps command
	cmd := exec.Command("ps", "-C", binList, "-o", "cmd", "--no-headers")
	out, err := cmd.Output()
	errmsgs += handleError(
		err,
		fmt.Sprintf("verifyBin: %s failed", binList),
	)

	// Actual verification
	for _, b := range binPath {
		matched := strings.Contains(string(out), b)

		if !matched {
			w = append(w, fmt.Sprintf("%s is not running\n", b))
		}
	}

	return w
}

func verifyKubeVersion(b string) []string {
	// These executables might not be on the user's path.
	// TODO! Check the version number using kubectl, which is more likely to be on the path.
	var w []string

	// Check version
	cmd := exec.Command(b, "--version")
	out, err := cmd.Output()
	errmsgs += handleError(
		err,
		fmt.Sprintf("verifyKubeVersion: failed"),
	)

	matched := strings.Contains(string(out), kubeVersion)
	if !matched {
		w = append(w, fmt.Sprintf("%s unsupported version\n", b))
	}

	return w
}
