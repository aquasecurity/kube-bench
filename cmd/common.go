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

	"github.com/aquasecurity/kube-bench/check"
	"github.com/spf13/viper"
)

var (
	apiserverBin            string
	apiserverConf           string
	schedulerBin            string
	schedulerConf           string
	controllerManagerBin    string
	controllerManagerConf   string
	config                  string
	etcdBin                 string
	etcdConf                string
	flanneldBin             string
	flanneldConf            string
	kubeletBin              string
	kubeletConf             string
	proxyBin                string
	proxyConf               string
	fedApiserverBin         string
	fedControllerManagerBin string

	errmsgs string

	// TODO: Consider specifying this in config file.
	kubeMajorVersion = "1"
	kubeMinorVersion = "7"
)

func runChecks(t check.NodeType) {
	var summary check.Summary
	var file string

	// Master variables
	apiserverBin = viper.GetString("installation." + installation + ".master.bin.apiserver")
	apiserverConf = viper.GetString("installation." + installation + ".master.conf.apiserver")
	schedulerBin = viper.GetString("installation." + installation + ".master.bin.scheduler")
	schedulerConf = viper.GetString("installation." + installation + ".master.conf.scheduler")
	controllerManagerBin = viper.GetString("installation." + installation + ".master.bin.controller-manager")
	controllerManagerConf = viper.GetString("installation." + installation + ".master.conf.controller-manager")
	config = viper.GetString("installation." + installation + ".config")

	etcdBin = viper.GetString("etcd.bin")
	etcdConf = viper.GetString("etcd.conf")
	flanneldBin = viper.GetString("flanneld.bin")
	flanneldConf = viper.GetString("flanneld.conf")

	// Node variables
	kubeletBin = viper.GetString("installation." + installation + ".node.bin.kubelet")
	kubeletConf = viper.GetString("installation." + installation + ".node.conf.kubelet")
	proxyBin = viper.GetString("installation." + installation + ".node.bin.proxy")
	proxyConf = viper.GetString("installation." + installation + ".node.conf.proxy")

	// Federated
	fedApiserverBin = viper.GetString("installation." + installation + ".federated.bin.apiserver")
	fedControllerManagerBin = viper.GetString("installation." + installation + ".federated.bin.controller-manager")

	// Run kubernetes installation validation checks.
	verifyKubeVersion(kubeMajorVersion, kubeMinorVersion)
	verifyNodeType(t)

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
		exitWithError(fmt.Errorf("error opening %s controls file: %v", t, err))
	}

	// Variable substitutions. Replace all occurrences of variables in controls files.
	s := multiWordReplace(string(in), "$apiserverbin", apiserverBin)
	s = multiWordReplace(s, "$apiserverconf", apiserverConf)
	s = multiWordReplace(s, "$schedulerbin", schedulerBin)
	s = multiWordReplace(s, "$schedulerconf", schedulerConf)
	s = multiWordReplace(s, "$controllermanagerbin", controllerManagerBin)
	s = multiWordReplace(s, "$controllermanagerconf", controllerManagerConf)
	s = multiWordReplace(s, "$config", config)

	s = multiWordReplace(s, "$etcdbin", etcdBin)
	s = multiWordReplace(s, "$etcdconf", etcdConf)
	s = multiWordReplace(s, "$flanneldbin", flanneldBin)
	s = multiWordReplace(s, "$flanneldconf", flanneldConf)

	s = multiWordReplace(s, "$kubeletbin", kubeletBin)
	s = multiWordReplace(s, "$kubeletconf", kubeletConf)
	s = multiWordReplace(s, "$proxybin", proxyBin)
	s = multiWordReplace(s, "$proxyconf", proxyConf)

	s = multiWordReplace(s, "$fedapiserverbin", fedApiserverBin)
	s = multiWordReplace(s, "$fedcontrollermanagerbin", fedControllerManagerBin)

	controls, err := check.NewControls(t, []byte(s))
	if err != nil {
		exitWithError(fmt.Errorf("error setting up %s controls: %v", t, err))
	}

	if groupList != "" && checkList == "" {
		ids := cleanIDs(groupList)
		summary = controls.RunGroup(ids...)
	} else if checkList != "" && groupList == "" {
		ids := cleanIDs(checkList)
		summary = controls.RunChecks(ids...)
	} else if checkList != "" && groupList != "" {
		exitWithError(fmt.Errorf("group option and check option can't be used together"))
	} else {
		summary = controls.RunGroup()
	}

	// if we successfully ran some tests and it's json format, ignore the warnings
	if (summary.Fail > 0 || summary.Warn > 0 || summary.Pass > 0) && jsonFmt {
		out, err := controls.JSON()
		if err != nil {
			exitWithError(fmt.Errorf("failed to output in JSON format: %v", err))
		}

		fmt.Println(string(out))
	} else {
		prettyPrint(controls, summary)
	}
}

// verifyNodeType checks the executables and config files are as expected
// for the specified tests (master, node or federated).
func verifyNodeType(t check.NodeType) {
	var bins []string
	var confs []string

	switch t {
	case check.MASTER:
		bins = []string{apiserverBin, schedulerBin, controllerManagerBin}
		confs = []string{apiserverConf, schedulerConf, controllerManagerConf}
	case check.NODE:
		bins = []string{kubeletBin, proxyBin}
		confs = []string{kubeletConf, proxyConf}
	case check.FEDERATED:
		bins = []string{fedApiserverBin, fedControllerManagerBin}
	}

	for _, bin := range bins {
		if !verifyBin(bin) {
			printlnWarn(fmt.Sprintf("%s is not running", bin))
		}
	}

	for _, conf := range confs {
		_, err := os.Stat(conf)
		if err != nil {
			if os.IsNotExist(err) {
				printlnWarn(fmt.Sprintf("Missing kubernetes config file: %s", conf))
			} else {
				exitWithError(fmt.Errorf("error looking for file %s: %v", conf, err))
			}
		}
	}
}

// colorPrint outputs the state in a specific colour, along with a message string
func colorPrint(state check.State, s string) {
	colors[state].Printf("[%s] ", state)
	fmt.Printf("%s", s)
}

// prettyPrint outputs the results to stdout in human-readable format
func prettyPrint(r *check.Controls, summary check.Summary) {
	colorPrint(check.INFO, fmt.Sprintf("Using config file: %s\n", viper.ConfigFileUsed()))

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
