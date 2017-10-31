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
	"time"

	"github.com/aquasecurity/kube-bench/check"
	"github.com/golang/glog"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
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
)

func runChecks(t check.NodeType) {
	var summary check.Summary
	var file string
	var err error
	var typeConf *viper.Viper

	switch t {
	case check.MASTER:
		file = masterFile
		typeConf = viper.Sub("master")
	case check.NODE:
		file = nodeFile
		typeConf = viper.Sub("node")
	case check.FEDERATED:
		file = federatedFile
		typeConf = viper.Sub("federated")
	}

	// Get the set of exectuables and config files we care about on this type of node. This also
	// checks that the executables we need for the node type are running.
	binmap := getBinaries(typeConf)
	confmap := getConfigFiles(typeConf)

	switch t {
	case check.MASTER:
		file = masterFile
	case check.NODE:
		file = nodeFile
	case check.FEDERATED:
		file = federatedFile
	}

	ver := getKubeVersion()
	path := fmt.Sprintf("%s/%s/%s", cfgDir, ver.Server, file)
	in, err := ioutil.ReadFile(path)
	if err != nil {
		exitWithError(fmt.Errorf("error opening %s controls file: %v", t, err))
	}

	// Variable substitutions. Replace all occurrences of variables in controls files.
	s := string(in)
	s = makeSubstitutions(s, "bin", binmap)
	s = makeSubstitutions(s, "conf", confmap)

	glog.V(1).Info(fmt.Sprintf("Using config file: %s\n", viper.ConfigFileUsed()))
	glog.V(1).Info(fmt.Sprintf("Using benchmark file: %s\n", path))

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
		// if we want to store in PostgreSQL, convert to JSON and save it
		if (summary.Fail > 0 || summary.Warn > 0 || summary.Pass > 0) && pgSql {
			out, err := controls.JSON()
			if err != nil {
				exitWithError(fmt.Errorf("failed to output in JSON format: %v", err))
			}

			savePgsql(string(out))
		} else {
			prettyPrint(controls, summary)
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

func savePgsql(jsonInfo	 string) {
	envVars := map[string]string{
		"PGSQL_HOST":     viper.GetString("PGSQL_HOST"),
		"PGSQL_USER":     viper.GetString("PGSQL_USER"),
		"PGSQL_DBNAME":   viper.GetString("PGSQL_DBNAME"),
		"PGSQL_SSLMODE":  viper.GetString("PGSQL_SSLMODE"),
		"PGSQL_PASSWORD": viper.GetString("PGSQL_PASSWORD"),
	}

	for k, v := range envVars {
		if v == "" {
			err := fmt.Errorf("Environment variable %s missing", envVarsPrefix+"_"+k)
			panic(err)
		}
	}

	connInfo := fmt.Sprintf("host=%s user=%s dbname=%s sslmode=%s password=%s",
		envVars["PGSQL_HOST"],
		envVars["PGSQL_USER"],
		envVars["PGSQL_DBNAME"],
		envVars["PGSQL_SSLMODE"],
		envVars["PGSQL_PASSWORD"],
	)

	hostname, err := os.Hostname()
	if err != nil {
		panic(err)
	}

	timestamp := time.Now()

	type ScanResult struct {
		gorm.Model
		ScanHost string    `gorm:"type:varchar(63) not null"` // https://www.ietf.org/rfc/rfc1035.txt
		ScanTime time.Time `gorm:"not null"`
		ScanInfo string    `gorm:"type:jsonb not null"`
	}

	db, err := gorm.Open("postgres", connInfo)
	defer db.Close()
	if err != nil {
		panic(err)
	}

	db.Debug().AutoMigrate(&ScanResult{})
	db.Save(&ScanResult{ScanHost: hostname, ScanTime: timestamp, ScanInfo: jsonInfo})
}
